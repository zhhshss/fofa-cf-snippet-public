package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var magic = [4]byte{0x21, 0x12, 0xA4, 0x42}

const (
	allocReq = 0x0003
	allocOK  = 0x0103
	allocErr = 0x0113
	permReq  = 0x0008
	permOK   = 0x0108
	connReq  = 0x000A
	connOK   = 0x010A
	bindReq  = 0x000B
	bindOK   = 0x010B
	sendInd  = 0x0016
	dataInd  = 0x0017

	aUser      = 0x0006
	aIntegrity = 0x0008
	aError     = 0x0009
	aRealm     = 0x0014
	aNonce     = 0x0015
	aPeer      = 0x0012
	aTransport = 0x0019
	aConnID    = 0x002A
	aSoftware  = 0x8022
	aData      = 0x0013
)

var (
	optPing, optTimeout, optConn time.Duration
	flagConcur, flagPingConcur   int
	verifyIP                     string
	verifyHost, verifyPath       string
	verifyPort                   int
	dnsIP, ipMetaAPI             string
)

var creds = [][2]string{
	{"test", "test"}, {"test", "test123"}, {"test", "1234"}, {"test", "123456"},
	{"coturn", "coturn"}, {"coturn", "coturn123"}, {"coturn", "password"},
	{"guest", "guest"}, {"guest", "guest123"},
	{"admin", "admin"}, {"admin", "admin123"}, {"admin", "password"}, {"admin", "123456"},
	{"user", "user"}, {"user", "password"}, {"user", "user123"},
	{"turn", "turn"}, {"turn", "turn123"}, {"turn", "password"},
	{"root", "root"}, {"root", "password"}, {"root", "123456"},
	{"username", "password"}, {"demo", "demo"}, {"webrtc", "webrtc"},
}

// ── STUN primitives ──

func mkAttr(t uint16, v []byte) []byte {
	b := make([]byte, 4+len(v)+(4-len(v)%4)%4)
	binary.BigEndian.PutUint16(b, t)
	binary.BigEndian.PutUint16(b[2:], uint16(len(v)))
	copy(b[4:], v)
	return b
}

func joinAttrs(attrs ...[]byte) []byte {
	var out []byte
	for _, a := range attrs {
		out = append(out, a...)
	}
	return out
}

func mkMsg(tp uint16, tid []byte, attrs ...[]byte) []byte {
	body := joinAttrs(attrs...)
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h, tp)
	binary.BigEndian.PutUint16(h[2:], uint16(len(body)))
	copy(h[4:], magic[:])
	copy(h[8:], tid)
	return append(h, body...)
}

func signMsg(m, key []byte) []byte {
	mc := make([]byte, len(m))
	copy(mc, m)
	binary.BigEndian.PutUint16(mc[2:], binary.BigEndian.Uint16(mc[2:])+24)
	mac := hmac.New(sha1.New, key)
	mac.Write(mc)
	return append(mc, mkAttr(aIntegrity, mac.Sum(nil))...)
}

func sign(m, key []byte) []byte {
	if key == nil {
		return m
	}
	return signMsg(m, key)
}

func xorAddr(ip string, port uint16) []byte {
	parts := strings.Split(ip, ".")
	b := make([]byte, 8)
	b[1] = 1
	binary.BigEndian.PutUint16(b[2:], port^0x2112)
	for i := 0; i < 4; i++ {
		v, _ := strconv.Atoi(parts[i])
		b[4+i] = byte(v) ^ magic[i]
	}
	return b
}

func randTID() []byte {
	b := make([]byte, 12)
	rand.Read(b)
	return b
}

// ── STUN parsing ──

type stunMsg struct {
	tp    uint16
	attrs map[uint16][]byte
}

func (m *stunMsg) is(t uint16) bool { return m != nil && m.tp == t }
func (m *stunMsg) get(k uint16) []byte {
	if m == nil {
		return nil
	}
	return m.attrs[k]
}
func (m *stunMsg) sw() string { return string(m.get(aSoftware)) }

func (m *stunMsg) errCode() int {
	d := m.get(aError)
	if len(d) < 4 {
		return 0
	}
	return int(d[2]&7)*100 + int(d[3])
}

func parseMsg(data []byte) *stunMsg {
	if len(data) < 20 || *(*[4]byte)(data[4:8]) != magic {
		return nil
	}
	ml := int(binary.BigEndian.Uint16(data[2:4]))
	attrs := make(map[uint16][]byte)
	for o := 20; o+4 <= 20+ml; {
		at := binary.BigEndian.Uint16(data[o : o+2])
		al := int(binary.BigEndian.Uint16(data[o+2 : o+4]))
		if o+4+al > len(data) {
			break
		}
		v := make([]byte, al)
		copy(v, data[o+4:])
		attrs[at] = v
		o += 4 + al + (4-al%4)%4
	}
	return &stunMsg{tp: binary.BigEndian.Uint16(data[0:2]), attrs: attrs}
}

func readStun(r *bufio.Reader, dl time.Time) *stunMsg {
	hdr := make([]byte, 20)
	if readN(r, hdr, dl) != nil || hdr[0]&0xC0 != 0 {
		return nil
	}
	ml := int(binary.BigEndian.Uint16(hdr[2:4]))
	if ml > 0 {
		body := make([]byte, ml)
		if readN(r, body, dl) != nil {
			return nil
		}
		return parseMsg(append(hdr, body...))
	}
	return parseMsg(hdr)
}

func readN(r *bufio.Reader, buf []byte, dl time.Time) error {
	for n := 0; n < len(buf); {
		if time.Now().After(dl) {
			return fmt.Errorf("timeout")
		}
		nn, err := r.Read(buf[n:])
		n += nn
		if err != nil {
			return err
		}
	}
	return nil
}

// ── TCP conn helper ──

type stunConn struct {
	net.Conn
	br *bufio.Reader
}

func dial(addr string, timeout time.Duration) (*stunConn, error) {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	return &stunConn{Conn: c, br: bufio.NewReader(c)}, nil
}

func (c *stunConn) send(m []byte, timeout time.Duration) *stunMsg {
	dl := time.Now().Add(timeout)
	c.SetDeadline(dl)
	c.Write(m)
	return readStun(c.br, dl)
}

func (c *stunConn) sendRaw(m []byte, timeout time.Duration) {
	c.SetDeadline(time.Now().Add(timeout))
	c.Write(m)
}

func (c *stunConn) recv(timeout time.Duration) *stunMsg {
	return readStun(c.br, time.Now().Add(timeout))
}

// ── DNS probe ──

func buildDNSQuery() ([]byte, []byte) {
	txid := make([]byte, 2)
	rand.Read(txid)
	h := make([]byte, 12)
	copy(h, txid)
	h[2] = 0x01
	h[5] = 1
	q := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	return append(h, q...), txid
}

func checkDNS(data, txid []byte) bool {
	return len(data) >= 12 && data[0] == txid[0] && data[1] == txid[1] && (data[2]>>4)&0xF == 8 && data[3]&0xF == 0
}

// ── Allocate + Auth ──

type authInfo struct {
	key    []byte
	aa     []byte // pre-joined auth attrs
	sw     string
	noAuth bool
	cred   string
}

func (a *authInfo) sign(m []byte) []byte { return sign(m, a.key) }

func doAlloc(c *stunConn, transport byte, knownCred string) *authInfo {
	tp := []byte{transport, 0, 0, 0}
	r := c.send(mkMsg(allocReq, randTID(), mkAttr(aTransport, tp)), optTimeout)
	if r == nil {
		return nil
	}

	sw := r.sw()
	if r.is(allocOK) {
		return &authInfo{sw: sw, noAuth: true}
	}
	if !r.is(allocErr) || r.errCode() != 401 {
		return nil
	}

	realm, nonce := string(r.get(aRealm)), r.get(aNonce)
	tryList := creds
	if knownCred != "" {
		p := strings.SplitN(knownCred, ":", 2)
		tryList = [][2]string{{p[0], p[1]}}
	}

	for _, cr := range tryList {
		user, passwd := cr[0], cr[1]
		h := md5.Sum([]byte(user + ":" + realm + ":" + passwd))
		key := h[:]
		aa := joinAttrs(mkAttr(aUser, []byte(user)), mkAttr(aRealm, []byte(realm)), mkAttr(aNonce, nonce))
		m := signMsg(mkMsg(allocReq, randTID(), mkAttr(aTransport, tp), aa), key)

		r = c.send(m, optTimeout)
		if r == nil {
			return nil
		}
		if r.is(allocOK) {
			return &authInfo{key: key, aa: aa, sw: sw, cred: user + ":" + passwd}
		}
		if r.is(allocErr) {
			if n := r.get(aNonce); n != nil {
				nonce = n
			}
			if nr := r.get(aRealm); nr != nil {
				realm = string(nr)
			}
			continue
		}
		return nil
	}
	return nil
}

// ── TCP relay: Perm → Connect → Bind → TLS verify + 出口元数据 ──

type exitMeta struct {
	Country, City, ExitIP, ISP, Org, AS, IPType, Purity string
	SpeedKBs                                            float64
}

func testTCP(c *stunConn, addr string, auth *authInfo) (bool, *exitMeta, int64) {
	peer := mkAttr(aPeer, xorAddr(verifyIP, uint16(verifyPort)))
	permMsg := auth.sign(mkMsg(permReq, randTID(), peer, auth.aa))
	connMsg := auth.sign(mkMsg(connReq, randTID(), peer, auth.aa))

	t0 := time.Now()
	dl := time.Now().Add(optConn)
	c.SetDeadline(dl)
	c.Write(append(permMsg, connMsg...))

	if r := readStun(c.br, dl); !r.is(permOK) {
		return false, nil, 0
	}
	r := c.recv(optConn)
	if !r.is(connOK) || r.get(aConnID) == nil {
		return false, nil, 0
	}

	dc, err := dial(addr, optTimeout)
	if err != nil {
		return false, nil, 0
	}
	defer dc.Close()

	bindMsg := auth.sign(mkMsg(bindReq, randTID(), mkAttr(aConnID, r.get(aConnID)), auth.aa))
	if br := dc.send(bindMsg, optTimeout); !br.is(bindOK) {
		return false, nil, 0
	}

	tc := tls.Client(dc.Conn, &tls.Config{ServerName: verifyHost})
	tc.SetDeadline(time.Now().Add(optTimeout))
	if tc.Handshake() != nil {
		return false, nil, time.Since(t0).Milliseconds()
	}
	reqStart := time.Now()
	tc.Write([]byte("GET " + verifyPath + " HTTP/1.1\r\nHost: " + verifyHost + "\r\nConnection: close\r\n\r\n"))
	resp, _ := io.ReadAll(io.LimitReader(tc, 8192))
	elapsed := time.Since(reqStart)
	relayMs := time.Since(t0).Milliseconds()
	if idx := strings.Index(string(resp), "\r\n\r\n"); idx >= 0 {
		body := resp[idx+4:]
		meta := parseExitJSON(body)
		if meta == nil {
			meta = &exitMeta{}
		}
		if elapsed > 0 && len(body) > 0 {
			meta.SpeedKBs = float64(len(body)) / elapsed.Seconds() / 1024.0
		}
		return true, meta, relayMs
	}
	return false, nil, relayMs
}

func parseExitJSON(body []byte) *exitMeta {
	var j map[string]interface{}
	if json.Unmarshal(body, &j) != nil {
		return nil
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := j[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	m := &exitMeta{
		Country: str("country", "country_name", "countryCode"),
		City:    str("city"),
		ExitIP:  str("ip", "query", "ipAddress"),
		ISP:     str("isp", "org"),
		Org:     str("org", "organization"),
		AS:      str("as", "asn"),
	}
	// 类型/纯净度
	hosting, _ := j["hosting"].(bool)
	proxy, _ := j["proxy"].(bool)
	mobile, _ := j["mobile"].(bool)
	if b, ok := j["hosting"].(string); ok {
		hosting = b == "true" || b == "1"
	}
	if b, ok := j["proxy"].(string); ok {
		proxy = b == "true" || b == "1"
	}
	if b, ok := j["mobile"].(string); ok {
		mobile = b == "true" || b == "1"
	}
	// iplark 可能用 type 字段
	typ := strings.ToLower(str("type", "ip_type", "usage"))
	switch {
	case proxy || strings.Contains(typ, "proxy") || strings.Contains(typ, "vpn"):
		m.IPType, m.Purity = "proxy", "dirty"
	case hosting || strings.Contains(typ, "hosting") || strings.Contains(typ, "datacenter") || strings.Contains(typ, "business"):
		m.IPType, m.Purity = "hosting", "dirty"
	case mobile || strings.Contains(typ, "mobile"):
		m.IPType, m.Purity = "mobile", "clean"
	case strings.Contains(typ, "residential") || strings.Contains(typ, "isp"):
		m.IPType, m.Purity = "residential", "clean"
	default:
		// 用 AS/org 粗判
		blob := strings.ToLower(m.Org + " " + m.ISP + " " + m.AS)
		if strings.Contains(blob, "cloud") || strings.Contains(blob, "amazon") ||
			strings.Contains(blob, "google") || strings.Contains(blob, "digitalocean") ||
			strings.Contains(blob, "ovh") || strings.Contains(blob, "hetzner") ||
			strings.Contains(blob, "contabo") || strings.Contains(blob, "vultr") ||
			strings.Contains(blob, "linode") || strings.Contains(blob, "hosting") {
			m.IPType, m.Purity = "hosting", "dirty"
		} else if m.ISP != "" || m.Org != "" {
			m.IPType, m.Purity = "residential", "clean"
		} else {
			m.IPType, m.Purity = "unknown", "unknown"
		}
	}
	return m
}

// lookupIPMeta 直连 ip-api 补全（非中继出口时的兜底）
func lookupIPMeta(ip string) *exitMeta {
	if ip == "" {
		return nil
	}
	client := &http.Client{Timeout: 4 * time.Second}
	u := strings.ReplaceAll(ipMetaAPI, "{ip}", url.PathEscape(ip))
	resp, err := client.Get(u)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var j map[string]interface{}
	if json.Unmarshal(body, &j) != nil || j["status"] != "success" {
		return nil
	}
	// 复用 parse 逻辑
	b, _ := json.Marshal(j)
	return parseExitJSON(b)
}

// ── UDP relay: Alloc(17) → Perm → SendInd(DNS) → DataInd ──

func testUDP(addr, knownCred string) (*authInfo, bool) {
	c, err := dial(addr, optPing)
	if err != nil {
		return nil, false
	}
	defer c.Close()

	auth := doAlloc(c, 17, knownCred)
	if auth == nil {
		return nil, false
	}

	permMsg := auth.sign(mkMsg(permReq, randTID(), mkAttr(aPeer, xorAddr(dnsIP, 0)), auth.aa))
	if r := c.send(permMsg, optTimeout); !r.is(permOK) {
		return auth, false
	}

	dnsQ, txid := buildDNSQuery()
	sendMsg := mkMsg(sendInd, randTID(), mkAttr(aPeer, xorAddr(dnsIP, 53)), mkAttr(aData, dnsQ))
	r := c.send(sendMsg, optTimeout)
	if !r.is(dataInd) {
		return auth, false
	}
	return auth, checkDNS(r.get(aData), txid)
}

// ── scan one target ──

type scanInfo struct {
	IP, SW, Cred, Country, City, Mode string
	Port                              int
	NoAuth, TCP, UDP                  bool
	// 出口/质量
	ExitIP   string  `json:"exit_ip,omitempty"`
	ISP      string  `json:"isp,omitempty"`
	Org      string  `json:"org,omitempty"`
	AS       string  `json:"as,omitempty"`
	IPType   string  `json:"ip_type,omitempty"`    // residential / hosting / mobile / proxy / unknown
	Purity   string  `json:"purity,omitempty"`     // clean / dirty / unknown
	Latency  int64   `json:"latency_ms,omitempty"` // TCPing ms
	RelayMs  int64   `json:"relay_ms,omitempty"`   // 中继往返测活 ms
	SpeedKBs float64 `json:"speed_kbs,omitempty"`  // 粗测 KB/s，0=未测
}

func scanOne(ip string, port int, sem, pingSem chan struct{}, alive *int64) *scanInfo {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	// TCPing only
	pingSem <- struct{}{}
	t0 := time.Now()
	c, err := net.DialTimeout("tcp", addr, optPing)
	lat := time.Since(t0).Milliseconds()
	<-pingSem
	if err != nil {
		return nil
	}
	c.Close()
	atomic.AddInt64(alive, 1)

	sem <- struct{}{}
	defer func() { <-sem }()

	info := &scanInfo{IP: ip, Port: port, Latency: lat}

	// TCP relay + 出口信息
	if tc, err := dial(addr, optTimeout); err == nil {
		if auth := doAlloc(tc, 6, ""); auth != nil {
			info.SW, info.NoAuth, info.Cred = auth.sw, auth.noAuth, auth.cred
			ok, meta, rms := testTCP(tc, addr, auth)
			info.TCP, info.RelayMs = ok, rms
			if meta != nil {
				if meta.Country != "" {
					info.Country = meta.Country
				}
				info.City = meta.City
				info.ExitIP = meta.ExitIP
				info.ISP = meta.ISP
				info.Org = meta.Org
				info.AS = meta.AS
				info.IPType = meta.IPType
				info.Purity = meta.Purity
				info.SpeedKBs = meta.SpeedKBs
			}
		}
		tc.Close()
	}

	// UDP relay
	udpAuth, udpOK := testUDP(addr, info.Cred)
	info.UDP = udpOK
	if udpAuth != nil {
		if info.SW == "" {
			info.SW = udpAuth.sw
		}
		if !info.NoAuth && info.Cred == "" {
			info.NoAuth, info.Cred = udpAuth.noAuth, udpAuth.cred
		}
	}

	// 出口元数据补全（TCP 中继没拿到时，用目标 IP 自身查）
	if info.ExitIP == "" {
		info.ExitIP = ip
	}
	if info.IPType == "" || info.Purity == "" || info.Country == "" {
		if m := lookupIPMeta(info.ExitIP); m != nil {
			if info.Country == "" {
				info.Country = m.Country
			}
			if info.City == "" {
				info.City = m.City
			}
			if info.ISP == "" {
				info.ISP = m.ISP
			}
			if info.Org == "" {
				info.Org = m.Org
			}
			if info.AS == "" {
				info.AS = m.AS
			}
			if info.IPType == "" {
				info.IPType = m.IPType
			}
			if info.Purity == "" {
				info.Purity = m.Purity
			}
		}
	}

	switch {
	case info.TCP && info.UDP:
		info.Mode = "ALL"
	case info.TCP:
		info.Mode = "TCP"
	case info.UDP:
		info.Mode = "UDP"
	default:
		return nil
	}
	return info
}

// ── main ──

func main() {
	verifyHost = requiredEnv("TURN_VERIFY_HOST")
	verifyPath = requiredEnv("TURN_VERIFY_PATH")
	dnsIP = requiredEnv("TURN_DNS_IP")
	ipMetaAPI = requiredEnv("IP_META_API")
	verifyPort = envInt("TURN_VERIFY_PORT", 443)
	if !strings.Contains(ipMetaAPI, "{ip}") {
		fmt.Fprintln(os.Stderr, "IP_META_API 必须包含 {ip} 占位符")
		os.Exit(2)
	}
	var pt, t, ct int
	var useFofa bool
	flag.IntVar(&flagConcur, "c", 100, "扫描并发数")
	flag.IntVar(&flagPingConcur, "p", 500, "TCPing并发数")
	flag.IntVar(&pt, "pt", 3, "TCPing超时(秒)")
	flag.IntVar(&t, "t", 5, "扫描超时(秒)")
	flag.IntVar(&ct, "ct", 8, "Connect超时(秒)")
	flag.BoolVar(&useFofa, "fofa", false, "从 FOFA 网关自动拉取候选(用 FOFA_* 环境变量)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法:\n  turn_scan -fofa                 # FOFA 自动拉取并扫描(GitHub Action 用)\n  turn_scan [参数] <ip_list.txt|->  # 从文件/stdin 读候选\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if !useFofa && flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	optPing = time.Duration(pt) * time.Second
	optTimeout = time.Duration(t) * time.Second
	optConn = time.Duration(ct) * time.Second

	type target struct {
		ip   string
		port int
	}
	var targets []target

	pushLine := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			return
		}
		if i := strings.LastIndex(line, ":"); i > 0 {
			p, _ := strconv.Atoi(line[i+1:])
			targets = append(targets, target{line[:i], p})
		} else {
			targets = append(targets, target{line, 3478})
		}
	}

	if useFofa {
		// FOFA 模式:从网关拉候选（默认亚太，可 FOFA_QUERY 覆盖）
		base := env("FOFA_BASE", "")
		token := env("FOFA_TOKEN", "")
		query := env("FOFA_QUERY",
			`protocol="stun" && port="3478" && country="SG" && is_domain=false`)
		pages, _ := strconv.Atoi(env("FOFA_PAGES", "8"))
		// 免费号 FOFA size=100 会全号失败；50 是实测安全上限
		size, _ := strconv.Atoi(env("FOFA_SIZE", "50"))
		if size > 50 {
			fmt.Fprintf(os.Stderr, "[FOFA] size=%d 过大，强制改为 50（免费号 size=100 会 502）\n", size)
			size = 50
		}
		if size < 2 {
			size = 10
		}
		// 多查询串行：SG 主 + 邻近国家补量（FOFA 不支持 country 多值）
		extraQ := env("FOFA_EXTRA_QUERIES",
			`protocol="stun" && port="3478" && country="JP" && is_domain=false|protocol="stun" && port="3478" && country="KR" && is_domain=false|protocol="stun" && port="3478" && country="HK" && is_domain=false|protocol="stun" && port="3478" && country="TW" && is_domain=false`)
		fmt.Fprintln(os.Stderr, "[FOFA] 拉取候选…")
		queries := []string{query}
		for _, q := range strings.Split(extraQ, "|") {
			q = strings.TrimSpace(q)
			if q != "" && q != query {
				queries = append(queries, q)
			}
		}
		// 每国均分页数，至少 2 页
		perPages := pages
		if len(queries) > 1 {
			perPages = pages / len(queries)
			if perPages < 2 {
				perPages = 2
			}
		}
		for qi, q := range queries {
			fmt.Fprintf(os.Stderr, "[FOFA] query=%s pages=%d\n", clip([]byte(q), 80), perPages)
			for _, ipp := range fofaFetch(base, token, q, perPages, size) {
				pushLine(ipp)
			}
			// 国与国之间再歇，避免 exceededSnippetsSubrequests
			if qi+1 < len(queries) {
				time.Sleep(2 * time.Second)
			}
		}
		// 去重 targets（pushLine 不去重）
		{
			seenT := map[string]bool{}
			var uniq []target
			for _, t := range targets {
				k := fmt.Sprintf("%s:%d", t.ip, t.port)
				if seenT[k] {
					continue
				}
				seenT[k] = true
				uniq = append(uniq, t)
			}
			targets = uniq
		}
		if len(targets) == 0 {
			// 不硬退出：保留旧 R2，写空本地报告后 exit 0，避免 schedule 红灯清空产物
			fmt.Fprintln(os.Stderr, "FOFA 未返回候选（网关瞬时失败?），跳过扫描，不覆盖 R2")
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "[FOFA] 候选 %d 个（%d 条 query）\n", len(targets), len(queries))
	} else {
		var sc *bufio.Scanner
		if flag.Arg(0) == "-" {
			sc = bufio.NewScanner(os.Stdin)
		} else {
			f, err := os.Open(flag.Arg(0))
			if err != nil {
				fmt.Println("打开文件失败:", err)
				os.Exit(1)
			}
			defer f.Close()
			sc = bufio.NewScanner(f)
		}
		for sc.Scan() {
			pushLine(sc.Text())
		}
	}
	total := len(targets)

	addrs, err := net.LookupHost(verifyHost)
	if err != nil || len(addrs) == 0 {
		fmt.Println("解析验证主机失败:", err)
		os.Exit(1)
	}
	verifyIP = addrs[0]

	sem := make(chan struct{}, flagConcur)
	pingSem := make(chan struct{}, flagPingConcur)
	var alive, done, allCnt, tcpCnt, udpCnt int64
	var mu sync.Mutex
	var results []scanInfo
	t0 := time.Now()

	printBar := func() {
		n := atomic.LoadInt64(&done)
		a := atomic.LoadInt64(&alive)
		ac, tc, uc := atomic.LoadInt64(&allCnt), atomic.LoadInt64(&tcpCnt), atomic.LoadInt64(&udpCnt)
		hit := ac + tc + uc
		elapsed := time.Since(t0).Seconds()
		rate := 0.0
		if elapsed > 0 {
			rate = float64(n) / elapsed
		}
		pct := 0
		if total > 0 {
			pct = int(n * 100 / int64(total))
		}
		w := 30
		bar := strings.Repeat("█", w*pct/100) + strings.Repeat("░", w-w*pct/100)
		fmt.Fprintf(os.Stderr, "\r\033[KTURN Scan | [%s] %d%% | %d/%d, Alive=%d, %.0f/s | HIT=%d (ALL=%d, TCP=%d, UDP=%d)",
			bar, pct, n, total, a, rate, hit, ac, tc, uc)
	}

	printHit := func(line string) {
		mu.Lock()
		fmt.Fprintf(os.Stderr, "\r\033[K%s\n", line)
		printBar()
		mu.Unlock()
	}

	var wg sync.WaitGroup
	for _, tgt := range targets {
		wg.Add(1)
		go func(ip string, port int) {
			defer wg.Done()
			info := scanOne(ip, port, sem, pingSem, &alive)
			atomic.AddInt64(&done, 1)
			if info != nil {
				switch info.Mode {
				case "ALL":
					atomic.AddInt64(&allCnt, 1)
				case "TCP":
					atomic.AddInt64(&tcpCnt, 1)
				case "UDP":
					atomic.AddInt64(&udpCnt, 1)
				}
				auth := "NO_AUTH"
				if !info.NoAuth {
					auth = fmt.Sprintf("WEAK(%s)", info.Cred)
				}
				sw := info.SW
				if sw == "" {
					sw = "?"
				}
				c := ""
				if info.Country != "" {
					c = "  " + info.Country
				}
				printHit(fmt.Sprintf("  [+] %-22s %-4s %-30s %s%s",
					fmt.Sprintf("%s:%d", info.IP, info.Port), info.Mode, sw, auth, c))
				mu.Lock()
				results = append(results, *info)
				mu.Unlock()
			} else {
				mu.Lock()
				printBar()
				mu.Unlock()
			}
		}(tgt.ip, tgt.port)
	}
	wg.Wait()

	fmt.Fprintf(os.Stderr, "\r\033[K")
	elapsed := time.Since(t0).Seconds()
	hit := allCnt + tcpCnt + udpCnt
	fmt.Printf("\n%s\n", strings.Repeat("=", 50))
	fmt.Printf("完成: %d 目标, %.1fs, %.0f/s\n", total, elapsed, float64(total)/elapsed)
	fmt.Printf("  存活: %d, 可用: %d (ALL=%d TCP=%d UDP=%d)\n", alive, hit, allCnt, tcpCnt, udpCnt)

	if len(results) > 0 {
		if out, err := os.Create("turn_results.txt"); err == nil {
			for _, r := range results {
				auth := "NO_AUTH"
				if !r.NoAuth {
					auth = fmt.Sprintf("CRED(%s)", r.Cred)
				}
				fmt.Fprintf(out, "%s:%d  %s  %s  %s  %s\n", r.IP, r.Port, r.Mode, r.Country, auth, r.SW)
			}
			out.Close()
		}
		fmt.Println("结果: turn_results.txt")
		for _, r := range results {
			auth := "无认证"
			if !r.NoAuth {
				auth = r.Cred
			}
			fmt.Printf("  %s:%d  %s  %s  (%s)  [%s]\n", r.IP, r.Port, r.Mode, r.Country, auth, r.SW)
		}
	}

	// 生成订阅 + 写 R2
	emitOutputs(results)
}

// ══════════════════════════════════════════════════════════════════
//  FOFA 拉取源(-fofa 模式:自动出候选 IP 列表,喂给上面的扫描器)
// ══════════════════════════════════════════════════════════════════

type fofaResp struct {
	OK   bool `json:"ok"`
	Data struct {
		Assets []struct {
			IP      string `json:"ip"`
			Port    int    `json:"port"`
			Server  string `json:"server"`
			Country string `json:"country"`
		} `json:"assets"`
		Page struct {
			Total int `json:"total"`
		} `json:"page"`
	} `json:"data"`
}

// fofaFetch 优先走 /v1/export（多时间窗 page1 吃免费 web_data），失败回退 /v1/search 分页。
func fofaFetch(base, token, query string, pages, size int) []string {
	seen := map[string]bool{}
	var out []string
	client := &http.Client{Timeout: 90 * time.Second}
	base = strings.TrimRight(base, "/")
	if size > 50 {
		size = 50
	}
	if size < 2 {
		size = 50
	}
	// 1) export：limit ≈ pages*size，跨时间窗去重
	limit := pages * size
	if limit < 100 {
		limit = 100
	}
	if limit > 2000 {
		limit = 2000
	}
	exportURL := fmt.Sprintf("%s/v1/export?q=%s&limit=%d&size=%d&days=365&window_days=30",
		base, url.QueryEscape(query), limit, size)
	req, _ := http.NewRequest("GET", exportURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if resp, err := client.Do(req); err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var er struct {
			OK     bool `json:"ok"`
			Count  int  `json:"count"`
			Assets []struct {
				IP   string `json:"ip"`
				Port int    `json:"port"`
			} `json:"assets"`
			Error any `json:"error"`
		}
		if json.Unmarshal(body, &er) == nil && er.OK {
			for _, a := range er.Assets {
				if a.IP == "" || a.Port == 0 {
					continue
				}
				if a.Port != 3478 && a.Port != 3479 && a.Port != 5349 {
					continue
				}
				k := fmt.Sprintf("%s:%d", a.IP, a.Port)
				if seen[k] {
					continue
				}
				seen[k] = true
				out = append(out, k)
			}
			fmt.Fprintf(os.Stderr, "[fofa] export: +%d (limit=%d count=%d)\n", len(out), limit, er.Count)
			if len(out) > 0 {
				return out
			}
		} else {
			fmt.Fprintf(os.Stderr, "[fofa] export 不可用，回退 search: %s\n", clip(body, 160))
		}
	} else {
		fmt.Fprintf(os.Stderr, "[fofa] export 请求失败，回退 search: %v\n", err)
	}

	// 2) 回退：仅 page=1 多 query 由上层 FOFA_EXTRA 负责；这里仍尝试有限页+重试
	for page := 1; page <= pages; page++ {
		u := fmt.Sprintf("%s/v1/search?q=%s&size=%d&page=%d",
			base, url.QueryEscape(query), size, page)

		var body []byte
		var fr fofaResp
		okPage := false
		for attempt := 1; attempt <= 4; attempt++ {
			req, _ := http.NewRequest("GET", u, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := client.Do(req)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[fofa] page %d 请求失败(try%d): %v\n", page, attempt, err)
				time.Sleep(time.Duration(attempt) * time.Second)
				continue
			}
			body, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			fr = fofaResp{}
			if err := json.Unmarshal(body, &fr); err != nil {
				fmt.Fprintf(os.Stderr, "[fofa] page %d 解析失败(try%d): %v (%s)\n", page, attempt, err, clip(body, 120))
				time.Sleep(time.Duration(attempt) * time.Second)
				continue
			}
			if !fr.OK {
				fmt.Fprintf(os.Stderr, "[fofa] page %d 非 ok(try%d): %s\n", page, attempt, clip(body, 160))
				time.Sleep(time.Duration(attempt*2) * time.Second)
				continue
			}
			okPage = true
			break
		}
		if !okPage {
			fmt.Fprintf(os.Stderr, "[fofa] page %d 放弃（累计已有 %d）\n", page, len(out))
			break
		}
		got := 0
		for _, a := range fr.Data.Assets {
			if a.IP == "" || a.Port == 0 {
				continue
			}
			if a.Port != 3478 && a.Port != 3479 && a.Port != 5349 {
				continue
			}
			k := fmt.Sprintf("%s:%d", a.IP, a.Port)
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, k)
			got++
		}
		fmt.Fprintf(os.Stderr, "[fofa] page %d: +%d 累计 %d (total=%d)\n", page, got, len(out), fr.Data.Page.Total)
		// 免费号 page>1 基本废，拿完 page1 就够
		if page >= 1 || page*size >= fr.Data.Page.Total || len(fr.Data.Assets) == 0 {
			break
		}
		time.Sleep(1500 * time.Millisecond)
	}
	return out
}

func clip(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n])
	}
	return string(b)
}

// ══════════════════════════════════════════════════════════════════
//  输出:vless 订阅 + JSON 报告 + 写 Cloudflare R2
// ══════════════════════════════════════════════════════════════════

func emitOutputs(results []scanInfo) {
	xudpHost := env("XUDP_HOST", "")
	xudpUUID := env("XUDP_UUID", "")

	// 全部 usable 写 R2；订阅只出 ALL（TCP+UDP）
	var usable, allOnly []scanInfo
	for _, r := range results {
		if r.TCP || r.UDP {
			usable = append(usable, r)
		}
		if r.Mode == "ALL" {
			allOnly = append(allOnly, r)
		}
	}
	sortServers := func(list []scanInfo) {
		sort.SliceStable(list, func(i, j int) bool {
			rank := func(m string) int {
				switch m {
				case "ALL":
					return 0
				case "TCP":
					return 1
				case "UDP":
					return 2
				default:
					return 3
				}
			}
			if rank(list[i].Mode) != rank(list[j].Mode) {
				return rank(list[i].Mode) < rank(list[j].Mode)
			}
			// 延迟低优先，其次 relay
			if list[i].Latency != list[j].Latency {
				return list[i].Latency < list[j].Latency
			}
			return list[i].RelayMs < list[j].RelayMs
		})
	}
	sortServers(usable)
	sortServers(allOnly)

	// 主订阅：仅 ALL
	var lines []string
	for _, r := range allOnly {
		lines = append(lines, vlessURI(xudpHost, xudpUUID, r))
	}
	subPlain := strings.Join(lines, "\n") + "\n"
	subB64 := base64.StdEncoding.EncodeToString([]byte(subPlain))

	// 全量节点（含 UDP-only）备用
	var allLines []string
	for _, r := range usable {
		allLines = append(allLines, vlessURI(xudpHost, xudpUUID, r))
	}
	allPlain := strings.Join(allLines, "\n") + "\n"

	report := map[string]any{
		"updated_at":  time.Now().UTC().Format(time.RFC3339),
		"host":        xudpHost,
		"total":       len(results),
		"usable":      len(usable),
		"all_count":   len(allOnly),
		"udp_only":    len(usable) - len(allOnly),
		"servers":     usable,  // R2 全量保留（含 UDP-only）
		"sub_servers": allOnly, // 进订阅的
	}
	reportJSON, _ := json.MarshalIndent(report, "", "  ")

	os.WriteFile("turn_report.json", reportJSON, 0644)
	os.WriteFile("turn_sub.txt", []byte(subB64), 0644)
	os.WriteFile("turn_nodes.txt", []byte(subPlain), 0644)
	os.WriteFile("turn_nodes_all.txt", []byte(allPlain), 0644)
	fmt.Printf("\n本地产物: turn_report.json / turn_sub.txt(仅ALL) / turn_nodes.txt / turn_nodes_all.txt(含UDP)\n")
	fmt.Fprintf(os.Stderr, "  订阅 ALL=%d，R2 全量 usable=%d（含 UDP-only）\n", len(allOnly), len(usable))

	ak := os.Getenv("R2_ACCESS_KEY_ID")
	if ak == "" {
		fmt.Fprintln(os.Stderr, "[R2] 跳过(无 R2_ACCESS_KEY_ID)")
		return
	}
	// 零 usable 不覆盖 R2（避免 FOFA 抖动/全灭时把订阅清空）
	if len(usable) == 0 {
		fmt.Fprintln(os.Stderr, "[R2] 跳过写入：本次 usable=0，保留旧订阅")
		return
	}
	r2 := r2cfg{
		ak:         ak,
		sk:         os.Getenv("R2_SECRET_ACCESS_KEY"),
		bucket:     env("R2_BUCKET", "fofa"),
		publicBase: env("R2_PUBLIC_BASE", ""),
		endpoint:   requiredEnv("R2_ENDPOINT"),
	}
	prefix := env("R2_PREFIX", "turn/")
	fmt.Fprintln(os.Stderr, "[R2] 写入…")
	putR2(r2, prefix+"turn_report.json", reportJSON, "application/json")
	putR2(r2, prefix+"turn_sub.txt", []byte(subB64), "text/plain; charset=utf-8")
	putR2(r2, prefix+"turn_nodes.txt", []byte(subPlain), "text/plain; charset=utf-8")
	putR2(r2, prefix+"turn_nodes_all.txt", []byte(allPlain), "text/plain; charset=utf-8")
	if r2.publicBase != "" {
		pb := strings.TrimRight(r2.publicBase, "/") + "/" + strings.TrimSuffix(prefix, "/")
		fmt.Printf("\n订阅(仅 ALL):\n  %s/turn_sub.txt\n", pb)
		fmt.Printf("全量节点: %s/turn_nodes_all.txt\n", pb)
		fmt.Printf("完整报告: %s/turn_report.json\n", pb)
	}
}

func vlessURI(host, uuid string, r scanInfo) string {
	cred := ""
	if !r.NoAuth && r.Cred != "" {
		cred = r.Cred + "@"
	}
	// path 带 global=0：非 CF IP 直连，CF IP 仍走 TURN
	path := fmt.Sprintf("/turn://%s%s:%d?ed=2560&global=0", cred, r.IP, r.Port)
	authTag := "noauth"
	if !r.NoAuth {
		authTag = "weak"
	}
	// 备注：模式-国家-出口IP-类型-纯净度-延迟
	parts := []string{"TURN", r.Mode}
	if r.Country != "" {
		parts = append(parts, r.Country)
	}
	if r.ExitIP != "" {
		parts = append(parts, r.ExitIP)
	} else {
		parts = append(parts, r.IP)
	}
	if r.IPType != "" {
		parts = append(parts, r.IPType)
	}
	if r.Purity != "" {
		parts = append(parts, r.Purity)
	}
	if r.Latency > 0 {
		parts = append(parts, fmt.Sprintf("%dms", r.Latency))
	}
	parts = append(parts, authTag)
	remark := strings.Join(parts, "-")

	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("security", "tls")
	q.Set("sni", host)
	q.Set("type", "ws")
	q.Set("host", host)
	q.Set("path", path)
	q.Set("fp", "chrome")
	if ech := env("XUDP_ECH", ""); ech != "" {
		q.Set("ech", ech)
	}
	return fmt.Sprintf("vless://%s@%s:443?%s#%s", uuid, host, q.Encode(), url.QueryEscape(remark))
}

// ── Cloudflare R2 (S3 SigV4,手写零依赖) ──

type r2cfg struct {
	ak, sk, bucket, publicBase, endpoint string
}

func putR2(c r2cfg, key string, data []byte, contentType string) {
	base, err := url.Parse(strings.TrimRight(c.endpoint, "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		fmt.Fprintf(os.Stderr, "[R2] endpoint 无效: %v\n", err)
		return
	}
	endpoint := strings.TrimRight(c.endpoint, "/") + "/" + c.bucket + "/" + key
	req, _ := http.NewRequest("PUT", endpoint, bytes.NewReader(data))
	req.Header.Set("Content-Type", contentType)
	signV4(req, data, c.ak, c.sk, "auto", "s3")
	resp, err := (&http.Client{Timeout: 40 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[R2] %s 失败: %v\n", key, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "[R2] %s -> %d: %s\n", key, resp.StatusCode, clip(b, 200))
		return
	}
	fmt.Fprintf(os.Stderr, "[R2] %s ✓ (%d B)\n", key, len(data))
}

func requiredEnv(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		fmt.Fprintf(os.Stderr, "缺少必需环境变量: %s\n", key)
		os.Exit(2)
	}
	return v
}

func envInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s 必须是整数\n", key)
		os.Exit(2)
	}
	return n
}

func signV4(req *http.Request, payload []byte, ak, sk, region, service string) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	host := req.URL.Host
	payloadHash := hexSHA256(payload)

	req.Header.Set("Host", host)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	canonURI := escapePath(req.URL.Path)
	canonHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n", host, payloadHash, amzDate)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonReq := strings.Join([]string{req.Method, canonURI, "", canonHeaders, signedHeaders, payloadHash}, "\n")

	scope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	strToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, hexSHA256([]byte(canonReq))}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+sk), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(kSigning, strToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", ak, scope, signedHeaders, sig))
}

func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

func hexSHA256(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
