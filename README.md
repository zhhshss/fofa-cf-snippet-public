# FOFA / TURN GitHub Actions

本仓库只保留运行 GitHub Actions 所需的最小代码。所有域名、网络端点、令牌、密钥和 UUID 均通过 GitHub Actions Secrets 注入，仓库中不提供网络端点默认值。

工作流：

- `fofa-refill`：维护 FOFA 账户池。
- `turn-scan`：扫描并发布 TURN 报告。
- `turn-speed-rank`：测试并发布 TURN 排名。
- `dmit-cf-proxy`：刷新 DMIT Cloudflare 反代池和 DNS。

公开仓库的 Actions 日志和构建产物可被任何人查看。工作流不会输出 Secret 值，但运行产物本身仍应按公开数据处理。
