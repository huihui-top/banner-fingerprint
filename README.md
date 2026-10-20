# Banner 指纹识别系统

[![CI](https://github.com/huihui-top/banner-fingerprint/actions/workflows/ci.yml/badge.svg)](https://github.com/huihui-top/banner-fingerprint/actions/workflows/ci.yml)

使用 Go 标准库实现的批量 Banner 指纹识别服务，提供独立 server 和 client。输入已有扫描数据中的 `ip`、`port`、`banner`，提取协议、产品、软件版本、操作系统线索和置信度。

识别结果严格包含七个字段。无法识别或单条输入非法时，该位置返回 `unknown`；详细错误记录在 server 日志中，其他记录继续处理。系统不连接输入记录中的目标 IP。

## 一键启动

环境需要 Docker Engine / Docker Desktop 与 Docker Compose V2。首次构建需联网下载 Go 构建镜像；代码只使用标准库，无第三方 Go 模块。

```bash
git clone https://github.com/huihui-top/banner-fingerprint.git
cd banner-fingerprint
docker compose up
```

Compose 构建两个运行镜像，启动 server，等待 `/health` 通过后运行 client。默认 client 读取 `samples/input.json` 的 20 条输入，输出识别数组后以状态 0 退出。server 继续运行，在本机 `http://127.0.0.1:8080` 提供接口。

```bash
# 在另一个终端查看状态
docker compose ps -a

# 再次运行默认样例
docker compose run --rm client

# 将自测文件放在 samples/acceptance.json 后执行
docker compose run --rm client --server http://server:8080 --input /data/acceptance.json

# 查看服务端内部错误
docker compose logs server

# 停止并清理本项目容器、网络
docker compose down
```

client 容器里的 `server` 是 Compose 服务名；宿主机程序使用 `127.0.0.1`。不要给默认启动命令加 `--abort-on-container-exit`，否则一次性 client 完成会停止 server。

## 接口

### POST /fingerprint

请求头：`Content-Type: application/json`，可带 `charset=utf-8`。

```json
[
  {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
  {"ip":"1.2.3.5","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"}
]
```

返回 HTTP 200：

```json
[
  {"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95},
  {"ip":"1.2.3.5","port":80,"protocol":"HTTP","product":"nginx","version":"1.24.0","os_hint":"","confidence":0.9}
]
```

```bash
curl -H "Content-Type: application/json" \
  --data-binary @samples/input.json \
  http://127.0.0.1:8080/fingerprint
```

PowerShell 可用 `curl.exe` 执行 curl 命令。

| 字段 | 输入要求 |
| --- | --- |
| `ip` | 必填字符串，合法 IPv4 或 IPv6；不接受域名、zone 和前后空白 |
| `port` | 必填 JSON 整数，1～65535；字符串、小数和指数形式不自动转换 |
| `banner` | 必填字符串，允许为空 |
| `banner_encoding` | 可选字符串，`text` 或 `base64`，缺省为 `text` |

数组内的错误逐条处理，包括 `null`、非对象元素、缺失字段、错误类型、重复字段名、非法地址/端口、错误编码、Banner 超限。

- 输出条数、顺序与输入一致，重复记录分别返回。
- 非法条目分别保留有效 IP 和端口；无效值使用 `""` 和 `0`。
- 合法未知和非法条目的识别字段均为 `protocol: "unknown"`、三个空字符串、`confidence: 0`。
- 不添加 `error`、索引或其他响应字段；通过 `X-Request-ID` 响应头关联内部日志。
- 空数组返回 `[]`；空 Banner 属于合法未知数据。
- 只识别到协议、产品时保留已知信息，未提取到的字段留空。

请求级错误也使用数组响应体 `[]`，具体原因记录在 server 日志：

| 状态码 | 含义 |
| --- | --- |
| 200 | 数组完成处理，含全部 unknown 的情况 |
| 400 | JSON 损坏、顶层非数组、存在额外顶层值 |
| 404 | 未知路由 |
| 405 | 请求方法不支持 |
| 413 | 请求体或条数超限 |
| 415 | 非 JSON 媒体类型 |
| 429 | 同时处理的批量请求达到上限 |
| 500 | 请求级内部故障 |
| 503 | 未就绪或处理超时 |

### GET /health

就绪返回 HTTP 200，响应体为空；未就绪返回 503。规则文件必须在启动时成功加载和编译，才会进入就绪状态。非法规则导致进程启动失败。

```bash
curl -i http://127.0.0.1:8080/health
```

## 二进制输入

`text` 按标准 JSON 字符串解码，支持 `\r\n`、`\n`、`\u0000`。题目中的 `\xNN` 不是合法 JSON 转义，不自动进行第二次反转义。

下面两条 MySQL 记录含有相同的原始字节，识别结果相同：

```json
[
  {"ip":"::1","port":3306,"banner":"J\u0000\u0000\u0000\n8.0.32\u0000"},
  {"ip":"::1","port":3306,"banner":"SgAAAAo4LjAuMzIA","banner_encoding":"base64"}
]
```

任意原始字节使用标准 Base64，包含所需的 `=` 填充，不接受 URL-safe 变体或夹带空白。64 KiB 的单条限制作用于解码后的字节。自测 TLS 片段在样例文件中使用 Base64 保存，第一版返回 unknown。

## 识别能力与规则

| 协议 | 产品与特征 | 默认分数 |
| --- | --- | --- |
| SSH | OpenSSH 版本，Ubuntu / Debian / FreeBSD / OpenBSD 线索，SSH 1.99 与 2.0 标识 | 版本规则 0.95 |
| HTTP | nginx、Apache、Microsoft-IIS 的 Server 头和版本 | 0.90 |
| HTTP | Jetty，支持 `Jetty/版本` 和 `Jetty(版本)` | 0.85 |
| MySQL | 带包头的服务端握手前缀及 NUL 结束的版本 | 0.90 |
| Redis | PONG、NOAUTH、典型参数数量错误 | 0.70 |
| FTP | ProFTPD、vsFTPd、Pure-FTPd，提取可见版本 | 有版本 0.90，无版本 0.80 |
| 通用协议 | 有明确 SSH / HTTP 结构而产品未知 | 0.60 |

端口不决定协议。443、8443 上的 HTTP 文本仍返回 HTTP。HTTP 产品仅从响应头提取，正文中的产品字符串不参与识别。单独的 `220`、通用 `-ERR`、`QUIT` 或数字版本串不会被强行判定为 FTP、Redis 或 MySQL。

MySQL 自测包声明的长度超过实际片段长度；协议标识和版本字段完整时仍可识别，未终止的版本或越界字段返回 unknown。其他 MySQL 协议兼容实现的产品识别可继续增加专门规则。

规则位于 `rules/fingerprints.json`，JSON schema 版本为 1。产品匹配、版本命名捕获、OS 线索、优先级和置信度均在配置中维护。结构解析器向规则提供如下 source：

| source | 内容 |
| --- | --- |
| `ssh.identification` | 完整 SSH 标识行 |
| `ssh.protocol` | 已验证的 `SSH` 结构标记 |
| `http.server` | 单个 Server 头值 |
| `http.protocol` | 已验证的 `HTTP` 结构标记 |
| `mysql.server_version` | 握手中的软件版本字段 |
| `redis.response` | RESP 简单字符串或错误响应首行 |
| `ftp.greeting` | 220 欢迎行，仅匹配明确 FTP 产品规则 |

`match.type` 支持 `regex`、`exact`；`version_group` 引用 Go 正则的命名捕获。`os_hints` 按顺序在同一 source 内取首个匹配。先选择产品规则，再选择通用协议规则；同类规则按 priority 降序、confidence 降序、ID 字典序升序排列，文件排列顺序不改变结果。

新增产品时复用合适的 source，添加规则和有代表性的样例。修改规则后：

```bash
docker compose restart server
docker compose run --rm client
```

规则启动时校验 ID、协议/source、正则、捕获组和分数。坏规则不会被静默忽略；加载失败直接退出。置信度为公开的规则评分，unknown 固定为 0。

## 本地 Go 开发

工具链使用 Go 1.26.0，标准库实现，无需第三方模块。以下命令均在项目根目录执行：

```bash
go test ./...
go vet ./...
go build -o bin/server ./cmd/server
go build -o bin/client ./cmd/client
go run ./cmd/server serve --rules rules/fingerprints.json
```

另一个终端：

```bash
go run ./cmd/client --input samples/input.json --server http://127.0.0.1:8080
go run ./cmd/client --input testdata/mixed.json --server http://127.0.0.1:8080
```

Windows 构建真实进程验收所用文件时：

```powershell
go build -o bin/server.exe ./cmd/server
go build -o bin/client.exe ./cmd/client
python scripts/smoke.py --mode local
```

client stdout 仅包含结果 JSON，stderr 输出 HTTP 状态和请求 ID。HTTP 200 且结果符合契约时退出 0，包括非法条目被 server 降级为 unknown 的情况；文件/网络/响应/输出失败退出 1，参数错误退出 2。client 不自动重试批量请求。

## 配置与内部日志

server 的命令行参数优先于环境变量，环境变量优先于默认值：

| 环境变量 | CLI 参数 | 默认值 |
| --- | --- | --- |
| `LISTEN_ADDR` | `--listen` | `:8080` |
| `RULES_FILE` | `--rules` | 本地 `rules/fingerprints.json`；容器 `/app/rules/fingerprints.json` |
| `MAX_REQUEST_BYTES` | `--max-request-bytes` | 16777216，16 MiB |
| `MAX_BATCH_SIZE` | `--max-batch-size` | 1000 |
| `MAX_BANNER_BYTES` | `--max-banner-bytes` | 65536，64 KiB |
| `MAX_INFLIGHT_REQUESTS` | `--max-inflight-requests` | 4 |
| `REQUEST_TIMEOUT` | `--request-timeout` | 20s |
| `SHUTDOWN_TIMEOUT` | `--shutdown-timeout` | 30s |
| `LOG_LEVEL` | `--log-level` | INFO |

client 的文件和响应大小上限均为 16 MiB，请求超时默认 30s，可用 `--timeout` 调整。HTTP server 默认读头 5s、读取 10s、空闲 60s；写超时为处理预算加 5s。server 处理预算增大时，应同步调整 client 超时和 Compose 停机宽限。

结构化日志包含 `request_id`、`item_index`（从 0 开始）、内部错误码和简短原因，不记录完整 Banner。成功批次的 identified、unknown、invalid、failed 数量相加等于 total；请求中断时摘要表示已完成部分。

```json
{"level":"WARN","event":"item_rejected","request_id":"example","item_index":1,"code":"invalid_port","field":"port","reason":"port must be an integer between 1 and 65535"}
```

健康检查成功不刷访问日志。服务收到 SIGTERM / SIGINT 后退出就绪状态，等待在途请求，最多 30 秒；Compose 提供 35 秒停止宽限。

## 容器设计

- 同一 Dockerfile 使用 Go 构建阶段和两个 scratch 运行目标，编译时 `CGO_ENABLED=0`、`-trimpath`，运行镜像只保留对应二进制及必要规则。
- server 在容器内监听 `:8080`；仅发布宿主机 `127.0.0.1:8080`。client 不发布端口。
- client 只加入 `internal: true` 的 fingerprint 网络，以服务名访问 server。server 另接专用 ingress bridge，使 Docker 能实际发布本机端口；宿主机入口仍只绑定 `127.0.0.1`。
- 两个容器均以 `65532:65532` 运行，只读根文件系统、只读数据挂载，移除 capabilities，禁止权限提升。
- 内置 `server healthcheck` 使用 Go HTTP 客户端，scratch 中无需安装 shell 或 curl。
- client 依赖 `service_healthy`，作为一次性任务退出，`restart: "no"`。server 进程异常有限次重启；unhealthy 标记本身不会触发自动重启。
- 日志输出到容器 stdout/stderr，并配置大小及轮转数量；没有容器内日志文件或临时写入依赖。
- 默认容器链路使用内部 HTTP。宿主机 client 可使用系统 CA 访问 HTTPS；若扩展容器外部 HTTPS，需要同时补充 CA 与网络配置。

## 验证与交付资料

`samples/input.json` 和 `samples/expected.json` 给出题目全部 20 条合法化输入及预期结果。`testdata/mixed.json` 验证中间非法记录不会吞掉前后的有效结果。

Go 测试覆盖版本变化、非默认端口、缺失版本、HTTP 正文误匹配、MySQL 截断边界、二进制编码、规则冲突、请求限制、七字段结构、单条 panic 隔离、健康状态及 client 退出语义。

完整验收脚本：

```bash
# 先构建 bin/server 和 bin/client，再运行真实进程调用
python3 scripts/smoke.py --mode local

# 构建并启动完整 Compose，验收权限/网络/接口/客户端/优雅关闭
python3 scripts/smoke.py --mode compose
docker compose down
```

Compose 验收脚本完成后会停止 server，以核验 SIGTERM 优雅退出；再次运行服务使用 `docker compose up`。

GitHub Actions 在每次 push 和 PR 中运行 `go vet`、`go test -race`、真实进程验收和 Docker Compose 验收。容器验收还检查实际用户、只读文件系统、capabilities、只读挂载、内部网络、回环端口发布以及默认 client 的退出状态。

详细设计见 [技术文档 V1](docs/banner-fingerprint-technical-design-v1.md)。仓库公开，评估者可以直接克隆。首次完全断网构建需要预先准备构建镜像；默认交付不包含镜像离线包。
