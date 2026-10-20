# Banner 指纹识别系统技术文档

版本：V1.0  
日期：2026-10-20  
用途：作为第一版实现、联调和验收的技术依据。

系统使用 Go 开发独立的 client 和 server，接收已有网络扫描数据，批量提取协议、软件、软件版本与操作系统线索，通过 Docker Compose 完成构建、启动和示例调用。

已确认的接口原则是：每条识别结果严格保留七个字段，不增加 `error`、`status`、`index` 等字段。批内非法输入逐条处理，输出 `unknown`；具体错误在服务端内部记录，其他记录继续处理。

## 1 开发目标与范围

| 编号 | 需求 | 完成标准 |
| --- | --- | --- |
| R01 | 独立 client 与 server | 分别具有 Go 程序入口和可执行文件 |
| R02 | 批量识别接口 | `POST /fingerprint` 接收 JSON 数组并返回结果数组 |
| R03 | 健康检查 | `GET /health` 能反映服务是否就绪 |
| R04 | 最低识别能力 | 覆盖 SSH、HTTP、MySQL、Redis、FTP，提取可见产品和版本 |
| R05 | 固定响应字段 | 所有结果对象恰好包含规定的七个字段 |
| R06 | 逐条容错 | 单条非法或未知数据不影响其他条目，不导致服务崩溃 |
| R07 | 规则解耦 | 产品特征和提取规则由独立配置维护 |
| R08 | 一键运行 | 干净克隆项目后，执行 `docker compose up` 可跑通默认示例 |
| R09 | 部署约束 | 服务名通信、真实健康依赖、多阶段构建、非 root 和最小权限 |
| R10 | 独立验收 | 源码、样例、配置与 README 足以支持评估者自行运行 |

HTTP 产品覆盖 nginx、Apache、Jetty，并纳入自测输入中的 Microsoft-IIS。FTP 产品覆盖 ProFTPD、vsFTPd、Pure-FTPd。TLS 作为后续扩展项，第一版对 TLS 片段返回 `unknown`。

当前系统分析调用方提供的 Banner，不主动连接输入的 IP 和端口。数据保存在请求处理过程和日志中，第一版无需数据库。

## 2 整体架构

```text
本地 JSON 文件
      │
      ▼
独立 client ── POST /fingerprint ──► server
      ▲                                │
      │                                ├─ 请求边界检查
      │                                ├─ 逐条校验与 Banner 解码
      │                                ├─ 协议解析与规则匹配
      │                                ├─ 结果归一化
      │                                └─ 内部错误日志
      └──────── 七字段 JSON 数组 ───────┘

规则文件 ── 启动时加载和编译 ──► 识别引擎
Docker healthcheck ── GET /health ──► server
```

server 在启动时加载规则并构造只读识别引擎。请求之间共享编译后的规则，每次请求使用自己的输入、候选结果和诊断信息。第一版在一个批次内按顺序处理，保持输出顺序；不同请求由 HTTP 服务并发处理，并设置并发上限。

### 2.1 目标项目结构

以下是实现阶段的目标目录：

```text
banner-fingerprint/
├── cmd/
│   ├── server/main.go
│   └── client/main.go
├── internal/
│   ├── api/                     # 路由、请求处理、健康检查、恢复边界
│   ├── config/                  # 参数、环境变量及校验
│   ├── model/                   # 输入、七字段输出、内部诊断类型
│   ├── validation/              # 逐条字段校验与编码解码
│   ├── fingerprint/
│   │   ├── engine.go            # 候选匹配与稳定选择
│   │   ├── rules.go             # 规则加载、校验、预编译
│   │   └── parsers/             # SSH、HTTP、MySQL、Redis、FTP
│   └── logging/                 # 请求关联及结构化日志
├── rules/fingerprints.json
├── samples/
│   ├── input.json
│   └── expected.json
├── testdata/                    # 混合非法、未知、截断数据
├── docs/
├── Dockerfile
├── compose.yaml
├── .dockerignore
├── go.mod
└── README.md
```

优先使用 Go 标准库完成 HTTP、JSON、正则、Base64、IP 校验和日志处理。引入第三方模块时提交对应的 `go.sum`。Go 工具链在实现阶段固定到受支持的稳定补丁版本，Dockerfile 和模块声明保持兼容。

## 3 输入契约

### 3.1 字段定义

| 字段 | 类型 | 必填 | 规则 |
| --- | --- | --- | --- |
| `ip` | string | 是 | 合法 IPv4 或 IPv6 地址 |
| `port` | integer | 是 | `1～65535` |
| `banner` | string | 是 | 允许空字符串；解码后不超过 64 KiB |
| `banner_encoding` | string | 否 | `text` 或 `base64`，缺省为 `text` |

输入校验采用以下约定：

- 不自动修正 IP 前后空格，不接受域名代替 IP。
- 端口只接受 JSON 整数字面量；`"80"`、`80.0`、`8e1` 均视为非法。
- 缺少 `banner` 与 `banner: ""` 区分处理；前者非法，后者合法但通常无法识别。
- 显式提供 `banner_encoding` 时，其值必须是支持的字符串，`null` 和空字符串均非法。
- 未定义的额外输入字段可以忽略；重复字段名视为该条非法，避免同一字段具有多个值。
- 数组内的 `null`、字符串、数字和数组等非对象元素均按单条非法输入处理。
- 空数组合法；顶层 `null`、对象或字符串不属于批量输入。

### 3.2 文本与二进制编码

`text` 表示先进行标准 JSON 解码，再将得到的字符串作为 UTF-8 字节传给识别器。支持 JSON 的 `\r\n`、`\n`、`\u0000`，不对字面量 `\xNN` 进行第二次反转义。

MySQL 自测片段可表示为：

```json
[
  {
    "ip": "1.2.3.7",
    "port": 3306,
    "banner": "J\u0000\u0000\u0000\n8.0.32\u0000"
  }
]
```

任意原始字节使用标准 Base64 传输。上面的同一片段也可表示为：

```json
[
  {
    "ip": "1.2.3.7",
    "port": 3306,
    "banner": "SgAAAAo4LjAuMzIA",
    "banner_encoding": "base64"
  }
]
```

采用标准 Base64 字母表及所需填充，不接受 URL-safe 变体或夹带空白的编码。先根据编码长度检查潜在大小，再解码并核验实际长度。解码失败只影响该条记录。

题目中的重复双引号和 `\xNN` 需在制作样例文件时转换为合法 JSON。JSON Unicode 字符不等同于任意单个原始字节，因此二进制保真传输使用 Base64。

## 4 HTTP 接口

### 4.1 批量指纹识别

请求方式：`POST /fingerprint`。请求 `Content-Type` 为 `application/json`，允许携带 `charset` 参数。

```json
[
  {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
  {"ip":"1.2.3.5","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"}
]
```

HTTP 200 响应：

```json
[
  {"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95},
  {"ip":"1.2.3.5","port":80,"protocol":"HTTP","product":"nginx","version":"1.24.0","os_hint":"","confidence":0.9}
]
```

### 4.2 固定结果结构

| 字段 | JSON 类型 | 说明 |
| --- | --- | --- |
| `ip` | string | 有效输入 IP 原样保留 |
| `port` | integer | 有效输入端口原样保留 |
| `protocol` | string | 协议名称，无法识别时为小写 `unknown` |
| `product` | string | 规范化产品名称，无法确定时为空字符串 |
| `version` | string | 软件版本，无法提取时为空字符串 |
| `os_hint` | string | Banner 中有依据的操作系统线索 |
| `confidence` | number | `0～1` 的有限数值，unknown 固定为 `0` |

响应不包含 Banner、内部诊断、规则 ID 或条目索引。七字段全部输出，不使用 `omitempty`；空结果数组编码为 `[]`。

有效输入的输出数量、位置与输入一一对应。重复输入分别返回结果，不去重。

### 4.3 非法条目的输出

非法条目统一生成 unknown 结果，并分别保留该条中有效的 `ip` 和 `port`。IP 无效时填 `""`，端口无效时填 `0`。条目只要存在字段错误，就不再对它进行指纹识别。

例如请求：

```json
[
  {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
  {"ip":"1.2.3.5","port":"80","banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"},
  null,
  {"ip":"1.2.3.23","port":12345,"banner":"QUIT\r\n"}
]
```

仍返回 HTTP 200：

```json
[
  {"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95},
  {"ip":"1.2.3.5","port":0,"protocol":"unknown","product":"","version":"","os_hint":"","confidence":0},
  {"ip":"","port":0,"protocol":"unknown","product":"","version":"","os_hint":"","confidence":0},
  {"ip":"1.2.3.23","port":12345,"protocol":"unknown","product":"","version":"","os_hint":"","confidence":0}
]
```

第二、三条记录在内部产生日志；第四条属于合法未知数据，不记为输入错误。四条结果均只有规定的七个字段。

### 4.4 请求级错误

`/fingerprint` 的应用层响应体始终为 JSON 数组。请求级失败返回对应 HTTP 状态码及 `[]`，详细原因写服务端日志。

| 状态码 | 场景 |
| --- | --- |
| `200` | 合法数组处理完成，包括空数组、含非法条目、全部 unknown |
| `400` | JSON 语法损坏、顶层非数组、数组后还有额外 JSON 内容 |
| `405` | 请求方法不支持，同时设置 `Allow` 响应头 |
| `413` | 整个请求体或批量条数超过限制 |
| `415` | 请求媒体类型不是 `application/json` |
| `429` | 处理中的识别请求达到并发上限 |
| `500` | 请求级未预期内部故障 |
| `503` | 服务未就绪或请求处理预算耗尽 |

正常处理的响应设置 `Content-Type: application/json`。所有进入应用处理层的请求生成服务端请求 ID，并通过 `X-Request-ID` 响应头返回。关联 ID 不占用响应体字段。

HTTP 服务在读取请求行、请求头或网络连接时发生的底层失败，可能表现为连接关闭或 HTTP 层错误；client 将其作为请求失败处理。

### 4.5 健康检查

`GET /health` 通过 HTTP 状态码表示健康状态，响应体为空：

- 规则加载、校验、编译成功且服务可以接收请求：`200`。
- 尚未就绪或进入关闭流程但监听仍可访问：`503`。

健康检查不执行扫描或整批样例识别，也不受识别接口的并发限流影响。监听关闭后，健康检查会连接失败。

## 5 服务端处理流程

一次批量请求按以下步骤执行：

1. 生成请求 ID，检查路径、方法、媒体类型、就绪状态与并发额度。
2. 限制请求体大小，在处理时间预算内读入并解析顶层数组。
3. 验证数组后没有额外 JSON 值，检查批量条数上限。
4. 为每个输入位置预先分配 unknown 结果。
5. 逐条检查对象形态、重复字段、字段存在性、类型与取值。
6. 有错误时保留有效 IP 和端口，记录内部诊断，继续下一条。
7. 对合法条目解码 Banner，识别协议结构，执行对应产品规则。
8. 选择稳定的候选结果，提取产品、版本和系统线索。
9. 汇总处理数量和耗时，完整序列化结果后一次性写出响应。
10. 释放并发额度并记录请求完成日志。

使用 `[]json.RawMessage` 延迟解析数组元素，避免将整个数组直接绑定到强类型输入切片后，被某条类型错误中断。字段名与重复字段使用逐条对象解析检查；`null` 和缺失字段必须显式区分。`RawMessage` 的延迟解码方式见 [Go JSON 文档](https://pkg.go.dev/encoding/json#RawMessage)。

请求体限制使用 `http.MaxBytesReader` 等 HTTP 边界机制。单条识别设置恢复边界，捕获意外 panic 后记录内部错误、保留该条 unknown 并继续；请求级恢复在尚未提交响应时返回 `500 []`。通过输入边界检查和确定性解析预防异常，恢复机制承担最后一道容错。

### 5.1 核心类型

```go
type Result struct {
    IP         string  `json:"ip"`
    Port       int     `json:"port"`
    Protocol   string  `json:"protocol"`
    Product    string  `json:"product"`
    Version    string  `json:"version"`
    OSHint     string  `json:"os_hint"`
    Confidence float64 `json:"confidence"`
}

type NormalizedInput struct {
    IP     string
    Port   int
    Banner []byte
}

// 仅用于服务内部，不写入 HTTP 响应。
type ItemIssue struct {
    Code    string
    Field   string
    Message string
}
```

校验层返回规范化输入、可保留的 IP/端口以及内部诊断。识别引擎返回候选结果和内部执行错误。普通“无规则命中”属于正常识别结果，不作为 Go error 返回。

## 6 协议识别策略

### 6.1 通用原则

- 以 Banner 内容为依据，端口只作为辅助信息，不能单独决定协议。
- 先识别协议结构，再在该协议的上下文中匹配产品。
- 不跨协议拼接产品、版本与系统信息。
- 软件版本与协议版本分别处理；HTTP 的 `1.1`、SSH 的 `2.0` 不写入软件版本字段。
- 已识别协议但无产品信息时保留协议，产品和版本为空。
- 版本通过提取规则获得，不能只匹配自测中的固定版本。
- 原始字节不全局转小写、不全局删除 NUL；仅在明确的文本上下文做大小写无关比较。
- 有截断数据时，只使用已存在且可验证的字段；所有切片和长度读取先检查边界。

### 6.2 各协议处理

| 协议 | 识别与提取方式 | 关键边界 |
| --- | --- | --- |
| SSH | 解析 `SSH-协议版本-软件标识`，在软件标识和注释中提取 OpenSSH 版本与系统线索 | 支持 `SSH-2.0`、`SSH-1.99`；保留 `8.9p1` 等完整软件版本 |
| HTTP | 识别响应状态行，读取响应头，针对 `Server` 值匹配产品和版本 | 头名称大小写无关；支持缺少结束空行的截断头；正文不参与 Server 产品匹配 |
| MySQL | 解析包头及握手协议标识，在握手版本字段中读取以 NUL 结束的软件版本 | 样例包不完整；版本字段已完整时允许识别，不能因声明总长度较大就全部拒绝 |
| Redis | 匹配 `+PONG`、`-NOAUTH Authentication required.`、规定的参数错误消息等特征 | 允许样例省略末尾 CRLF；任意 `-ERR` 不直接判为 Redis |
| FTP | 解析欢迎行，识别 ProFTPD、vsFTPd、Pure-FTPd 特征并提取版本 | 单独的 `220` 不足以确定 FTP；Pure-FTPd 无版本时留空 |

HTTP 样例位于 443、8443 时仍输出 `HTTP`。HTTP 解析器需要读取所给片段中的头字段，不依赖完整 HTTP 消息或响应体。

MySQL 第一版针对带四字节包头的服务端握手前缀：验证长度字段、初始包序号和协议标识 `0x0a`，再在已接收范围内寻找版本结束 NUL。声明长度可以大于现有片段，但必须能容纳已提取的字段。只有数字版本字符串而没有握手特征时不判为 MySQL。握手字段顺序参照 [MySQL HandshakeV10](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html)。

Redis 的简单字符串和错误响应均按 RESP 特征解析，具体语法参照 [Redis 协议说明](https://redis.io/docs/latest/develop/reference/protocol-spec/)。

### 6.3 候选选择与置信度

引擎先区分产品候选和通用协议候选，同协议内优先使用产品候选。多个同类候选依次比较：显式 `priority` 降序、`confidence` 降序、规则 ID 字典序升序。规则 ID 必须唯一，文件排列顺序不改变结果。

第一版采用可解释的固定规则评分：

| 识别证据 | 默认分数 |
| --- | --- |
| OpenSSH 产品和软件版本 | `0.95` |
| nginx、Apache、Microsoft-IIS 产品和版本 | `0.90` |
| Jetty 产品和版本 | `0.85` |
| MySQL 握手特征及版本 | `0.90` |
| FTP 产品和版本 | `0.90` |
| 明确产品但版本缺失，如 Pure-FTPd | `0.80` |
| Redis 典型无版本响应 | `0.70` |
| 明确的通用协议结构，产品未知 | `0.60` |
| 无法识别或非法输入 | `0` |

置信度是规则评分。OS 线索不额外改变分数；分数存放在规则配置中，启动时校验范围和数值有效性。

## 7 规则配置

规则文件使用 JSON，第一版修改后重启生效。协议的字节结构由解析器处理，产品名称、匹配表达式、版本提取、规则优先级和分数由规则配置定义。

下面给出一条 nginx 规则的目标格式：

```json
{
  "schema_version": 1,
  "rules": [
    {
      "id": "http.nginx.version",
      "protocol": "HTTP",
      "kind": "product",
      "source": "http.server",
      "match": {
        "type": "regex",
        "pattern": "(?i)^nginx/(?P<version>[0-9]+(?:\\.[0-9]+)+(?:[-+][A-Za-z0-9._-]+)?)(?:\\s|$)"
      },
      "product": "nginx",
      "version_group": "version",
      "os_hints": [
        {"pattern": "(?i)\\bUbuntu\\b", "value": "Ubuntu"},
        {"pattern": "(?i)\\bDebian\\b", "value": "Debian"}
      ],
      "priority": 100,
      "confidence": 0.9
    }
  ]
}
```

`source` 是解析器提供的受支持字段，例如 `http.server`、`ssh.identification`、`mysql.server_version`、`redis.response`、`ftp.greeting`。`match.type` 支持 `regex` 和 `exact`；`version_group` 缺省时版本为空。`os_hints` 在同一 source 内按配置顺序取首个匹配结果。

规则加载需要检查 schema 版本、重复 ID、合法协议、source 与协议对应关系、匹配类型、必需字段、正则、捕获组、优先级及置信度。通用协议规则由解析器提供的结构特征触发，也在配置中维护 ID、优先级和分数。

规则文件缺失、没有启用规则或规则校验失败时，server 输出启动错误并以非零状态退出。不得悄悄跳过坏规则后报告健康。

新增普通产品的步骤是：选择已有 source → 添加产品规则 → 添加针对性样本 → 重启并验证。新增协议需要增加结构解析器和相应规则。

## 8 内部错误与日志

采用结构化 JSON 日志，写到标准输出或标准错误，由容器日志系统收集。时间使用 UTC，字段包括日志级别、事件名称和请求关联信息。

条目错误至少记录：

| 字段 | 含义 |
| --- | --- |
| `request_id` | 服务端生成的请求 ID |
| `item_index` | 输入数组的零基序号 |
| `code` | 稳定的内部错误码 |
| `field` | 出错字段，没有具体字段时为空 |
| `message` | 简短原因 |

```json
{"level":"WARN","event":"item_rejected","request_id":"example-request-001","item_index":1,"code":"invalid_port","field":"port","message":"port must be an integer between 1 and 65535"}
```

内部错误码至少覆盖：`invalid_item`、`missing_field`、`duplicate_field`、`invalid_ip`、`invalid_port`、`invalid_banner`、`unsupported_encoding`、`invalid_base64`、`banner_too_large`、`internal_item_error`。

请求完成时记录总条数、识别成功数、合法 unknown 数、非法条目数、内部处理失败数、HTTP 状态码和耗时；这四类条目计数相加等于总条数。默认不记录完整 Banner 或原始请求体。合法 unknown 不作为错误逐条刷日志。

发生问题时使用响应头中的请求 ID 查询 server 日志，再以 `item_index` 对应原始输入。HTTP 响应体始终保持七字段结果结构。

## 9 client 设计

命令行入口约定：

```text
client --input <JSON文件路径> --server <server基础地址> --timeout 30s
```

client 读取文件并发送原始 JSON 内容，不先把每条记录绑定到强类型结构体，以免在客户端整批拒绝某条非法数据。可以预检顶层数组和请求大小，但不实施逐条字段拦截。

HTTP 200 时，client 校验响应为数组、条数与输入一致、对象包含七字段且字段类型正确，然后将格式化 JSON 写到 stdout。运行提示、HTTP 状态和请求 ID 写到 stderr。非 200 时不把 `[]` 当作成功结果。

| 退出码 | 场景 |
| --- | --- |
| `0` | HTTP 200，响应格式正确且全部结果输出成功，包括全部 unknown |
| `1` | 文件读取、网络、超时、非 200 响应、响应解析或输出失败 |
| `2` | 命令行参数错误 |

client 不根据 unknown 推断内部发生了输入错误，也不据此退出失败。第一版不自动重试批量请求；Compose 负责等待初次健康状态，后续失败通过退出状态和日志呈现。

## 10 配置与资源边界

server 配置优先级为命令行参数、环境变量、内置默认值。参数取值非法时启动失败。

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `LISTEN_ADDR` | `:8080` | 容器内监听所有接口 |
| `RULES_FILE` | `/app/rules/fingerprints.json` | 规则路径 |
| `MAX_REQUEST_BYTES` | `16777216` | 16 MiB HTTP 请求体 |
| `MAX_BATCH_SIZE` | `1000` | 单次最多条数 |
| `MAX_BANNER_BYTES` | `65536` | 单条解码后 64 KiB |
| `MAX_INFLIGHT_REQUESTS` | `4` | 同时处理的识别请求数 |
| `REQUEST_TIMEOUT` | `20s` | handler 总预算，包含读取 body |
| `SHUTDOWN_TIMEOUT` | `30s` | 优雅关闭等待时间 |
| `LOG_LEVEL` | `info` | 日志级别 |

HTTP server 设置 `ReadHeaderTimeout=5s`、`ReadTimeout=10s`、`WriteTimeout=25s`、`IdleTimeout=60s`。client 默认总超时为 30 秒。不同超时的起点不同，handler 需检查上下文取消并及时停止后续识别。

单条 Banner 超限属于条目错误；请求体和批量数量超限属于请求边界错误。并发额度耗尽时直接返回 `429 []`，不建立无限等待队列。

停止时接收 `SIGTERM` 或 `SIGINT`，将就绪状态设为 false，再调用 `http.Server.Shutdown` 等待在途请求。主流程等待关闭过程完成后退出。关闭行为参照 [Go HTTP Server 文档](https://pkg.go.dev/net/http#Server.Shutdown)。

## 11 Docker 与 Compose 部署

### 11.1 镜像设计

一个 Dockerfile 包含构建阶段以及名为 `server`、`client` 的两个运行目标。构建阶段分别编译两个二进制，启用 `CGO_ENABLED=0` 并使用 `-trimpath`，目标为对应平台的 Linux 程序。

运行目标使用 `scratch`，只复制所需二进制；server 额外复制默认规则。运行用户固定为数字 UID/GID `65532:65532`。规则文件需允许该用户读取。

`server healthcheck` 子命令通过 Go HTTP 客户端访问 `/health`，超时 2 秒，仅状态码 200 时退出 0。它不加载规则、不启动监听，不依赖 shell、curl 或 wget。

默认 Compose 使用内部 HTTP。若后续支持从 client 容器访问外部 HTTPS 服务，需要同时配置容器网络和 CA 证书。多阶段构建依据见 [Docker 多阶段构建文档](https://docs.docker.com/build/building/multi-stage/)。

### 11.2 Compose 配置基线

以下配置约定 Dockerfile 的运行入口分别为 `/app/server` 和 `/app/client`：

```yaml
services:
  server:
    build:
      context: .
      target: server
    command: ["serve"]
    environment:
      LISTEN_ADDR: ":8080"
      RULES_FILE: "/app/rules/fingerprints.json"
    ports:
      - "127.0.0.1:8080:8080"
    networks: [ingress, fingerprint]
    user: "65532:65532"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    volumes:
      - ./rules:/app/rules:ro
    healthcheck:
      test: ["CMD", "/app/server", "healthcheck", "--url", "http://127.0.0.1:8080/health"]
      interval: 5s
      timeout: 3s
      start_period: 5s
      retries: 5
    restart: "on-failure:3"
    stop_grace_period: 35s
    mem_limit: 512m
    pids_limit: 128
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

  client:
    build:
      context: .
      target: client
    command: ["--server", "http://server:8080", "--input", "/data/input.json"]
    networks: [fingerprint]
    depends_on:
      server:
        condition: service_healthy
    user: "65532:65532"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    volumes:
      - ./samples:/data:ro
    restart: "no"
    mem_limit: 256m
    pids_limit: 64

networks:
  ingress:
    driver: bridge
  fingerprint:
    driver: bridge
    internal: true
```

server 在容器内监听 `:8080`，client 使用 `http://server:8080`。宿主机的 `127.0.0.1` 端口发布用于本机验收，不能把 server 的容器监听地址也缩成 loopback。

`service_healthy` 等待真实健康状态；client 成功退出后 server 继续运行。服务启动后的 unhealthy 状态不会单凭 `depends_on` 自动重新执行 client。参见 [Compose 启动依赖](https://docs.docker.com/compose/how-tos/startup-order/)。

client 只加入内部 fingerprint 网络，容器间使用服务名解析。server 额外加入专用 ingress 网络以支持实际的宿主机端口发布，宿主机入口仍限制为 `127.0.0.1`。这一配置已根据首次 Docker 验收中的端口发布行为调整：仅有内部网络时，容器之间调用成功，但该环境没有生成宿主机端口映射。

镜像拉取和构建依赖下载属于构建阶段，需在 README 单独说明网络前提。网络行为参见 [Compose 网络文档](https://docs.docker.com/compose/how-tos/networking/)。

### 11.3 启动与排查

```bash
# 首次构建并运行默认示例
docker compose up

# server 已运行时，再次执行默认 client
docker compose run --rm --no-deps client

# 将新数据放到 samples/acceptance.json 后执行
docker compose run --rm --no-deps client --server http://server:8080 --input /data/acceptance.json

# 查看容器状态和内部错误
docker compose ps -a
docker compose logs server

# 本机调用健康检查
curl -i http://127.0.0.1:8080/health

# 本机提交同一份数据
curl -H "Content-Type: application/json" --data-binary @samples/input.json http://127.0.0.1:8080/fingerprint
```

源码修改后使用 `docker compose up --build`。规则只读挂载时，修改规则后重启 server 生效。重复调用中的 `--no-deps` 用于复用已健康的 server，避免重新创建依赖容器。PowerShell 环境可用 `curl.exe` 执行上述 curl 示例。默认运行不使用 `--abort-on-container-exit`，避免 client 完成后把 server 一并停止。

## 12 自测与验收

### 12.1 自测数据的预期识别

将题目提供的 20 条输入整理为合法 `samples/input.json`，按下表生成 `samples/expected.json`。表中的 `空` 表示 JSON 空字符串。

| IP 尾号 | 协议 | 产品 | 版本 | os_hint | confidence |
| --- | --- | --- | --- | --- | --- |
| 4 | SSH | OpenSSH | 8.9p1 | Ubuntu | 0.95 |
| 5 | HTTP | nginx | 1.24.0 | 空 | 0.90 |
| 6 | HTTP | Apache | 2.4.57 | 空 | 0.90 |
| 7 | MySQL | MySQL | 8.0.32 | 空 | 0.90 |
| 8 | Redis | Redis | 空 | 空 | 0.70 |
| 9 | FTP | ProFTPD | 1.3.7 | 空 | 0.90 |
| 10 | HTTP | Jetty | 9.4.51 | 空 | 0.85 |
| 11 | SSH | OpenSSH | 9.3 | Debian | 0.95 |
| 12 | HTTP | nginx | 1.18.0 | Ubuntu | 0.90 |
| 13 | HTTP | Apache | 2.4.41 | Ubuntu | 0.90 |
| 14 | MySQL | MySQL | 5.7.42 | 空 | 0.90 |
| 15 | Redis | Redis | 空 | 空 | 0.70 |
| 16 | FTP | vsFTPd | 3.0.5 | 空 | 0.90 |
| 17 | HTTP | nginx | 1.25.3 | 空 | 0.90 |
| 18 | SSH | OpenSSH | 4.3 | 空 | 0.95 |
| 19 | unknown | 空 | 空 | 空 | 0 |
| 20 | HTTP | Microsoft-IIS | 10.0 | 空 | 0.90 |
| 21 | Redis | Redis | 空 | 空 | 0.70 |
| 22 | FTP | Pure-FTPd | 空 | 空 | 0.80 |
| 23 | unknown | 空 | 空 | 空 | 0 |

TLS 自测片段的 Base64 为 `FgMBAKUBAACh`，使用 `banner_encoding: "base64"` 保存。它是合法输入，第一版返回 unknown。

### 12.2 必要验证项目

| 验证项 | 必须观察到的结果 |
| --- | --- |
| 自测 20 条 | 条数、顺序和识别内容符合预期 |
| 版本变化 | 新版本通过提取规则识别，不依赖写死值 |
| 非默认端口 | 相同 Banner 在其他端口仍按内容识别 |
| 头大小写和截断 HTTP | 能提取可见 Server 信息 |
| 空 Banner、未知文本 | 返回 unknown，服务继续可用 |
| 文本与 Base64 等价输入 | 同一原始内容得到相同识别结果 |
| 截断 MySQL | 足够结构时提取版本，边界不足时返回 unknown |
| 混合非法批次 | 前后合法条目正常，非法位置回填 unknown |
| null、缺字段、错误类型、重复字段 | 逐条处理并写内部日志 |
| 输出结构 | 每条恰好七字段，空值不省略 |
| 请求损坏或超限 | 按契约返回 4xx 和空数组 |
| client 退出行为 | HTTP 200 的 unknown 不触发失败退出 |
| 无效规则 | 启动失败，不进入健康状态 |
| Compose 完整链路 | server 健康后 client 执行，client 完成后 server 保持运行 |
| 运行权限 | 非 root、只读挂载、最小 capabilities 与内部通信生效 |

测试文件放在对应 Go 包旁边，使用表驱动测试覆盖真实规则和边界。HTTP 行为使用 `httptest` 验证，容器配置通过一次实际 Compose 链路验收。只在实现变化、检查失败或仍有未解决问题时补充或重跑相关检查。

## 13 开发顺序与交付

| 阶段 | 工作内容 | 阶段产物 |
| --- | --- | --- |
| 1 | 固定输入输出模型、逐条校验、内部日志 | 七字段响应与混合非法批次可运行 |
| 2 | 规则加载、协议解析、产品提取 | 必需协议及 20 条自测通过 |
| 3 | HTTP 边界、健康状态、client | 本地完整调用链路 |
| 4 | Dockerfile、Compose、权限和生命周期 | 一键构建启动与健康依赖 |
| 5 | 针对性验证、样例、README | 可克隆、可运行、可核对的仓库 |

交付仓库需包含源码、规则、合法样例及预期结果、Dockerfile、Compose 文件、模块文件和 README。README 写明首次构建条件、默认行为、自定义输入方式、接口契约、日志排查、规则更新和配置项。

GitHub 仓库必须公开，或已将评估者添加为协作者；评估者应能直接克隆。当前交付按可联网获取构建镜像和依赖的环境设计，完全断网的首次构建需要另行提供离线镜像与依赖。

第一版文档确定接口、模块、识别策略和部署基线。后续拓展重点为完整规则清单、各协议解析器伪代码、规则 schema 的详细字段定义，以及与实际实现对应的测试用例和运维说明。
