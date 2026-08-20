# oixproxy

开源的 oixCloud **专属 helper** 数据面（CGO-free，可在 Linux / macOS 运行，后续可交叉编译到 Windows、OpenWrt）。

用 `accessToken` 登录后，把面板下发的 **snell + ech-tls** 节点映到本机 SOCKS5（同一端口也接 HTTP CONNECT），再对外提供 Surge / Clash / 节点列表 / OpenSurge 配置。客户端侧只有本地 socks5，**不会**出现 PSK、ECH、anytls 密码。

公开订阅 `clash=1`（`type: anytls`）**不是**专属节点源，本程序不会去拉它。

参数和 `config.json` 对齐官方 `oixcloud-external-proxy-program`（`docker.md` / `opensurge.md` 里 helper 那一侧）。不含官方 macOS 菜单栏、DHCP/TUN（那是 OpenSurge 自己的事）。

## 快速开始

```bash
cp config.example.json config.json   # 填 accessToken
./oixproxy --map --listen 127.0.0.1:6172 --bind 127.0.0.1 --config ./config.json
```

局域网访问把 listen/bind 改成 `0.0.0.0`（并建议配置 `lanAuth`）。

未指定 `--config` 时依次尝试：

- `~/.config/oixcloud-external-proxy-program/config.json`
- `/config/config.json`（Docker 挂载）

```bash
curl -f http://127.0.0.1:6172/health
curl --socks5-hostname 127.0.0.1:7200 -o /dev/null -w '%{http_code}\n' https://www.google.com/generate_204
```

`map` 模式从 `mapBasePort` 起为每个节点占一个连续端口。请保证这段端口空闲（本机若已有进程占着其中某一个，启动会失败）。

## 配置文件

见 `config.example.json`。常用字段：

| 字段 | 默认 | 说明 |
|---|---|---|
| `accessToken` | （必填） | 面板登录令牌 |
| `proxyMode` | `map` | `map` 每节点一端口；`single` 只映一个节点 |
| `servePort` | `6172` | 配置 HTTP 端口（可被 `--listen` 覆盖） |
| `mapBasePort` | `7200` | map 模式起始端口（可被 `--map-base-port` 覆盖） |
| `listenAddress` | `127.0.0.1` | 默认绑定地址 |
| `simpleRules` | `false` | 为 `true` 时向面板带 `simplerules=true` |
| `filter` | `""` | 按节点名筛选，语法同 [Clash Meta filter](https://wiki.metacubex.one/config/proxy-groups/#filter)：正则，反引号分隔多条，按条的顺序保留 |
| `oixParams` | `""` | 额外面板查询参数（不会改成 `clash=1`） |
| `lanAuth` | 无 | `{ "username", "password" }`；环回地址不鉴权，非环回对 HTTP / SOCKS5 / HTTP CONNECT 生效 |
| `listeners` | `[]` | map 模式下额外的固定端口：`name` / `type` / `port` / `node` / `listen` |

`filter` / `--filter` 示例：`香港.*Premium` 与 `日本` 用反引号拼成一条，先留下香港 Premium，再留下日本：

```json
"filter": "香港.*Premium`日本"
```

身份文件与 `OpenSurge.yaml` 写在数据目录（`OIXCLOUD_DATA`，否则 `/data` 或 `~/.config/oixcloud-external-proxy-program`）。

## 命令行

与官方 helper 相同：

```
--serve                        启动本地托管配置 HTTP（map 时默认就会开）
--listen, -l [host:]port       配置服务地址
--port, -p [host:]port         single 模式代理端口
--bind <host>                  代理监听地址
--node, -n <name>              只使用指定节点
--filter <regexp>              按节点名筛选（同 Clash Meta filter，反引号分隔）
--mode <single|map>            模式
--map / --single               模式快捷方式
--map-base-port <port>         map 起始端口
--config, -c <path>            config.json
--help, -h
--version, -v
--healthcheck [host:]port      探活配置服务后退出
```

`--tray` / `--menu` / `--menubar` 仅官方 macOS 菜单栏使用，本程序会拒绝。

额外支持 `--profile <yaml>`：跳过面板，直接读本地专属 YAML（调试用）。

## HTTP 接口

配置服务根据客户端访问的 Host 填写代理地址：从 `http://127.0.0.1:6172/` 拉到的是环回；从 `http://<局域网IP>:6172/` 拉到的指向该 IP。

| 路径 | 内容 |
|---|---|
| `/health` | `ok` |
| `/` | 完整 Surge 托管配置（`#!MANAGED-CONFIG`） |
| `/clash` | Clash / mihomo provider，`type: socks5` |
| `/list` | Surge policy-path：`name = socks5, host, port`；环回带 `udp-relay=true` |
| `/opensurge` | OpenSurge 用的 mihomo overlay（只读检查，不要当 HTTPS 订阅源） |

客户端产物里只有本地 socks5，没有远端节点地址、PSK、ECH。

## OpenSurge

1. helper 保持运行。
2. 用 `GET /opensurge` 检查，或使用数据目录里写出的 `OpenSurge.yaml`（目录 `0700`，文件 `0600`）。
3. 在 OpenSurge「来源」里导入**本地 YAML**，不要把 `http://127.0.0.1:6172/opensurge` 填进 HTTPS 订阅框。

YAML 内容与官方 helper 一致：`oixcloud-nodes` HTTP provider（`/clash`，10 分钟刷新、5 分钟健康检查）、`oixCloud` Selector、helper 进程直连规则、`MATCH,oixCloud`。开启 `lanAuth` 时 provider URL 会带 Basic Auth，不要把这份 YAML 转发出去。

## 许可与仓库卫生

MIT。不要把 `config.json`、专属订阅 YAML、token 文件或 `.identity` 提交进仓库。

默认 `go test ./...` 只打本地夹具，不含真实订阅。联通性测试必须显式打开：

```bash
OIX_LIVE_SOCKS=1 OIX_PROFILE=/path/to/your-dedicated.yaml go test ./internal/run/ -run TestLiveMappedSOCKSReachesGoogle -count=1
```

## 编译

需要 Go 1.26+。默认关闭 CGO，便于交叉编译。

```bash
go build -o oixproxy ./cmd/oixproxy
```
