# 开源的 oixCloud Surge / OpenSurge / Clash 转换器

把 oixCloud 节点转换成 Surge / Clash 配置，或配合 OpenSurge GUI 构建 DHCP/DNS 全屋网关。

Convert oixCloud nodes to Surge / Clash profiles, or build a DHCP/DNS gateway with the OpenSurge GUI.

本仓库是 [oixcloud-external-proxy-program](https://github.com/pickrui/oixcloud-external-proxy-program) 的开源数据面。用 `accessToken` 登录后，把面板下发的 **snell + ech-tls** 节点映到本机 SOCKS5（同一端口也接 HTTP CONNECT），再对外提供 Surge / Clash / 节点列表 / OpenSurge 配置。客户端侧只有本地 socks5，**不会**出现 PSK、ECH、anytls 密码。

参数和 `config.json` 对齐官方助手在 Docker / OpenSurge 一侧的行为。不含官方 macOS 菜单栏；DHCP/TUN 由 OpenSurge 自己负责。需要菜单栏、一键接入 Surge、自动更新时，请用官方发行版。

公开订阅 `clash=1`（`type: anytls`）**不是**专属节点源，本程序不会去拉它。

## 选择部署方式

| 场景 | 做法 |
|---|---|
| 在当前机器使用 Surge | 继续阅读本页「快速开始」 |
| 使用 OpenSurge GUI 与 DHCP/DNS 接管 | [OpenSurge](#opensurge) |
| 部署到 Linux、NAS 或家用服务器 | [Docker 部署](#docker-部署) |
| 保留现有 Surge 配置或自定义规则 | 用 `/list` 作为 `policy-path`，见 [保留现有 Surge 配置](#保留现有-surge-配置) |

## 快速开始

准备：

- Surge for Mac，或其它会消费 Surge / Clash 托管配置的客户端
- oixCloud 账户和 Access Token

```bash
cp config.example.json config.json   # 填 accessToken
./oixproxy --map --listen 127.0.0.1:6172 --bind 127.0.0.1 --config ./config.json
```

未指定 `--config` 时依次尝试：

- `~/.config/oixcloud-external-proxy-program/config.json`
- `/config/config.json`（Docker 挂载）

默认使用本地多端口映射（`map`），节点直接在 Surge 策略组中选择。`map` 模式从 `mapBasePort`（默认 `7200`）起为每个节点占一个连续端口，请保证这段端口空闲。

本机验收：

```bash
curl -f http://127.0.0.1:6172/health
curl --socks5-hostname 127.0.0.1:7200 -o /dev/null -w '%{http_code}\n' https://www.google.com/generate_204
```

完成标志：

- `GET /health` 返回 `ok`
- Surge 出现 oixCloud 配置和节点策略组
- 切换节点后可以正常访问网络

`/health` 不返回账户、节点或配置内容。

## Docker 部署

适用于 Linux 主机、NAS 和家用服务器，支持 `linux/amd64` 与 `linux/arm64`。需要 Docker Engine 和 Docker Compose。

镜像：[`ghcr.io/soffchen/oixproxy:latest`](https://github.com/soffchen/oixproxy/pkgs/container/oixproxy)

下载仓库后进入目录：

```bash
git clone https://github.com/soffchen/oixproxy.git
cd oixproxy
cp config.example.json config.json
chmod 644 config.json
```

镜像以非 root 运行，`config.json` 必须是 `0644`，`0600` 时容器读不到配置、无法启动。

编辑 `config.json`：填入 `accessToken`；建议设置 `lanAuth`，不需要鉴权时保持 `null`。

```bash
docker compose up -d
docker compose ps
curl -f http://127.0.0.1:6172/health
```

健康状态应显示 `healthy`。同一局域网设备使用 Docker 主机 IP：

```text
完整配置    http://用户名:密码@Docker主机IP:6172/
节点列表    http://用户名:密码@Docker主机IP:6172/list
Clash       http://用户名:密码@Docker主机IP:6172/clash
```

未配置 `lanAuth` 时删除 URL 中的 `用户名:密码@`。这些 URL 使用 HTTP，必须由防火墙限制在可信局域网内，禁止直接暴露公网。

| 项目 | 用途 |
|---|---|
| `config.json` | 账户与运行配置，只读挂载到 `/config/config.json` |
| `oixproxy-data` | 身份密钥与 `OpenSurge.yaml` |
| `6172/tcp` | 配置、节点列表和健康检查 |
| `7200-7299/tcp` | 默认节点映射端口 |

节点超过 100 个或使用范围外的固定端口时，扩大 `compose.yaml` 的端口范围。镜像以非 root 运行，根文件系统只读，并移除所有 Linux capabilities。

Compose 固定使用 `latest`，以后无需修改版本号：

```bash
docker compose pull
docker compose up -d
```

停止：

```bash
docker compose down
```

同时删除持久数据：

```bash
docker compose down -v
```

## 接入 Surge

在 Surge 中添加托管配置，地址为配置服务：

```text
完整配置    http://127.0.0.1:6172/
节点列表    http://127.0.0.1:6172/list
Clash       http://127.0.0.1:6172/clash
```

同一局域网设备改用助手所在主机的 IP；开启 `lanAuth` 时写成：

```text
http://用户名:密码@主机IP:6172/
http://用户名:密码@主机IP:6172/list
http://用户名:密码@主机IP:6172/clash
```

配置服务根据客户端访问的 Host 填写代理地址：从 `http://127.0.0.1:6172/` 拉到的是环回；从 `http://<局域网IP>:6172/` 拉到的指向该 IP。

Surge 首次要求安装时确认，然后开启 `Set as System Proxy`。

## 接入模式

| 模式 | 节点选择位置 | 本地端口 |
|---|---|---|
| `map`，默认 | Surge 策略组 | 从 `7200` 起，每个节点一个端口 |
| `single` | `--node` / 配置里只留一个节点 | 默认 `7100` |

```json
{
  "proxyMode": "map",
  "mapBasePort": 7200
}
```

固定节点端口：

```json
{
  "proxyMode": "map",
  "listeners": [
    { "name": "香港", "port": 7801, "node": "香港 01" },
    { "name": "日本", "type": "socks5", "port": 7802, "node": "日本 01" }
  ]
}
```

`type` 可选 `mixed`、`socks5`、`http`，默认 `mixed`。本程序的额外端口目前一律按 mixed（SOCKS5 + HTTP CONNECT）监听。

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

最小配置：

```json
{ "accessToken": "你的 Access Token" }
```

`filter` / `--filter` 示例：`香港.*Premium` 与 `日本` 用反引号拼成一条，先留下香港 Premium，再留下日本：

```json
"filter": "香港.*Premium`日本"
```

身份文件与 `OpenSurge.yaml` 写在数据目录（`OIXCLOUD_DATA`，否则 `/data` 或 `~/.config/oixcloud-external-proxy-program`）。

## 局域网访问

默认仅监听 `127.0.0.1`。局域网访问把 listen/bind 改成 `0.0.0.0`，并建议配置 `lanAuth`：

```bash
./oixproxy --map --listen 0.0.0.0:6172 --bind 0.0.0.0 --config ./config.json
```

这些 URL 使用 HTTP，HTTP Basic 仅做 Base64 编码而非加密，必须由防火墙限制在可信局域网内，禁止直接暴露公网。

## 保留现有 Surge 配置

不使用完整托管配置时，可在现有策略组中使用本地节点列表：

```ini
香港 = select, policy-path=http://127.0.0.1:6172/list, policy-regex-filter="香港|HK", update-interval=600
Premium = select, policy-path=http://127.0.0.1:6172/list, policy-regex-filter="Premium", update-interval=600
```

现有 `policy-regex-filter` 继续按本地节点名过滤。

## OpenSurge

OpenSurge 提供 Web GUI、mihomo TUN、DHCP/DNS、设备策略和流量观察；本助手继续负责 oixCloud 账户、节点与本地出站。两者通过 `127.0.0.1` 上的 HTTP proxy provider 与本地代理端口通信。

1. helper 保持运行。
2. 用 `GET /opensurge` 检查，或使用数据目录里写出的 `OpenSurge.yaml`（目录 `0700`，文件 `0600`）：

   ```text
   ~/.config/oixcloud-external-proxy-program/OpenSurge.yaml
   ```

3. 在 OpenSurge「来源」里导入**本地 YAML**，不要把 `http://127.0.0.1:6172/opensurge` 填进 HTTPS 订阅框。OpenSurge 会拒绝 loopback HTTP URL 导入，这是其 SSRF 安全边界。
4. 在 OpenSurge 的「网络设置」中选择局域网 DHCP 接管、旁路由或独立下游 LAN。

局域网 DHCP 接管不会自动修改路由器，必须按 OpenSurge 恢复状态机人工关闭和恢复路由器 DHCP，禁止同时运行两个 DHCP 服务器。

YAML 内容与官方 helper 一致：`oixcloud-nodes` HTTP provider（`/clash`，10 分钟刷新、5 分钟健康检查）、`oixCloud` Selector、helper 进程直连规则、`MATCH,oixCloud`。provider 只暴露本地端口，不包含远端节点地址、PSK 或 ECH。开启 `lanAuth` 时 provider URL 会带 Basic Auth，不要把这份 YAML 转发出去。

节点切换和面板节点更新通常不需要重新导出，OpenSurge 可在 Provider 页面手动刷新。修改配置服务端口、局域网鉴权或 helper 路径后，需要重新导入 YAML。

helper 必须先于 OpenSurge 启动。helper 退出时现有 OpenSurge 连接会失败，重新打开 helper 后刷新 provider。

详细步骤、运行边界与排错见官方 [OpenSurge 接入与 DHCP/DNS 接管](https://github.com/pickrui/oixcloud-external-proxy-program/blob/main/docs/opensurge.md)。

## HTTP 接口

| 路径 | 内容 |
|---|---|
| `/health` | `ok` |
| `/` | 完整 Surge 托管配置（`#!MANAGED-CONFIG`） |
| `/clash` | Clash / mihomo provider，`type: socks5` |
| `/list` | Surge policy-path：`name = socks5, host, port`；环回带 `udp-relay=true` |
| `/opensurge` | OpenSurge 用的 mihomo overlay（只读检查，不要当 HTTPS 订阅源） |

客户端产物里只有本地 socks5，没有远端节点地址、PSK、ECH。

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

## 常用操作

| 需求 | 入口 |
|---|---|
| 查看运行状态 | `curl -f http://127.0.0.1:6172/health` |
| 切换接入模式 | `proxyMode` / `--map` / `--single` |
| 修改规则后同步 | 重启 helper，让 Surge 刷新托管配置 |
| 导出 OpenSurge profile | 数据目录中的 `OpenSurge.yaml`，或 `GET /opensurge` 检查 |
| 允许局域网访问 | `--listen 0.0.0.0:6172 --bind 0.0.0.0`，并配置 `lanAuth` |
| 筛选节点 | `filter` / `--filter` |

## 更多

- 官方发行版、菜单栏与 Docker 镜像：[oixcloud-external-proxy-program](https://github.com/pickrui/oixcloud-external-proxy-program)
- [配置、接入模式、现有 Surge 配置和局域网访问](https://github.com/pickrui/oixcloud-external-proxy-program/blob/main/docs/configuration.md)
- [OpenSurge GUI 与 DHCP/DNS 接管](https://github.com/pickrui/oixcloud-external-proxy-program/blob/main/docs/opensurge.md)
- [Docker 部署与更新](https://github.com/pickrui/oixcloud-external-proxy-program/blob/main/docs/docker.md)
- [常见问题与日志](https://github.com/pickrui/oixcloud-external-proxy-program/blob/main/docs/troubleshooting.md)
- [Surge 官方手册](https://manual.nssurge.com/)

## 许可与仓库卫生

MIT。不要把 `config.json`、专属订阅 YAML、token 文件或 `.identity` 提交进仓库。

官方 [oixcloud-external-proxy-program](https://github.com/pickrui/oixcloud-external-proxy-program) 为专有软件，详见其 [NOTICE](https://github.com/pickrui/oixcloud-external-proxy-program/blob/main/NOTICE)。

默认 `go test ./...` 只打本地夹具，不含真实订阅。联通性测试必须显式打开：

```bash
OIX_LIVE_SOCKS=1 OIX_PROFILE=/path/to/your-dedicated.yaml go test ./internal/run/ -run TestLiveMappedSOCKSReachesGoogle -count=1
```

## 编译

需要 Go 1.26+。默认关闭 CGO，便于交叉编译。

```bash
go build -o oixproxy ./cmd/oixproxy
docker build -t oixproxy .
```
