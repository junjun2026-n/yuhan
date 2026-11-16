# Ubuntu + Docker 部署

正式运行环境为 Ubuntu，建议 Ubuntu Server 24.04 LTS。镜像基于 `ubuntu:24.04`。
需要原生 Linux Docker Engine 和 Compose v2；Docker Desktop / Windows 容器中的网卡不是 Ubuntu 服务器物理网卡，不能用于本项目的透明串联部署。

## 1. 安装 Docker

Ubuntu 24.04 可以安装发行版提供的软件包：

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2
sudo systemctl enable --now docker
sudo docker compose version
```

也可以使用已有的 Docker Engine / Compose v2，无需重复安装。以下命令假定当前用户有 Docker 权限，否则在 docker / bash start.sh 前使用 sudo。

## 2. 复制项目并配置首次管理口

将 WAF 项目复制到例如 `/opt/waf`，不用复制 Windows 的 `.venv`、`.env` 和 `runtime`。
全新安装使用空 runtime；迁移数据库应先备份，再在页面将旧网卡绑定替换成 Ubuntu 物理网卡。

```bash
cd /opt/waf
ip -br link
nano mgrnic.ini
```

示例（把 enp1s0 换成实际**专用管理口**）：

```ini
[management]
alias = mgmt0
interface = enp1s0
physical_id =
mac =
ip = 192.168.1.1/24
nic_count = 3
apply_ip = true
```

网卡名称、物理标识、MAC 三种选择方式只填一项。别名与硬件的实际绑定存入数据库，首次成功后不再从 INI 覆盖。
`apply_ip=true` 添加管理地址，不删除现有地址或更改默认网关；会将专用管理口设为 UP。
无需预先在容器里创建与宿主机同名的虚拟网卡。
管理客户端需能到达该管理网段，且不要使用已被其他设备占用的 IP。

## 3. 构建并启动

```bash
cd /opt/waf
bash start.sh
docker compose ps
docker compose logs --tail=100 waf
sudo cat runtime/initial-admin.txt
```

首次构建需要下载 Ubuntu 镜像、APT 软件包及 Python 依赖。`start.sh` 创建 runtime 目录后执行 `docker compose up -d --build`。
管理员随机密码只生成一次，保存在 runtime 中，不写入镜像。

- 管理页面：`http://192.168.1.1:8301`（以实际已初始化 IP 为准）。
- Ubuntu 本机备用入口：`http://127.0.0.1:8301`。
- 反向代理入口：`http://服务器IP:8300`，未设置源站返回 503，不影响管理页面健康检查。

如果 mgrnic.ini 留空或管理 IP 初始化失败，页面仅在本机入口可用；可以通过 SSH 隧道访问：

```bash
ssh -L 8301:127.0.0.1:8301 user@ubuntu-server
```

在客户端浏览器访问 `http://127.0.0.1:8301`。页面「系统配置」显示具体初始化错误。
容器重建、Docker 重启和 Ubuntu 重启不会删除 runtime。初始化允许的自动应用 IP 会在容器再次启动时从数据库恢复管理 IP。

## 4. 网络权限与挂载

Compose 使用 `network_mode: host`，不会通过 Docker bridge 或 ports 映射隔离网卡。
容器看到的是 Ubuntu 宿主机网络命名空间，NET_ADMIN / NET_RAW 分别用于 IP、桥接、nftables 操作和镜像报文采集。
没有使用 `privileged: true`，无需挂载 Docker socket，也不挂载宿主机根目录。
服务以容器 root 运行，才能对已授权的宿主机网络进行配置。
宿主机 UFW / nftables 与已有网络服务仍需按管理网和业务网规划配置；不要把服务部署在承担其他重要业务的共享主机上后随意接管其业务网卡。

| 宿主机 | 容器 | 用途 |
| --- | --- | --- |
| `./mgrnic.ini` | `/app/mgrnic.ini`，只读 | 管理口初始化与业务口加载，详见 MGRNIC_DOCKER.md |
| `./runtime` | `/app/runtime`，可写 | 数据库、凭据、初始化状态、数据平面锁 |

容器根文件系统只读，临时文件放在 tmpfs `/tmp`。初始账号文件为 `runtime/initial-admin.txt`，实际认证配置为 `runtime/admin.env`。
初始管理员导入数据库后，在页面“修改密码”保存立即生效，无需重启。修改 `runtime/admin.env` 不会覆盖已导入用户密码；旧的初始密码文件可移除。详见 [用户与权限管理](USERS_PERMISSIONS.md)。
不要把 runtime 放进镜像，或将其和 mgrnic.ini 替换成不明来源文件。

## 5. 旁挂与串联

容器默认启用数据平面自动管理，不需要另行执行 Python 工作进程。
在页面保存配置后会依照逻辑别名映射实际网卡：

- 反向代理：只运行管理服务和 8300 代理。
- 镜像旁挂：将交换机镜像目的口接到配置的镜像业务口；自动采集，仅审计，不拦截。
- 透明串联：上下游分别连接两块专用业务口；自动创建 `wafbr0` 和 `bridge waf_guard` nftables 表，并运行 NFQUEUE。

业务口不得拥有主机 IPv4 / 全局 IPv6 地址，不得已属于其他 bridge / bond；管理口不参与桥接。
部署前由宿主机网络配置（Netplan / NetworkManager / systemd-networkd）为 WAF 预留这些业务口，避免系统网络服务重新分配地址或接管桥接关系。
镜像模式和串联模式都要求独立管理网卡成功绑定，串联通常至少需要三块网卡。

系统配置改变时，监督进程停止旧数据平面并启动新配置。串联桥接切换有中断，请在维护窗口操作。
数据平面异常退出会保留管理服务，容器健康状态会变成 unhealthy；Docker 自身不会仅因 unhealthy 自动重启容器。
为避免不断创建 / 删除桥接，失败配置不循环自动重试；修正配置后保存，或执行 `docker compose restart waf` 重试。
只点保存而未改变任何配置不会重试同一份失败配置。

容器正常停止会向工作进程发 SIGTERM，等待其清理创建的桥接和 nftables 表。
不要使用 `docker kill` / SIGKILL 作为正常停止方式；强制杀死或主机断电后可能残留规则，需从本机或独立管理口检查恢复。
当前是软件桥，无硬件断电直通能力。停止串联服务会中断相应物理链路。

当前检测范围为 TCP 80 / 8080 的明文 HTTP/1.x。HTTPS、HTTP/2、HTTP/3 不会被解密或审计；详细范围见 README。

## 6. 日常维护

```bash
# 更新代码后重建
docker compose up -d --build

# 查看状态 / 日志
docker compose ps
docker compose logs -f --tail=100 waf

# 应用新的管理 IP 后重启，以更新管理监听地址
docker compose restart waf

# 正常停止，runtime 保留
bash stop.sh

# 停止并删除容器，runtime 仍保留
docker compose down
```

健康检查验证本机管理 API、数据库、8300 监听；当配置旁挂 / 串联时还验证数据平面心跳。
重启策略为 `unless-stopped`，管理员手工停止后不会自动拉起，直到再次启动。
Docker stdout / stderr 日志配置了轮转；SQLite 审计记录仍需按磁盘空间安排归档。

备份前正常停止服务，将整个 runtime 和 mgrnic.ini 备份到受控位置，然后重新启动。
恢复时使用同样的运行目录结构，网卡更换后通过原逻辑别名重新绑定。
数据库 WAL 文件也属于备份内容，不能只在服务运行时随意复制主数据库文件。

## Docker Hub 受限时的基础镜像

Dockerfile 支持 `UBUNTU_IMAGE` 构建参数；Compose 可以通过项目 `.env` 中的 `WAF_UBUNTU_IMAGE` 指定本地 Ubuntu 基础镜像。
可以使用 Canonical 官方 `https://partner-images.canonical.com/oci/noble/current/` 发布的最小 OCI 根文件系统。
下载对应架构的 root.tar.gz、SHA256SUMS、SHA256SUMS.gpg，使用 Ubuntu 的 ubuntu-cloudimage-keyring 验证签名、核对 SHA256 后，再执行 docker import。
不能仅因为 Docker Hub 访问失败，就把第三方来源不明的同名镜像视为官方 Ubuntu 镜像。

例如 amd64 主机验证完下载文件后：

```bash
docker import ubuntu-noble-oci-amd64-root.tar.gz waf-ubuntu-base:24.04
printf 'WAF_UBUNTU_IMAGE=waf-ubuntu-base:24.04\n' > .env
bash start.sh
```

## 离线镜像包

如果已有 `qionghai-waf-ubuntu24.04.tar.gz` 和 `waf-deploy-files.tar.gz`，先核对随包的 WAF-SHA256SUMS，再加载和启动，不需要联网重新构建：

```bash
mkdir -p /opt/waf
cd /opt/waf
tar -xzf /path/to/waf-deploy-files.tar.gz
# 按目标机器修改 mgrnic.ini 的管理口和 IP
mkdir -p runtime
docker image load -i /path/to/qionghai-waf-ubuntu24.04.tar.gz
docker compose up -d --no-build --pull never
```

镜像包和部署文件不包含运行数据库、管理员密码；新安装会生成新的管理员凭据。

## 验证状态

已在 Ubuntu 22.04 宿主机 `192.168.17.126` 完成 Ubuntu 24.04 最小 OCI 基础镜像导入、WAF 多阶段镜像构建及 Compose 启动。
容器健康检查、管理网卡初始化、认证访问、实际 HTTP 源站转发和 SQLi 拦截通过。
该服务器只有一个实际管理网卡，当前运行反向代理模式；物理镜像旁挂和透明串联尚未在独立业务网卡上验收。
具体部署目录和打包信息见 [192.168.17.126 部署记录](DEPLOYMENT_192.168.17.126.md)。
