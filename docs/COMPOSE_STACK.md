# 应用与 PostgreSQL 一键启动

`compose.stack.yaml` 提供 WAF 应用与 PostgreSQL 两个服务，适用于新的 Ubuntu 独立部署。原 `compose.yaml` / `start.sh` 继续用于现有外部数据库或 SQLite 部署。

## 首次启动

安装 Docker Engine 和 Compose v2，将项目放在例如 `/opt/waf`，按实际硬件填写 `mgrnic.ini`，执行：

```bash
cd /opt/waf
bash start-stack.sh
docker compose -f compose.stack.yaml ps
sudo cat runtime-stack/initial-admin.txt
```

启动脚本自动创建独立的 `runtime-stack/` 和随机数据库密码文件 `.stack-secrets/postgres-password`，构建 Ubuntu WAF 镜像，拉取官方 `postgres:18-alpine`，先等待数据库健康，再启动应用。数据库与 WAF 表结构自动初始化，无需手动执行 CREATE DATABASE。首次构建和拉取需要镜像仓库及依赖网络可用。

管理入口仍为 `http://管理IP:8301`，业务 HTTP 为 8300，可选 HTTPS 默认 8443。管理口未初始化时保留本机管理入口。网卡访问及权限继承 `compose.yaml`，支持物理网卡别名绑定、旁挂及串联。

也可在启动脚本完成目录和密码准备后直接运行：

```bash
docker compose -f compose.stack.yaml up -d --build
```

## 网络及持久化

| 项目 | 配置 |
| --- | --- |
| Compose 项目名 | `qionghai-waf-stack` |
| 应用运行文件 | 宿主机 `runtime-stack/` → 容器 `/app/runtime/` |
| 数据库数据 | Docker 命名卷 `qionghai-waf-stack_postgres_data` |
| 数据库监听 | 宿主机 `127.0.0.1:55432`，不向局域网开放 |
| 数据库名称 / 用户 | `waf` / `wafuser` |
| 数据库密码 | `.stack-secrets/postgres-password`，通过 Compose secret 挂载 |
| 初始化网卡 | 与现有部署相同的 `mgrnic.ini` |

WAF 使用 host 网络，不能依赖 Compose 服务名 `database` 访问数据库，因此连接本机 55432。数据库容器使用独立 Docker 网络，通过仅本机发布端口连接。管理账号、证书等不写入镜像；密码不直接写入 YAML 或容器的配置环境变量。

如 55432 已占用，在项目 `.env` 中设置 `WAF_STACK_DB_PORT=55433`，再使用同一环境重建两个服务。可用 `WAF_POSTGRES_IMAGE` 指定兼容的 PostgreSQL 18 镜像，使用 `WAF_UBUNTU_IMAGE` 指定可访问的 Ubuntu 基础镜像。不要在已有数据卷上直接切换 PostgreSQL 大版本。

数据库服务的官方初始化账号 `wafuser` 具有集群管理权限；该数据库实例专用于本 WAF，不用于共享其他业务数据库。需要权限隔离时应使用独立管理员建立受限应用账号并按数据库迁移说明配置。

## 日常启动与停止

```bash
# 后续启动，不重新构建
docker compose -f compose.stack.yaml up -d
# 更新应用镜像
docker compose -f compose.stack.yaml up -d --build
# 日志
docker compose -f compose.stack.yaml logs --tail=100 waf database
# 正常停止；数据卷保留
docker compose -f compose.stack.yaml down
```

不要执行 `down -v`，该参数会删除数据库卷。备份数据库、`runtime-stack/`、`.stack-secrets/`、`mgrnic.ini` 和部署参数。数据库导出示例：

```bash
umask 077
docker compose -f compose.stack.yaml exec -T database pg_dump -U wafuser -d waf -Fc > waf-backup.dump
```

不要修改或删除密码文件来“重置密码”：官方数据库只在空卷第一次初始化时设置密码，改文件不会修改已有数据库密码。已有卷但密码丢失时启动脚本会拒绝重新生成，需从备份恢复或按 PostgreSQL 管理流程同时变更数据库和密码文件。

## 与当前生产部署的关系

当前 `192.168.17.126` 应用仍使用 `192.168.17.127` 的外部 PostgreSQL。本配置提供新的应用＋数据库启动方式，不会自动复制当前生产数据库或替换其连接。

两个应用使用相同管理及业务端口，不能在同一主机同时启动。切换部署方式必须先备份并停止旧应用，迁移数据及证书后再启动新方式，验证记录数量、网卡和业务；不能把全新本地数据库当作已经迁移的生产库。现有自动发布脚本针对默认生产 Compose 项目，若正式改用 stack，需同时调整发布目标后再使用自动发布。

排查时先确认 `database` 为 healthy，再查看 `waf` 日志。数据库健康不等于网卡初始化成功，旁挂及串联仍需有效的物理业务口绑定。
