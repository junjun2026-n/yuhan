# 192.168.17.126 部署记录

部署日期：2026-10-27（Asia/Shanghai）。

| 项目 | 实际值 |
| --- | --- |
| Ubuntu 宿主机 | Ubuntu 22.04.5 LTS / amd64 |
| 容器基础系统 | Ubuntu 24.04，Canonical 最小 OCI rootfs |
| 项目目录 | `/opt/waf` |
| Compose 项目 | `qionghai-waf` |
| 容器 | `qionghai-waf-waf-1` |
| 应用镜像 | `qionghai-waf:ubuntu24.04` |
| 管理网卡 | `mgmt0` → `ens33` |
| 管理 IP | `192.168.17.126/24`，沿用已有地址 |
| 管理入口 | <http://192.168.17.126:8301> |
| 反向代理入口 | <http://192.168.17.126:8300> |
| 默认模式 | 反向代理；源站待用户配置 |
| 凭据 | `/opt/waf/runtime/initial-admin.txt`，实际认证配置 `/opt/waf/runtime/admin.env` |
| 数据库 | PostgreSQL `192.168.17.127:5432/waf`，专用账号 `wafuser` |
| 数据库连接配置 | `/opt/waf/runtime/database.env`（权限 600） |
| 原 SQLite 备份 | `/opt/waf/runtime/pre-postgresql-*.sqlite3` |

未更改宿主机原有 IP、默认路由及 SSH 入口。由于当前只有一块实际网卡，`port1`、`port2` 留待添加硬件后绑定，不启用旁挂 / 串联。
反向代理正常业务地址未配置时返回 503；先登录管理页面，在站点配置中填写真实源站。

## 基础镜像来源

宿主机无法直连 Docker Hub，改用 Canonical 官方 OCI 根文件系统：

`https://partner-images.canonical.com/oci/noble/current/ubuntu-noble-oci-amd64-root.tar.gz`

下载时 SHA256：`e761e032a180489a564c3806a439222b0406f6c2b0eb03fcd1bad337e199a7fa`。
官方 SHA256SUMS.gpg 使用 ubuntu-cloudimage-keyring 验证成功，签名者 UEC Image Automatic Signing Key，指纹 `D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`。
导入的本地基础镜像标签为 `waf-ubuntu-base:24.04`，项目 `.env` 通过 WAF_UBUNTU_IMAGE 指定它。
校验文件和来源记录在 `/opt/waf/packages`，后续重建可直接复用此本地基础镜像。

## 启停与维护

```bash
cd /opt/waf
sudo docker compose ps
sudo docker compose logs --tail=100 waf
sudo docker compose restart waf
sudo docker compose stop waf
sudo docker compose up -d --no-build --pull never waf
sudo cat runtime/initial-admin.txt
```

Docker 已启用 unless-stopped 重启策略。管理员主动停止后，需要手动再次启动。

## 离线包

- 应用镜像：`/opt/waf/packages/qionghai-waf-ubuntu24.04.tar.gz`
- 部署文件：`/opt/waf/packages/waf-deploy-files.tar.gz`
- 校验文件：`/opt/waf/packages/WAF-SHA256SUMS`
- 应用镜像 ID：`/opt/waf/packages/WAF-IMAGE-ID`

这些包不含数据库、管理员密码及运行状态，首次在其他机器启动时会重新初始化。
部署文件中的 mgrnic.ini 针对本服务器，换机器应先改管理网卡名称和 IP。

## 已验证项目

- Ubuntu 镜像构建成功，容器为 healthy。
- mgrnic.ini 初始化完成，管理口与 localhost 备用管理入口正常监听。
- 未认证访问返回 401，认证后管理 API / 页面正常。
- 使用临时本机源站验证了完整 HTTP 代理转发，测试结束后恢复空源站配置。
- SQLi 测试返回 403。
- 物理旁挂和串联仍需增加独立业务网卡后验证，不据此次部署声称已通过。
