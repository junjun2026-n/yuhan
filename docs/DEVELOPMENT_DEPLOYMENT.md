# 本地开发与 Docker 更新

本地项目保留在 `C:\20260501\qionghai\WAF`，Python 虚拟环境为项目内 `.venv`。服务器正式环境位于 `192.168.17.126:/opt/waf`，PostgreSQL 位于 `192.168.17.127:5432/waf`。

## 本地开发

首次安装或更新依赖：

```powershell
cd C:\20260501\qionghai\WAF
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-deploy.txt
.\start-dev.ps1
```

开发管理页面：`http://127.0.0.1:8401`；开发代理：`http://127.0.0.1:8400`。账号和初始密码在 `runtime/dev/initial-admin.txt`，当前数据库为 PostgreSQL `192.168.17.127:5432/waf_dev`，私有连接配置位于 `runtime/dev/database.postgresql.env`。开发进程在前台运行，Ctrl+C 停止。也可直接执行 `.\.venv\Scripts\python.exe -m tools.dev`。

开发入口要求提前配置独立 PostgreSQL 开发库；缺少配置会拒绝启动，不会回退 SQLite。独立管理密码及 TLS 目录，不读取生产连接文件，不自动修改本机管理网卡 IP，不启动镜像/串联数据平面。原来的 `start.ps1` 使用标准端口 8300/8301，本地 PostgreSQL 库为 `waf_local`，既有服务器库 `waf` 保留。

## 验证、上传和更新

```powershell
# 运行测试并生成源码包，仅准备，不连接服务器
.\deploy.ps1 -PrepareOnly

# 测试、打包、上传、备份、构建并更新 Docker
.\deploy.ps1
```

默认更新 `192.168.17.126`，SSH 用户 `jun`，部署目录固定 `/opt/waf`。SSH/sudo 密码在终端隐藏输入，不写入源码或发布包。自动化可使用进程环境变量 `WAF_REMOTE_PASSWORD`，使用后删除。主机密钥从系统 SSH known_hosts 与 `runtime/remote-known-hosts` 加载，未知或已变化的密钥会拒绝连接；首次部署到其他主机需要先核对并保存 SSH 主机密钥。

部署脚本默认执行独立 SQLite 回归测试；真实 PostgreSQL 测试可另外显式设置 `WAF_TEST_POSTGRES_CONFIG` 后执行 pytest。发布源码白名单排除 `.env`、runtime、虚拟环境、本地数据库和 `mgrnic.ini`，因此不会把开发数据、密码、证书或网卡配置覆盖到生产。

部署流程：

1. 本地运行测试，生成源码包及 SHA256；发布记录保存在 `packages/releases/<UTC版本号>/`。
2. 上传后验证校验和，获取部署锁，防止同时更新。
3. 备份服务器旧代码、运行配置及当前数据库的一致性逻辑快照，保存旧镜像标签。
4. 使用服务器既有 Ubuntu 基础镜像构建 WAF，构建成功后只重建 WAF 容器，保留当前容器主机名。
5. 等待 Docker 健康状态，并执行应用健康检查。构建/启动/检查失败时恢复旧代码和旧镜像；数据库不会自动回退，避免覆盖新增数据。
6. 更新离线 Docker 镜像包、部署文件包及 SHA256，并保留本地部署日志。

服务器备份目录：`/opt/waf/runtime/deployment-backups/<版本号>/`；其中 `database.json` 为应用表的一致性逻辑快照，`runtime-config.tar.gz` 含账号、数据库连接及证书，权限受限，应安全保管。外部数据库还应保留 PostgreSQL 自身的定期备份。旧代码/镜像回滚适用于数据库结构兼容的更新；未来破坏性数据库变更需要专项迁移与回滚方案。

离线文件：`/opt/waf/packages/qionghai-waf-ubuntu24.04.tar.gz`、`waf-deploy-files.tar.gz` 和 `WAF-SHA256SUMS`。每次正式更新会重新生成。镜像构建使用服务器 `.env` 中现有 `WAF_UBUNTU_IMAGE`，不强制重新拉取 Docker Hub 基础镜像。
