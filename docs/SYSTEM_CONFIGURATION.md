# 平台与数据库配置

登录管理页面，进入「系统配置」，选择对应功能页签。

数据库配置页提供「数据初始化」按钮：填写或选择 SQLite/PQ 连接后点击，即在所选数据库创建缺失的 WAF 表、索引和默认防护配置。已有站点配置及审计记录保留，可重复执行。SQLite 文件不存在时自动创建；PostgreSQL 的数据库本身须由管理员先创建，连接账号须具备建表及读写权限。初始化不复制历史数据、不清空数据库、不自动启用待生效连接；需要保留原系统数据时仍使用停服迁移流程。管理员登录凭据与 TLS 私钥保存在 runtime，不由数据库初始化重置。
系统配置分为「平台配置」「数据库配置」「日志配置」「网卡配置」「运行状态」「部署说明」六个 Sheet 页签，每次仅显示当前功能。平台名称和主机名在平台配置页签，连接及数据库运行参数在数据库配置页签，各自保存。切换页签保留未保存的输入，不自动提交；键盘左右方向键、Home、End 可切换页签。日志转发见 [日志配置说明](LOG_FORWARDING.md)，完整操作见 [使用手册](USER_GUIDE.md)。

数据库类型使用下拉菜单：**SQLite**、**PostgreSQL（PQ）**。选择 SQLite 显示文件位置，选择 PQ 显示主机、端口、数据库名、用户名、密码与 TLS 模式。密码不回显，留空保留同一连接已保存的密码，可勾选显示本次输入的密码。使用「测试所选连接」验证参数，再点击「保存数据库配置」。保存成功后标记“待生效”，当前服务仍使用原数据库，可取消待生效配置。

勾选「显示密码（含已保存密码）」可查看当前连接已保存的密码；未保存的密码也可切换显示。取消勾选后，已读取的密码会从输入框清空。查看已保存密码需要管理员登录与同源请求，并记录 `DATABASE_PASSWORD_VIEW` 审计，不记录密码内容。普通配置查询仍不返回密码。

切换前备份数据库和 runtime，在 Ubuntu `/opt/waf` 执行：

```bash
docker compose stop waf
docker compose run --rm --no-deps --entrypoint python waf -m waf.switch_database
docker compose up -d --no-build --pull never waf
```

迁移命令读取 `runtime/database.pending.env`，支持 SQLite → PQ、PQ → SQLite、同类型空库迁移；逐表核对记录与 SHA256，成功后才原子替换正式连接配置。源数据库保留不删除，目标已有业务数据会拒绝覆盖，失败时保留待生效配置及原正式连接配置。迁移失败可重新启动原服务；切换后的新增数据不会自动同步回旧库。仅修改同一 PostgreSQL 实例和库的连接参数时校验后更新连接，无需复制数据。此流程用于单台 WAF 部署，外部其他写入方也须同时停写。

- 平台名称：1～60 个字符，保存即更新侧栏、浏览器标题和页脚，刷新后保留。
- 设备主机名：1～63 个小写字母、数字、中划线，不能以中划线开头或结尾。这是 Docker 容器的主机名，不修改 Ubuntu 宿主机名称。保存后，在 Ubuntu `/opt/waf` 执行 `bash start.sh`；脚本从持久化数据库读取主机名并重建容器。仅 `docker compose restart` 不会更新容器主机名。后续启动继续使用 `bash start.sh` 保留此配置。
- 数据库：支持 SQLite 和 PostgreSQL。页面显示实际数据库类型、位置、大小和读写测试结果，不返回数据库密码。数据库配置文件为 `/opt/waf/runtime/database.env`，权限应为 600。此配置文件优先于环境变量；未配置时继续使用原 SQLite 数据库。
- 连接等待时间：1～120 秒，数据库忙时等待的上限，默认 10 秒。
- WAL 自动检查点：100～100000 页，默认 1000 页；在所有服务的新数据库连接上生效。
- 测试数据库：测试已经保存的配置，执行读写后回滚，显示耗时、WAL 模式与实际参数；不会保留测试数据。

PostgreSQL 配置示例（密码替换为专用账号真实密码）：

```ini
WAF_DB_ENGINE=postgresql
WAF_DB_HOST=192.168.17.127
WAF_DB_PORT=5432
WAF_DB_NAME=waf
WAF_DB_USER=wafuser
WAF_DB_PASSWORD=REPLACE_WITH_SECRET
WAF_DB_SSLMODE=prefer
```

PostgreSQL 连接超时为 10 秒，平台中的连接等待时间用于 SQL 执行超时；WAL 检查点不适用 PostgreSQL。数据库不可用时服务报错，不会静默回退到 SQLite 产生两份数据。

SQLite 模式配置：`WAF_DB_ENGINE=sqlite` 与 `WAF_DATABASE=/app/runtime/waf.sqlite3`。切换数据库必须停服、备份并迁移，不能直接切换到空库。迁移工具 `python -m waf.migrate --sqlite-source /app/runtime/waf.sqlite3` 将 SQLite 所有配置、状态和审计事件导入配置文件指定的 PostgreSQL；目标已有业务数据时拒绝覆盖。逐表校验记录数量及内容 SHA256，一次事务提交，并修复事件自增序列。

本次部署：WAF 应用在 192.168.17.126，PostgreSQL 在 192.168.17.127:5432，数据库 waf，专用用户 wafuser。原 SQLite 文件保留作迁移前备份。迁移后恢复旧 SQLite 会丢失迁移后的新增数据，恢复前应先备份 PostgreSQL 并同步增量。

平台配置与网卡配置分别保存，修改平台名称或数据库参数不会触发网卡、桥接或管理 IP 变更。平台配置保存记录在访问审计的「配置变更」中。备份 SQLite 时使用 SQLite backup API 或停止服务后复制整个 runtime 目录，不要在运行中仅复制主数据库文件而遗漏 WAL。
