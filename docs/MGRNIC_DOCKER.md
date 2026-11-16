# mgrnic.ini 管理口与业务口加载

Ubuntu Docker 使用 `network_mode: host`，管理口与业务口共享宿主机网络命名空间。容器内直接看到实际网卡名称、MAC 和接口索引，`NET_ADMIN` / `NET_RAW` 允许网口启用、桥接及报文采集。无需 `/dev` 设备映射、Docker socket 或 `privileged`。这是宿主机网卡直接访问，不是将 PCI 设备独占分配给容器；宿主机仍可看见这些网卡。

示例（接口名须改成实际环境，可改用 MAC）：

```ini
[management]
alias = mgmt0
interface = ens33
ip = 192.168.1.1/24
nic_count = 3
apply_ip = true

[business:port1]
interface = ens34
bring_up = true

[business:port2]
mac = 00:11:22:33:44:55
bring_up = true
```

每个节的 `interface`、`physical_id`、`mac` 三种选择方式只填一种，MAC 支持冒号或短横线。`[business:port1]` 的 `port1` 是系统业务别名，实际调用时根据绑定的物理标识解析当前接口名称。建议按 MAC 绑定，以适应 Ubuntu 接口重命名。选择项全部留空时不会绑定、启用或猜测网卡。

`nic_count` 包含一个管理口和全部业务口，范围 1～32。首次初始化按业务节创建别名，未列出的剩余业务口自动命名为 portN。已有系统不因修改管理节而重置管理 IP、业务模式或网卡总数量；如需新增别名，先在“系统配置 → 网卡配置”添加对应业务行，再填写相同业务别名。

管理口首次导入成功后保持原有的一次性初始化语义。业务口独立初始化，因此已经完成管理口初始化的系统，也可以增加业务节后重启加载。业务配置会先整体校验，再原子写入数据库，避免只绑定一部分。禁止同一物理口重复绑定、与管理口共用，以及选择带 IPv4 或全局 IPv6 的业务口。业务口不分配 IP，不删除地址或修改默认路由。

`bring_up=true` 在加载时启用业务物理口，要求 Ubuntu / Linux 和 NET_ADMIN。`false` 仅保存别名绑定，适用于配置检查。后续启动会恢复已保存绑定的启用状态；接口重命名后仍按物理标识解析。页面修改过业务绑定后，相同 INI 不会覆盖页面修改；只有显式修改业务选择项后才重新导入。删除节或清空选择项不自动解绑，要解绑请在页面操作。

保存宿主机 `/opt/waf/mgrnic.ini` 后执行：

```bash
cd /opt/waf
docker compose restart waf
docker compose logs --tail=100 waf
docker compose exec waf ip -j address show
```

如果编辑器以替换文件的方式保存 INI，应运行 `docker compose up -d --force-recreate waf`，确保只读 bind mount 指向新文件。也可在容器中执行 `python -m waf.cli init-network` 重新导入；业务初始化失败时返回非零状态。

“系统配置 → 运行状态”会显示业务口加载状态和错误，网卡绑定列表显示逻辑别名及实际网卡。旁挂模式仍需选择镜像口、串联模式需选择两个不同业务口；配置文件不自动改变部署模式。已选择旁挂/串联的系统会按保存的业务绑定启动数据平面。

当前 192.168.17.126 仅有 ens33 管理网卡，Docker 内外已确认可见同一接口。部署模板的业务选择项保持为空；需给 Ubuntu 主机增加独立业务网卡后，按实际名称或 MAC 填写。镜像旁挂至少需 1 个业务口，透明串联至少需 2 个业务口。
