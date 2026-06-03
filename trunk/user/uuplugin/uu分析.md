# UU加速器 路由器插件 v12.2.10 MIPSEL 二进制程序分析报告

> 二进制文件: `uuplugin` | 版本：v12.2.10 | 架构: MIPS32 LE | 编译: 2026-04-28 | C库: musl libc

---

## 目录

1. [基本信息](#基本信息)
2. [设备名/主机名检测机制](#设备名主机名检测机制)
3. [设备类型识别引擎（Xbox/PS/Switch/PC/安卓/iOS）](#设备类型识别引擎)
4. [启动流程](#启动流程)
5. [完整协议消息类型](#完整协议消息类型)
6. [联网状态检测](#联网状态检测)
7. [自动退出机制](#自动退出机制)
8. [HTTP API 端点](#http-api-端点)
9. [文件读写清单](#文件读写清单)
10. [程序架构](#程序架构)
11. [环境路径依赖](#环境路径依赖)
12. [已知限制](#已知限制)

---

## 基本信息

| 项目 | 内容 |
|------|------|
| 文件 | `uuplugin` |
| 版本 | v12.2.10 |
| 编译时间 | 2026-04-28 15:32:27 |
| 架构 | MIPS32 little-endian, statically linked, stripped |
| C库 | musl libc |
| 源码路径 | `/home/gaoliang02/tun2proxy/` (tun2proxy 项目) |
| 构建者 | gaoliang02 (主), cbyn2993 (OpenSSL) |
| 网络库 | libev (事件循环) |
| SSL/TLS | OpenSSL 1.1.1b |
| 序列化 | Protocol Buffers (protobuf) |
| 协议定义 | `uu_router_messages.proto` |

---

## 设备名/主机名检测机制

四级检测链逐级回退:

### 第1级: 环境变量（主来源）

由路由器固件启动脚本预先设置:

| 环境变量 | 用途 |
|---------|------|
| `UU_VENDOR` | 厂商名 |
| `UU_MODEL` | 设备型号 |
| `UU_SN` | 序列号 |
| `UU_DEVICE_MAC` | MAC地址 |
| `UU_DEVICE_TYPE` | 设备类型 |
| `UU_FIRMWARE_VERSION` | 固件版本 |
| `UU_LAN_IP` | LAN IP |
| `UU_WAN_IP` | WAN IP |
| `UU_DEVICE_LINK_TYPE` | 连接类型 |
| `UU_TUN_IP` | TUN配置IP |
| `UU_TUN_NAME` | TUN接口名 |
| `UU_RANDOM` | 随机种子 |

### 第2级: 文件读取（后备）

- `/var/model` — 设备型号
- DHCP租约文件（解析 client-hostname）:
  - `/etc/config/dhcpd.leases` (OpenWrt路径)
  - `/tmp/dhcp.leases`
  - `/tmp/var/lib/misc/dnsmasq.leases`
- `/tmp/uu/uu_stack_config` — 堆栈配置
- `/tmp/uu/activate_status` — 激活状态

### 第3级: 命令执行

- `whoami` → 输出到 `/tmp/.uu_whoami.txt`
- `cat /proc/hw_nat` → 硬件NAT检测
- `nvram show | grep ctf_disable` → CTF状态检测
- iptables/nftables → 防火墙规则配置

### 第4级: 默认值

全部失败 → 显示 `"Unknown"` (字符串地址 0x0080dc38)

---

## 设备类型识别引擎

UU插件通过六层引擎并行检测局域网内设备类型（Xbox、PS4/5、Switch、PC、Android、iOS）。

### 全局数据流

```
设备(手机/电脑/游戏机)接入路由器
          │
          ▼
┌─────────────────────────────────────────────┐
│          六层识别引擎并行检测                   │
│                                              │
│  ① DHCP探针 ← 最先触发（设备获取IP时）          │
│  ② MAC OUI  ← 每台设备都有MAC地址              │
│  ③ mDNS     ← Apple/PS4/Switch设备会广播       │
│  ④ HTTP UA  ← 设备访问网络时可见                │
│  ⑤ DNS查询  ← 设备查询特定域名                  │
│  ⑥ 专用探针 ← Xbox/PS4/Switch专项探测           │
│                                              │
└──────────────────┬──────────────────────────┘
                   ▼
           类型决策引擎
                   │
        ┌──────────┼──────────┐
        ▼          ▼          ▼
    console_series  type   device_whitelist
    (系列分组)    (具体型号)  (MAC+类型绑定)
```

### ① DHCP探针（最优先）— `dhcp_record.cpp`

设备连路由器获取IP时，DHCP请求中包含丰富的识别信息:

| DHCP字段 | 用途 | 实际值举例 |
|----------|------|-----------|
| **Option 60** Vendor ID | 厂商身份 | `MSFT` = Xbox, `Android` = 安卓, `Apple` = 苹果 |
| **Option 12** Host Name | 设备主机名 | 包含 `Nintendo`、`Xbox`、`PS4` 等关键词 |
| **Option 55** Parameter List | 请求参数列表 | 不同设备请求不同参数组合（指纹特征） |
| **TTL初始值** | TTL | Windows/Mac默认TTL不同 |

关键变量:
- `dhcp_vendor_id` — Option 60 的厂商ID
- `dhcp_hostname` — Option 12 的主机名
- `dhcp_vendor_filter` / `dhcp_hostname_filter` — 黑白名单过滤
- `android_dhcp_vendorid_kw` — Android的DHCP厂商ID匹配关键词

```
逻辑示意:
if (dhcp_vendor_id == "MSFT")    → type = "xbox" / "windows"
if (dhcp_hostname 含有 "Nintendo") → type = "switch"
if (dhcp_vendor_id == "Android") → type = "android"
if (dhcp_vendor_id == "Apple")   → type = "apple"
```

### ② MAC OUI查询

读取 `/jffs/oui_sample.txt` OUI数据库，通过MAC地址前3字节识别厂商:

| MAC前缀 | 厂商 |
|---------|------|
| `00:50:F2` | Microsoft (Xbox) |
| `00:26:5B` | Nintendo (Switch) |
| `00:04:4B` | Sony (PlayStation) |
| `8C:85:90` | Apple |
| `04:CB:88` | Samsung |

### ③ mDNS探针 — `mdns.cpp` / `mdns_task.cpp`

设备通过mDNS广播服务类型:

| mDNS服务类型 | 设备类型 |
|-------------|---------|
| `_apple-mobdev._tcp` / `_airplay._tcp` | Apple (iPhone/iPad) |
| `_ps4._tcp` / `_ps5._tcp` | PlayStation 4/5 |
| `_xbox._tcp` | Xbox |
| `_nintendo._tcp` | Nintendo Switch |
| `_googlecast._tcp` | Android/Chromecast |

关键函数: `mdns_service_contain()` — 模糊匹配mDNS服务类型

### ④ HTTP User-Agent检测

```
Mozilla/5.0 ... Windows NT 10.0  → type = "windows"
Mozilla/5.0 ... Android 12       → type = "android"
Mozilla/5.0 ... iPhone           → type = "iPhone"
Mozilla/5.0 ... iPad             → type = "iPad"
Mozilla/5.0 ... Linux            → type = "linux"
```

### ⑤ DNS查询模式

不同设备查询特定域名:
- Nintendo Switch → `*.nintendo.net`
- Xbox → `*.xboxlive.com`
- PlayStation → `*.playstation.net`
- Android → `*.googleapis.com`

### ⑥ 专用探针

| 探针 | 源文件 | 方法 |
|------|--------|------|
| **Xbox探针** | `xbox_probe.cpp` | `xb-probe` / `xb-type-` 标记 |
| **PS4探针** | `ps4_probe.cpp` | 端口扫描+服务发现 |
| **Switch探针** | `switch_probe.cpp` | DHCP+mDNS+MAC组合验证 |

### 完整设备类型映射

| 类型值 | 对应设备 |
|--------|---------|
| `xbox` / `xboxone` / `xbox360` / `xboxx` | Microsoft Xbox 系列 |
| `ps4` / `ps5` | Sony PlayStation 系列 |
| `switch` | Nintendo Switch |
| `windows` / `windows store` | Windows PC |
| `android` | Android 手机/平板 |
| `iphone` / `ipad` / `apple` | Apple 设备 |
| `linux` | Linux 设备 |
| `nintendo` | Nintendo 其他设备 |
| `mac` | Mac电脑 |

### 类型的实际用途

1. **设备白名单** `DeviceRecord { mac, type }` — 记录允许加速的设备
2. **控制台分组** `console_series` — 同系列设备归组
3. **加速策略**:
   - console 类型 → 主机加速模式（UDP加速+KCP）
   - PC/手机类型 → TCP代理模式
   - 未识别 → 记录 `other_device_block_reason`

---

## 启动流程

```
1. 入口 main() @ 0x407e40
   ├── 解析命令行参数 (argv[1])
   │   ├── "v12.2.10" -> 直接打印版本退出
   │   └── 其他 -> 进入初始化 @ 0x46e140
   │
   ├── 2. 初始化阶段 @ 0x46e140
   │   ├── 加载配置项列表
   │   │   ├── log_level
   │   │   ├── version
   │   │   ├── uu_stack_config
   │   │   ├── uu_stack_config_result
   │   │   ├── uu_status
   │   │   ├── latency_monitor
   │   │   ├── router_vendor / router_model
   │   │   ├── device_type
   │   │   └── uu_plugin_version
   │   └── 每种配置设置默认值和类型标志
   │
   ├── 3. 读取 /etc/resolv.conf 获取DNS服务器
   │   ├── 默认: 223.5.5.5 (AliDNS)
   │   └── 备用: 8.8.8.8 (Google DNS)
   │
   ├── 4. 检查 /tmp/uu/uu_stack_config
   │   └── 不存在则报错但可能继续
   │
   ├── 5. 解析UU服务器域名
   │   ├── 自定义DNS解析器 (dns_resolver.cpp)
   │   │   ├── dns_new() ── 创建解析器
   │   │   ├── dns_init() ── 初始化DNS服务器地址
   │   │   └── dns_query() ── 发送UDP DNS查询
   │   ├── 后备: musl getaddrinfo()
   │   └── 目标: rglg.uu.163.com / rglg.uu.netease.com
   │
   ├── 6. 主连接 (main_link)
   │   ├── TCP连接到代理服务器
   │   ├── SSL/TLS握手 (OpenSSL 1.1.1b)
   │   ├── 登录认证 (send_login)
   │   │   └── 发送设备信息 + 账号凭证
   │   ├── 接收 OnlineReply (服务器列表)
   │   ├── CheckBound (检查设备绑定状态)
   │   └── 进入keepalive保活循环
   │
   └── 7. 进入libev主事件循环
       ├── HTTP服务器 (buildin_http_server)
       │   ├── GET /activate ── 激活页面
       │   ├── GET /json ── JSON状态API
       │   └── GET /conf/conf_api ── 配置API
       ├── DNS嗅探 (dns_sniffer)
       ├── 流量代理 (tun2proxy)
       └── 定时任务 (keepalive, flow_monitor, 延迟探测)
```

---

## 完整协议消息类型

| 消息 | 方向 | 用途 |
|------|------|------|
| **Online** / OnlineReply | C→S / S→C | 上线通知 / 服务器列表+状态 |
| **Acc** / AccReply | C→S / S→C | 启动加速 / 加速结果 |
| **CheckBound** / BoundUser | C→S / S→C | 设备绑定检查 |
| **Disconnect** / DisconnectReply | C→S / S→C | 断开连接 |
| **ServerPing** / ServerPingReply | C→S / S→C | 延迟探测 |
| **StopAccReply** | S→C | 停止加速确认 |
| **StopRtmpReply** | S→C | 停止RTMP确认 |
| **FenceModeLatency** / GamingServerLatency | C→S | 延迟上报 |
| **LogCtrl** | S→C | 日志级别控制 |
| **Device** | 内嵌 | 设备信息(型号、MAC、固件版本等) |
| **MacList** | C→S | MAC地址列表 |
| **UserMessage** | S→C | 用户消息推送 |
| **Uninstall** / **Upgrade** | S→C | 插件管理 |

### Connect 消息结构 (完整protobuf字段)

```
Connect {
    mid              (string)  ── 消息ID
    type             (string)  ── 设备类型 (xbox/ps4/switch/android/...)
    sn               (string)  ── 序列号
    version          (string)  ── 版本
    name             (string)  ── 设备名
    model            (string)  ── 型号
    firmware_version_code (uint32)
    firmware_version_name (string)
    ssid             (string)  ── 2.4G WiFi名
    device_type      (string)  ── 设备详细类型
    whoami           (string)  ── whoami输出
    mode_local       (string)  ── 本地模式
    plugin_type      (string)  ── 插件类型
    real_sn          (string)  ── 真实序列号
    firmware_type    (string)  ── 固件类型
    router_info      (string)  ── 路由器信息
    wan_ip           (uint32)  ── WAN IP
    wan_port_speed   (uint32)  ── WAN口速率
    debug_whoami_ip  (string)  ── 调试用IP
    ssid_5g          (string)  ── 5G WiFi名
}
```

---

## 联网状态检测

程序有三种独立的联网判定，全通过才认为在线:

### 检测1: WAN IP — `acc_ctl_wan_status.cpp`
- 检查 `UU_WAN_IP` 环境变量
- 检查内部 `wan_ip` 变量
- 无WAN IP → 未联网

### 检测2: 主链路连接 — `main_link.cpp`
```
IDLE ──> CONNECTING ──> CONNECTED ──> (keepalive) ──> DISCONNECTED
           │                │                              │
       TCP连接成功       login成功                     main link is down
           │                │                              │
       连接失败          Online发送                    重试超时→退出
```
- `main link started` → 连接成功
- `main link is down` → 判定离线
- `mainlink reconnect N/M` → 正在重试

### 检测3: 代理桥接状态
- `tcp bridge %u connected / not connected`
- `tproxy bridge %u connected / not connected`

### 综合判定
程序向UU服务器发送 `Online` 消息后，等待 `OnlineReply`。如果收不到回复或 `OnlineReply.Status` 不为成功，设备在服务器端显示离线。

---

## 自动退出机制

### 1. 服务器连接失败重试上限
```
mainlink reconnect 1/5 → 2/5 → ... → 5/5 → quit
```
- `mainlink reconnect times more max retry times %d, quit` @ 0x00834580
- 默认最大重试5次，间隔递增

### 2. 保活超时
- `mainlink reconnect keepalive timeout` @ 0x00834590
- 定期发送keepalive，收不到响应累计超时→断开→重试→最终退出

### 3. 登录失败
- `start master mainlink failed` @ 0x00834c49
- `[parse_packet] login failed, no result / no session id`
- 登录失败直接退出

### 4. SSL握手失败
- `mainlink_login: ssl handshake error, err = %d` @ 0x00834ff0
- SSL/TLS协商失败→重试→最终退出

### 5. 死循环检测 (deadloop)
- `uu.deadloop` 命令 @ 0x0080780c
- 主循环卡死超时触发

### 6. 堆栈配置不存在
- `%ld ERROR: "/tmp/uu/uu_stack_config" not exist` @ 0x00833b08
- 配置缺失可能阻止启动

---

## HTTP API 端点

内置HTTP服务器 (`buildin_http_server`):

| 路径 | 方法 | 用途 |
|------|------|------|
| `GET /` | GET | 管理页面入口（重定向） |
| `/activate` | GET/POST | 设备激活绑定 |
| `/json` | GET | 返回设备状态JSON |
| `/conf/conf_api` | GET/POST | 配置读写API |

### JSON状态API输出格式

```json
{
    "acced": true/false,
    "hostname": "...",
    "type": "xbox|ps4|switch|...",
    "uri": "",
    "redir_ip": "...",
    "redir_port": ...,
    "src_port": ...,
    "send": ...,
    "recv": ...,
    "duration": ...
}
```

---

## 文件读写清单

### 写入的文件（程序创建或修改）

| 文件路径 | 写入方式 | 内容/用途 |
|---------|---------|-----------|
| `/tmp/uu/uu_stack_config_result` | 程序写入 | 堆栈配置检测结果，反馈给上层脚本 |
| `/tmp/uu/activate_status` | 程序写入 | 在线状态: `wan_if=%s,wan_mtu=%d,path_mtu=%d` |
| `/tmp/.uu_whoami.txt` | `whoami > 文件` | whoami命令输出 |
| `/tmp/.uu.v6_neigh` | `ip -6 neigh show > 文件` | IPv6邻居表快照 |
| `/tmp/.uu.tmp.XXXXXX` | 程序创建 | 运行时临时文件 |
| `/tmp/uu/uu_crash_dump` | 信号处理器写入 | 崩溃时的寄存器/堆栈/版本信息 |
| `/tmp/xu_nft_create.txt` | 程序写入 | nftables规则创建脚本 |
| `/tmp/xu_nft_delete.txt` | 程序写入 | nftables规则删除脚本 |
| `/tmp/.dup_conntrack` | 程序写入 | 重复conntrack检测记录 |
| `/var/run/uuplugin.pid` | 程序写入 | PID锁文件，防止多开 |
| `/tmp/.uu_jd_tmpfile.txt` | 程序写入 | 京东云设备检测临时文件 |
| `{workdir}/.uu.db` | SQLite数据库 | **核心数据持久化文件** |
| `/tmp/uu/uu.tar.gz` | 程序下载写入 | 升级包文件 |

### .uu.db 数据库存储路径（依次尝试）

程序按顺序使用第一个存在的目录:
1. `/jffs/uu/.uu.db` — 华硕/梅林固件
2. `/jffs2/uu/.uu.db` — 备选
3. `/plugins/uu/.uu.db` — 小米等固件
4. `/var/tmp/plugmnt/uu/.uu.db` — 挂载分区
5. `/data/uu/.uu.db` — 部分国产固件

数据库内容（根据引用源码推断）:
- `dhcp_record.cpp` → DHCP设备记录（MAC+类型+主机名）
- `persist_device_record.cpp` → 设备白名单
- `nmp_client_list` → 网络映射客户端列表

### 读取的文件（只读输入）

| 文件路径 | 读取什么 |
|---------|---------|
| `/etc/resolv.conf` | DNS服务器地址 |
| `/tmp/uu/uu_stack_config` | 堆栈配置 |
| `/var/model` | 设备型号 |
| `/etc/config/dhcpd.leases` | DHCP租约（client-hostname） |
| `/tmp/dhcp.leases` | DHCP租约后备 |
| `/tmp/var/lib/misc/dnsmasq.leases` | dnsmasq租约后备 |
| `/jffs/oui_sample.txt` | MAC地址OUI厂商数据库 |
| `/jffs/nmp_client_list` | 持久化网络映射客户端列表 |
| `/tmp/nmp_client_list` | 运行时网络映射客户端列表 |
| `/proc/net/arp` | 系统ARP表 |
| `/proc/net/dev` | 网络设备统计 |
| `/proc/hw_nat` | 硬件NAT状态 |
| `/proc/sfe_rule/sfe_ip` | SFE快速转发规则 |
| `/proc/rtl865x/port_status` | Realtek交换机端口状态 |
| `/proc/rtl865x/arp` | Realtek硬件ARP |
| `/proc/wlan` | 无线信息 |
| `/sys/class/net/*/mtu` | 各接口MTU值 |
| `/etc/hosts` | hosts文件 |
| `/etc/TZ` / `/etc/localtime` | 时区 |
| `/dev/urandom` / `/dev/random` | 随机数 |
| `/dev/net/tun` | TUN设备 |

### 执行的外部命令

程序通过 `system()` / `popen()` 执行:

| 命令 | 用途 |
|------|------|
| `mkdir -p %s` | 创建目录（通常是 /tmp/uu/） |
| `rm -f %s` | 删除文件 |
| `whoami > /tmp/.uu_whoami.txt` | 获取当前用户名 |
| `ip -6 neigh show > /tmp/.uu.v6_neigh` | 获取IPv6邻居 |
| `ip addr add/del ...` | 配置TUN设备 |
| `ip route add/del ...` | 配置路由 |
| `ip rule add/del ...` | 配置策略路由 |
| `iptables -t nat -A/D ...` | 配置NAT规则 |
| `nft -f /tmp/xu_nft_create.txt` | 执行nftables规则 |
| `modprobe tun \|\| insmod tun` | 加载TUN模块 |
| `modprobe nfnetlink ...` | 加载conntrack模块 |
| `tar zxf ...` | 解压升级包 |
| `chmod u+x ...` | 加执行权限 |
| `cat /proc/hw_nat 2>/dev/null` | 检测硬件NAT |
| `nvram show \| grep ctf_disable` | CTF状态（华硕/博通） |

---

## 程序架构

### 源文件模块

| 模块 | 文件 | 功能 |
|------|------|------|
| **plugin_common/** | | 通用模块 |
| | `dns_resolver.cpp` | 自定义DNS解析器 |
| | `data_report.cpp` | 数据上报 |
| | `inner_pipe.cpp` | 内部管道通信 |
| | `ssl.cpp` | SSL/TLS封装 |
| **acc-client-common/** | | 加速客户端 |
| | `third_party/kcp/` | KCP协议（游戏UDP加速） |
| | `third_party/grp/` | GRP协议 |
| **https_proxy/** | | HTTPS代理 |
| | `https_proxy_libev/` | libev事件驱动实现 |
| **local_proxy/** | | 本地代理 |
| | `tun2proxy.cpp` | TUN设备入口 |
| | `dns_sniffer.cpp` | DNS嗅探 |
| | `mdns.cpp` / `mdns_task.cpp` | mDNS服务发现 |
| | `multipath_dns_manager.cpp` | 多路径DNS管理 |
| | `tproxy_bridge.cpp` | 透明代理桥接 |
| | `server_ping.cpp` | 服务器延迟探测 |
| | `latency_monitor.cpp` | 延迟监控 |
| | `acc_ctl.cpp` | 加速控制主模块 |
| | `acc_ctl_node_online.cpp` | 在线状态管理 |
| | `acc_ctl_wan_status.cpp` | WAN状态检测 |
| | `acc_ctl_timer_cb.h` | 定时器回调 |
| | `main_link.cpp` | 主连接管理 |
| | `buildin_http_server.cpp` | 内置HTTP服务器 |
| | `tcp_channel.cpp` | TCP通道管理 |
| | `signal_handle.cpp` | 信号处理 |
| **设备探针** | | |
| | `xbox_probe.cpp` | Xbox设备识别 |
| | `ps4_probe.cpp` | PlayStation 4/5识别 |
| | `switch_probe.cpp` | Nintendo Switch识别 |
| | `dhcp_record.cpp` | DHCP指纹记录 |
| | `persist_device_record.cpp` | 设备记录持久化 |

### 数据流全图

```
输入                                                     输出
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

UU_VENDOR (env)          ─┐
UU_MODEL (env)            │        ┌──────────────────┐
UU_SN (env)               │        │                  │    /tmp/uu/activate_status
UU_DEVICE_MAC (env)       ├───────►│    uuplugin      ├───► /tmp/.uu_whoami.txt
UU_WAN_IP (env)           │        │                  │    /tmp/.uu.v6_neigh
/etc/resolv.conf          │        │  读取环境变量      │    {workdir}/.uu.db
/var/model                │        │  解析配置文件      │    /var/run/uuplugin.pid
/jffs/oui_sample.txt      │        │  DHCP嗅探        │    /tmp/uu/uu_crash_dump
/proc/net/arp             │        │  ARP/MAC扫描      │    /tmp/xu_nft_create.txt
/etc/config/dhcpd.leases  │        │  mDNS监听        │    /tmp/uu/uu_stack_config_result
/sys/class/net/*          │        │  设备指纹识别      │
/dev/urandom              ─┘        │                  │
                                   │  输出:            │
                                   │  - 连接到UU服务器   │
                                   │  - 劫持DNS查询     │
                                   │  - 透明代理游戏流量  │
                                   │  - HTTP status API │
                                   └──────────────────┘
                                              │
                                              ▼
                                    UU加速器云端服务器
```

### 回调钩子

程序在关键生命周期点调用外部脚本:
- `before_acc_start` — 加速开始前
- `after_acc_start` — 加速开始后
- `after_acc_stop` — 加速停止后
- `on_login` — 登录成功
- `on_logout` — 登出
- `on_device_connect` — 设备连接
- `on_device_disconnect` — 设备断开

---

## 服务器域名

| 域名 | 用途 |
|------|------|
| `rglg.uu.netease.com` / `rglg.uu.163.com` | 登录认证服务器 |
| `devrglg.uu.163.com` | 开发环境服务器 |
| `gw.router.uu.163.com` | 网关服务器 |
| `log.uu.163.com` | 日志上报服务器 |

## 硬编码IP地址

| IP | 用途 |
|----|------|
| `223.5.5.5` | 默认DNS (AliDNS) |
| `8.8.8.8` | 备用DNS (Google) |
| `127.0.0.1` | 本地DNS |
| `224.0.0.251` | mDNS多播地址 |
| `255.255.255.255` | 广播地址 |

---

## 已知限制

1. **musl libc DNS 限制**
   - 不支持EDNS0（Extension Mechanisms for DNS）
   - 无TCP fallback（超过512字节的DNS响应会被丢弃）
   - 响应限制512字节

2. **固件环境依赖**
   - 依赖启动脚本设置 `UU_*` 环境变量

3. **内核依赖**
   - 需要 iptables/nftables 支持
   - 需要 TUN/TAP 驱动
   - 需要 netfilter conntrack

4. **联网检测机制**
   - "未联网"是三重检测结果（WAN_IP + main_link + tproxy bridge）
   - 实际检测的是到UU服务器的连接，不是本地网络

5. **SSL/TLS**
   - OpenSSL 1.1.1b
   - 依赖系统时间正确（证书验证）
   - 依赖 `/dev/urandom` 可用
