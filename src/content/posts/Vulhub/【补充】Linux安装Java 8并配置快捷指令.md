---
title: 【补充】Linux安装Java 8并配置快捷指令
published: 2026-10-22T10:00:00+08:00
description: 解决老旧安全工具与靶场环境的兼容性难题。详细记录在 Kali Linux 下通过镜像站下载并安装 OpenJDK 8 的步骤，并通过自定义脚本实现 java8 快捷指令，实现多版本 Java 完美共存，不影响系统默认环境。
image: images/Pasted image 20261022170938.png
tags:
  - Java
  - 环境搭建
  - Linux
  - 技巧
category: Vulhub靶场
draft: false
pinned: false
lang: zh-CN
author: Ynm
comment: true
---
在最近的漏洞复现时发现，之前用过的很多安全工具（比如 ysoserial、JNDIExploit、shiro_attack 等）都需要依赖 Java 8 环境才能正常运行。但目前的 Kali 系统默认是 Java 25，直接运行这些工具常常会遇到模块访问限制或找不到类的报错。为了省去反复折腾环境的时间，我决定直接在 Kali 本地安装一个独立的 Java 8，并把它配置成 `java8` 的快捷指令，这样既方便随时调用，又不会影响系统原本的默认环境。

在 Linux 中，要想实现类似 `python2` 或 `python3` 这样直接输入特定命令就能运行对应版本，最简单有效的方法是**创建一个自定义的 Bash 脚本**，把它放到系统的环境变量目录下。

### 1. 从华为云镜像站下载Java 8
```text wrap
cd /opt
sudo wget https://repo.huaweicloud.com/java/jdk/8u202-b08/jdk-8u202-linux-x64.tar.gz
sudo tar -zxvf jdk-8u202-linux-x64.tar.gz
sudo mv jdk1.8.0_202 jdk8
```
此时Java 8的路径应该是 `/opt/jdk8`。  

### 2. 创建 `java 8` 快捷指令

我们将创建一个脚本放到 `/usr/local/bin/` 目录下（这个目录默认在系统的 `PATH` 变量中，放进去后全局可用）。

在 Kali 终端执行以下命令：

```text wrap
# 1. 创建名为 java8 的脚本
sudo tee /usr/local/bin/java8 > /dev/null << 'EOF'
#!/bin/bash
# 临时指定 JAVA_HOME 和 PATH，然后执行 java 命令
export JAVA_HOME=/opt/jdk8
export PATH=$JAVA_HOME/bin:$PATH
exec java "$@"
EOF

# 2. 赋予脚本可执行权限
sudo chmod +x /usr/local/bin/java8
```

**如何使用：**

现在，无论在哪个目录，直接输入：
```text wrap
java8 -version
```
输出就会显示 `openjdk version "1.8.0_202"`。要运行工具时，只需：
```text wrap
java8 -jar 某某.jar
```
![](images/Pasted%20image%2020261022171130.png)