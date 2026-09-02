---
title: NAT 实验
published: 2026-09-03T09:00:00+08:00
description: 通过配置 NAPT、EASY IP 与 NAT Server，实现私网访问互联网及 FTP 服务公网发布，验证地址转换与端口映射。
tags:
  - 新华三
  - H3CNE
category: H3CNE-RS+
draft: false
pinned: false
lang: zh-CN
author: Ynm
comment: true
---


### 实验拓扑

![](http://img.dengfm.com/15224115283885.jpg)

  

图 1-1

> 注：如无特别说明，同一网段中，IP 地址的主机位为其设备编号，如 R3 的 g0/0 接口若在 `192.168.1.0/24` 网段，则其 IP 地址为 `192.168.1.3/24`，以此类推。此拓扑中 FTPA，PCA，PCB 使用路由器来模拟

---

## 实验需求

1. 按照图示配置 IP 地址
2. 私网 A 通过 R1 接入到互联网，私网 B 通过 R3 接入到互联网
3. 私网 A 内部存在 Vlan10 和 Vlan20，通过 R1 上单臂路由访问外部网络
4. 私网 A 通过 NAPT 使 Vlan10 和 Vlan20 都能够使用 R1 的公网地址访问互联网
5. 私网 B 通过在 R3 上配置 EASY IP 访问互联网
6. 私网 A 配置 NAT SERVER 把 FTPA 的 FTP 服务发布到公网，使 PCB 可以访问

---

### 实验解法

1. **配置 IP 地址部分略**
    
2. **R1 和 R3 上配置默认路由指向公网，配置步骤略**
    
3. **私网 A 内部单臂路由配置部分略**
    
4. **私网 A 通过 NAPT 使 Vlan10 和 Vlan20 都能够使用 R1 的公网地址访问互联网**
    
    　　_分析：根据需求得知，ACL 需要配置允许 `192.168.1.0/24` 和 `192.168.2.0/24` 网段；私网 A 只有 1 个公网地址可用，意味着创建的 NAT 地址池起始和结束地址就都是 `100.1.1.1`_
    
    _步骤 1：R1 上创建基本 ACL，允许 `192.168.1.0/24` 和 `192.168.2.0/24` 网段_
    
    ```
    [R1]acl basic 2000
    [R1-acl-ipv4-basic-2000]rule permit source 192.168.1.0 0.0.0.255
    [R1-acl-ipv4-basic-2000]rule permit source 192.168.2.0 0.0.0.255
    ```
    
    _步骤 2：R1 上创建 NAT 地址池，设置公网地址_
    
    ```
    [R1]nat address-group 1
    [R1-address-group-1]address 100.1.1.1 100.1.1.1
    ```
    
    _步骤 3：在 R1 的公网接口上配置 NAPT_
    
    ```
    [R1]interface g0/1
    [R1-GigabitEthernet0/1]nat outbound 2000 address-group 1 
    ```
    
    _步骤 4：在 PCA 上 Ping R3 的公网地址，测试是否可以访问互联网_
    
    ```
    <PCA>ping 100.2.2.3
    Ping 100.2.2.3 (192.168.2.10): 56 data bytes, press CTRL_C to break
    56 bytes from 100.2.2.3: icmp_seq=0 ttl=254 time=22.000 ms
    56 bytes from 100.2.2.3: icmp_seq=1 ttl=254 time=51.000 ms
    56 bytes from 100.2.2.3: icmp_seq=2 ttl=254 time=21.000 ms
    56 bytes from 100.2.2.3: icmp_seq=3 ttl=254 time=43.000 ms
    56 bytes from 100.2.2.3: icmp_seq=4 ttl=254 time=34.000 ms
    ```
    
5. **私网 B 通过在 R3 上配置 EASY IP 访问互联网**
    
    　　_分析：根据需求得知，ACL 需要配置允许 `192.168.1.0/24` 网段；使用 EASY IP，就无需配置 NAT 地址池，直接在公网接口上配置即可，EASY IP 会自动识别公网接口的 IP 地址_
    
    _步骤 1：R3 上创建基本 ACL，允许 `192.168.1.0/24` 网段_
    
    ```
    [R3]acl basic 2000
    [R3-acl-ipv4-basic-2000]rule permit source 192.168.1.0 0.0.0.255
    ```
    
    _步骤 2：在 R3 的公网接口上配置 EASY IP_
    
    ```
    [R3]interface g0/0
    [R3-GigabitEthernet0/0]nat outbound 2000
    ```
    
    _步骤 4：在 PCB 上 Ping R1 的公网地址，测试是否可以访问互联网_
    
    ```
    <PCB>ping 100.1.1.1
    Ping 100.1.1.1 (192.168.1.10): 56 data bytes, press CTRL_C to break
    56 bytes from 100.1.1.1: icmp_seq=0 ttl=254 time=32.000 ms
    56 bytes from 100.1.1.1: icmp_seq=1 ttl=254 time=29.000 ms
    56 bytes from 100.1.1.1: icmp_seq=2 ttl=254 time=41.000 ms
    56 bytes from 100.1.1.1: icmp_seq=3 ttl=254 time=33.000 ms
    56 bytes from 100.1.1.1: icmp_seq=4 ttl=254 time=34.000 ms
    ```
    
6. **私网 A 配置 NAT SERVER 把 FTPA 的 FTP 服务发布到公网，使 PCB 可以访问**
    
    　　_分析：根据需求得知，需要发布 FTPA 的 FTP 服务，也就是把 R1 的公网地址的 20 和 21 端口映射到 FTPA 的私网地址  
    　　配置 FTP 服务步骤略_  
    　　  
    _步骤 1：在 R1 的公网接口上配置 NAT SERVER，映射端口 20 和 21_
    
    ```
    [R1-GigabitEthernet0/1]nat server protocol tcp global current-interface 20 21 inside 192.168.1.10 20 21
    ```
    
    _步骤 2：在 PCB 上测试是否能够通过 R1 的公网地址访问 FTPA 的 FTP 服务_
    
    ```
    <PCB>ftp 100.1.1.1
    Press CTRL+C to abort.
    Connected to 100.1.1.1 (100.1.1.1).
    220 FTP service ready.
    User (100.1.1.1:(none)): 
    
    ```