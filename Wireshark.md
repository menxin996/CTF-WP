<h2 style="text-align:center">Wireshark</h2>

**1. Wireshark介绍**

Wireshark：一款网络流量捕获和分析的软件，有图形化界面和命令行(TShark)形式。

Wireshak的作用：

- 辅助学习，更深入理解网络协议
- 排查故障，更快发现问题

原理：

- 捕获二进制流量
- 转换Wireshark组装数据包
- 分析捕获的数据包，识别协议等信息。

基本使用方法：

- 选择网卡
- 捕获数据流量
- 过滤数据包
- 保存数据包(pcap)

Wireshark抓包界面：从上到下分别为菜单栏、工具栏、过滤器、数据列表区、数据详细区、数据字节区，以及最下方的数据统计区。

- Display Filter(显示过滤器)：用于设置过滤条件进行数据包列表过滤。
- Packet List Pane(数据列表区)：显示捕获到的数据包，每个数据包包括：编号、时间戳、源地址、目标地址、协议、长度以及数据包信息。不同的协议使用了不同的颜色区分。
- Packet Details Pane(数据详细区)：用于查看协议中的每一个字段。
  - Frame：物理层的数据帧信息
  - Ethernet II：数据链路层以太网帧头部信息
  - Internet Protocol Version 4：IP报文头部信息
  - Transmission Control Protocol：传输层TCP报文头部信息
  - Hypertext Transfer Protocol：应用层信息
- Dissector Pane(数据包字节区)：显示数据包每个字节的信息

**WireShark自动分析：**

- 分析 -> 专家信息：可以看到不同级别的提示信息。
- 数据 -> 服务响应时间 -> 指定协议名称：可以得到响应时间的统计表，常用于衡量服务器性能。
- 数据 -> TCP 流图形：可以生成几类统计图。
- 数据 -> 捕获文件属性：可以看到一些统计信息，比如平均流量，有助于推测负载情况。

**2. 伯克利包过滤规则**

伯克利包过滤(Berkeley Packet Filter)：采用和自然语言相近的语法，利用语法构造字符串确定保留具体符合规则的数据包而忽略其他数据包。

语法规则：

- type：表示对象。例如：
  - IP地址：host。(在 wireshark 中使用 ip.addr )
  - 子网：net
  - 端口：port
- dir：表示数据包传输的方向
  - src
  - dst
- proto：表示与数据包匹配的协议
  - ether
  - ip
  - tcp

例如：

- IP地址 192.168.4.5。语法：ip.addr == 192.168.4.5
- 源地址 192.168.4.5。语法：ip.src == 192.168.4.5
- 目的地址 192.168.4.1，目标端口 80。语法：ip.dst == 192.168.4.1 and tcp/udp.port == 80

**3. wireshark 过滤器**

**3.1 捕获过滤器：**在抓包之前设定规则以便于只抓取符合规则的数据包。(Caption Options中设置)

例如：

- 只捕获目标端口为80的TCP数据包：tcp dst port 80。(中间用空格隔开)
- 只捕获目标主机名为 192.168.162.129 的数据包：dst host 192.168.162.129

**3.2 筛选过滤器：**抓包之后设定规则只看某些协议的数据包。

表达式规则：主题 + 运算符 + 值。多个表达式用逻辑关系(and or not)连接

**4. wireshark 捕获文件保存**

输出文件格式：pcapng、pcap

**情形一：数据流特别大，导致 wireshark 无法打开正常保存的文件**。解决方法：设置自动创建文件，每隔10s创建一个。(Caption Options -> output -> Create a new file automatically -> after 10 seconds)

**情形二：使用 wireshark 进行网络监控，硬盘空间可能被消耗殆尽。**解决方法：环形缓存器。作用：每天保存固定数量的数据包，第二天开始删除靠前的数据包。(Caption Options -> output -> use a ring buffer with 10 files)

**5. wireshark 杂项设置**

查看 wireshark 的配置文件路径：Help - > About Wireshark -> Folders

查看 wireshark 使用的插件：Help - > About Wireshark -> Plugins

**6.网络设备**

- 网线：两台设备使用网线连接即可通信。
- 交换机：
  - 基于MAC地址：由6个字节组成，前三个字节表示厂商唯一标识(IEEE发布)，后三个字节由厂商自行赋予。
  - 通过不同的端口连接组成局域网。
  - 接收到数据帧后，查看MAC地址表中是否有对应数据，如果有则转发数据
  - 每个一段时间更新MAC地址表
- 路由器：
  - 基于IP地址通信：路由转发，实现不同网络之间的通信
  - 基于路由表：动态路由表和静态路由表

**7. wireshark 远程数据包捕获**

**适用情形：**对某台服务器的控制权限，但不能直接操作目标服务器(位置在远程机房)。

开启远程桌面，本地登录RDP(win + r -> mstsc -> 目标IP -> 连接)，在系统中安装wireshark进行抓包分析。

缺陷：会产生与目的远程连接无关的数据流量。

wireshark远程抓包：

- 服务器：winpcap   rpcapd。在 winpcap 安装路径下进入 cmd 界面，输入 rpcapd.exe -n 运行服务，默认打开的端口号为 2002。
- 客户端：wireshark。配置接口：设置 -> Manage Interfaces -> 远程接口 -> + -> 输入IP和端口号，无认证，点击ok -> 选中网卡，开始抓包 

**8. wireshark 本地数据包捕获**

wireshark **不能抓取本地环回网卡数据包**，因此可以借助其他软件进行抓取。

RawCap：

- 安装网址：https://www.netresec.com/?page=RawCap。
- 使用方法：Rawcap.exe 127.0.0.1 test.pcap。
- 抓取的数据包保存在 test.pcap 文件中，然后通过 wireshark 打开进行数据包分析

**9. wireshark 虚拟机数据包捕获**

选中指定网卡(eth0)进行流量嗅探。

使用netdiscover -r CIDR 发现局域网主机，同时使用 wireshark 捕获虚拟机的流量。

打开 wireshark -> 选中 Vmnet 8 网卡 -> 打开 kali 虚拟机(IP地址为192.168.162.129)，对 192.168.162 网段进行扫描 -> netdiscover -r 192.168.162.1/24，回车

**10. wireshark ARP欺骗数据包捕获**

在 kali 虚拟机中进行ARP欺骗，然后在本地使用 wireshark 进行抓包。

具体步骤：

- kali 虚拟机中使用命令：arpspoof  -i  etho  -t  10.12.182.125(目标windows IP)  10.12.182.1(欺骗的网关) 
- 打开 kali 虚拟机的 wireshark ，选择eth0网卡，进行抓包 
- windows 机器中打开网页(百度) 
- wireshark 获得的数据包都是目标机器发送到网关的数据流量(DNS数据包)

**11. wireshark 网络安全**

11.1 链路层网络安全

针对交换机的安全问题：

- MAC 地址欺骗：通过 MAC 地址欺骗达到隐藏真实主机的目的

  - macchanger 工具(kali 虚拟机中)：

    - macchanger -s eth0：显示网卡eth0 当前的 MAC 地址和永久 MAC 地址。

    - macchanger -m  xx:xx:xx:xx:xx:xx eth0：修改网卡 eth0 对应的 MAC 地址。

      ★注：修改之前需要关闭 eth0 网卡：ifconfig eth0 down。修改后再打开

      ★注：修改的 MAC 地址的前三个字节，是IEEE定义的厂商，不能随意设置

- MAC 地址泛洪：[ MAC地址泛洪攻击详细过程及原理](https://blog.csdn.net/Marsal/article/details/107534283)

  - 溢出交换机**CAM表**(交换机在二层转发数据要查找的表，表中有MAC地址，对应的端口号，端口所属的VLAN)。
  - macof 工具(kali 虚拟机中)：
    - macof -i eth0：指定 eth0 网卡进行 MAC 泛洪
  - 查看源头端口：交换机中使用 display mac-address
  - 防御策略：限制交换机端口 MAC 地址数量

- STP 操纵：生成树协议按照树的结构构造网络拓扑，**避免形成回路**。

  STP 协议中的各交换机通过交换 BPDU 报文信息传播生成树信息。

  如果伪造 BPDU 报文，控制交换机的端口转发状态，从而动态改变网络拓扑，劫持网络流量到本机。

- 广播风暴：ARP、DHCP 通过在局域网中广播，占用网络资源，网络性能下降。直观现象就是**网络速度变慢**。

  产生原因：

  - 网络短路
  - 存在环路
  - 网卡损坏
  - 蠕虫病毒

11.2 网络层网络安全

- 中间人安全测试：

  - **具体情形：**公司多名职工的账户被盗，包括单位 FTP 服务认证信息

  - ARP 协议：局域网中用来寻找主机发送数据包的协议，IP 地址 -> MAC 地址。

    每台终端设备都有 ARP 缓存表。

    - 查看缓存表：arp -a
    - 删除缓存表：arp -d 。条件：具有管理员权限
    - 填充缓存表：寻找 IP 地址对应的 MAC 地址，如果没有则广播 当前设置的 MAC 地址(00:00:00:00:00:00)，找到则替换为真实的 MAC 地址。

  - ★ wireshark 显示过滤器分析 ARP协议：

    - arp：筛选出所有 ARP 协议
    - arp.opcode==0x0001：查看请求的 ARP
    - arp.opcode==0x0002：查看响应的 ARP
    - arp.src.hw_mac == MAC 地址：查看具体源 MAC 地址的 ARP
    - arp.src.hw_mac == MAC 地址 && arp.opcode==0x0001：查看具体源 MAC 地址的请求的 ARP

  - arpspoof 安全测试：

    - 欺骗原理：双向欺骗
    - 命令：arpspoof -i 网络适配器 -t 被欺骗主机IP 网关IP
    - 开启路由转发：echo 1 >> /proc/sys/net/ipv4/ip_forward
    - 使用 wireshark 进行抓包

  - wireshark 安全分析：

    - 专家系统分析(左下角的圆点)：寻找网关地址和局域网中的计算机具有一致的 MAC 地址。
    - 出现大量ARP数据包的原因：
      - ARP 主机扫描
      - ARP 病毒通信
      - ARP 中间人测试

  - 防御 ARP 欺骗措施

    - 静态绑定 ARP 表：arp -s 网关的 IP 地址 网关的 MAC 地址

      ★注：需要管理员权限

      ★注：添加静态 arp 项还需命令：netsh -c "i i " add neighbors "网卡编号 网关" IP 地址 "网关 MAC 地址"。其中网卡编号可以用命令 netsh i i show in 进行查看

    - 交换机 DHCP-Snooping(适用于大型网络)：交换机监听 DHCP 数据，提取 IP 和 MAC 建立 DHCP Snooping 的绑定表

    - 划分VLAN(虚拟局域网)：每一个 VLAN 都是一个广播域(限制网络范围)

- 泪滴安全测试：

  - 针对 IP 协议的安全测试，伪造 IP 地址和发送畸形数据包，使得 IP 数据包碎片在重组的过程中有重合的部分，导致目标系统无法重组，进一步导致**系统奔溃和停止服务。**
  
  - IP 数据包的组成：(官方样例数据包 https://wiki.wireshark.org/SampleCaptures 中的 teardrop.cap)
    - 版本号：4位
    - 首部长度：4位，一般情况  值  20字节
    - 总长度：8位，一般情况   值   56字节
    - 标识：16位，数据包标识
    - 片偏移：16位，表示较长的分组在分片后某片在原分组中的相对位置，以8个字节为偏移单位
    - 生存时间：8位，TTL(Time To Live)，表示数据通过最大的路由器数量
    
    ★注：如果所有数据包的 TTL 都一致，则可以判断当前的安全问题在于**内网中没有经过路由器**
    
    - 协议字段：8位，表示 IP协议 为上层的哪一种协议服务
    - 源IP地址：32位
    - 目的IP地址：32位
    
  - IP协议分片
  
    - 分片原因：MTU(最大传输单元)，最大1500，当数据包大小大于1500时，则会对数据包进行分片
    - 分片组成：
      - IP 数据包标识：标记当前分片所属 IP 分组
      - 片偏移：前 3 位，确定是否还有更多分片；后 13 位，分片在原始数据的偏移
    - 案例演示：ping -n 1 -l 4400 目标地址：表示发送一个 4400 字节的 ICMP 数据包
  
  - 泪滴安全测试原理：IP 分片重组时发生重合，主要原因是偏移大小不够。(teardrop.cap中第8、9个数据包)

11.3 传输层网络安全

- 拒绝服务(Dos Denial of Service)：
  - 传输层针对 TCP 和 UDP 协议的 Dos攻击。
  - 特点：耗尽目标服务器的带宽和资源
  - 分布式拒绝服务攻击(DDOS)：多台主机向目标服务器发送大量数据包，导致目标服务器瘫痪
  
- TCP SYN 泛洪：
  - TCP 连接：客户端和服务器端**三次握手**建立连接
    - 客户端发送 SYN 到服务器
    - 服务器响应 SYN+ACK 到客户端
    - 客户端发送 ACK 到服务器
  - TCP SYN flooding 原理：客户端发送 SYN ，服务端返回 SYN+ACK，然后客户端不发送 ACK，使得服务器等待超时，重新发送 SYN+ACK，如果是大量的等待超时，可能导致服务器崩溃
    - (Kali虚拟机演示)：hping3 -q -n --rand-source -S -p 80 --flood 目标IP地址。-q：表示不显示发送流量；-n：表示数据化格式输出结果；--rand-source：表示随机化IP地址发送；-S：表示发送 SYN 的 TCP 数据包；-p：指定端口；--flood：表示使用泛洪
    - 接着使用 wireshark 抓包，通过流向图查看。Statistics -> Flow Graph -> Flow type 选择 TCP Flows
  - TCP SYN flooding 防御：
    - 丢弃第一个 SYN 数据包：缺点是用户体验差
    - 反向探测：向源地址发送探测包，确定源地址合法性
    - 代理模式：防火墙代理
  
- UDP 泛洪：
  - UDP协议：
    - 非连接状态协议，不可靠，传输速率高，适合传输大文件。
    - 组成：源端口、目的端口、UDP报文长度、检验码
  - UDP flooding 测试：
    - 原理：攻击者向目标服务器发送大量 UDP 数据包，导致目标服务器资源耗尽
    - (Kali 虚拟机演示)：hping3 -q -n -a IP地址 --udp -s 53 -p 目标端口 --flood 目标IP地址 -d 1000。-a：表示伪装的IP地址；-d：表示发送数据包大小
  - UDP flooding 防御：防火墙
    - 限流：将UDP报文控制在合理的范围，当超过阈值，则丢弃
    - 指纹学习：先学习，再匹配
  
- 网络取证：

  - 使用 wireshark 恢复传输文件(以 http_with_jpegs.cap 为例)

    1. 选中含有 JPEG 信息文件的数据包。

       ![12](E:\Study\渗透分析和漏洞测试\picture\57.png)

    2. 右键 -> 追踪流 -> TCP流 ->最上方显示图片名(sydney.jpg) -> 左下角选择 80 端口到本机，显示数据为原始数据 -> 点击另存为 test.bin 文件

    3. 打开 winhex.exe，将 test.bin 拖入 -> 找到图片的文件头 FF D8 FF E0 开头，删除之前的内容。

       ![12](E:\Study\渗透分析和漏洞测试\picture\58.png)

    4. 保存为 sydney.jpg，此时，图片恢复成功

       ![12](E:\Study\渗透分析和漏洞测试\picture\59.png)

  - ★取证案例实践：(以evidence01.pcap为例)

    - 本题的故事背景：Ann 可能是一名潜入公司的卧底。有一天，一台从未使用过的笔记本连入了公司的无线网当中，Ann的IP地址为(192.168.1.158)，Ann 不久就从公司中离开了，不过渗透测试人员捕获了当时的数据包，我们需要查看数据包究竟发生了什么行为？

    - 问题1(寻找 Ann 的通信对象)：

      选中 SSL 的连接协议(23号包) -> 右键 -> Decode as -> 改成 TCP port，值为443，解密方式为AIM(题目中说的是 AIM 加密方式) -> 完成AIM解密。

      ![12](E:\Study\渗透分析和漏洞测试\picture\60.png)

      接着分析 25号 包，从 AIM Messaging 中的 Buddy 可以看到 Ann 的通信对象，为 Sec558user1。

    - 问题2(寻找通信的首条消息)：

      选中25号包，从 AIM Messaging 中的 TLV 可以看到 ValueMessanger 的值，即为第一条消息。

      ![12](E:\Study\渗透分析和漏洞测试\picture\61.png)

    - 问题3(寻找通信的文件名称)：

      过滤器中输入 data 进行筛选 -> 选择第一个 TCP 数据包(112号数据包) -> 右键 -> 追踪流 -> TCP 流

      ![12](E:\Study\渗透分析和漏洞测试\picture\62.png)

      可以看到 recipe.docx 文件，即为通信的文件名称

    - 问题4(还原 Ann 发送的文件，并得到文件幻数(文件最前面的四个字节))：

      和之前图片恢复类似，追踪 TCP 流 -> 左下角选择 158 发送到 159 ，显示数据为原始数据 -> 另存为 recipe.bin 二进制文件 -> 使用 winhex 打开 -> 找一堆 00 结束的位置，可以看到在 504B0304之前。说明文件的幻数为(50 4B 03 04)

      ![12](E:\Study\渗透分析和漏洞测试\picture\63.png)

      删除之前的数据，另存为 recipe.docx，文件可以正常打开。

    - 问题5(计算文件的 MD5 值)：

      使用工具 hash.exe，将文件拖入即可。

      ![12](E:\Study\渗透分析和漏洞测试\picture\64.png)


11.3 应用层网络安全

11.3.1 暴力破解分析：使用medusa 破解 ssh 登录

命令：medusa -h 192.168.128.1 -u root -M ssh -P pass.txt

参数： 

- -h ：目标IP地址
- -u：指定连接的用户名(只需暴力破解密码即可)
- -M：破解的模块
- -P：密码字典

然后使用 wireshark 抓 ssh 的包

11.3.2 后门分析：分析 vsftpd 2.3.4 隐藏后门(笑脸后门)

![12](E:\Study\渗透分析和漏洞测试\picture\69.png)

通过 metasploit framework 进行攻击，步骤如下：

- search vsftpd：寻找对应的漏洞利用代码
- use exploit/unix/ftp/vsftpd_234_backdoor：运行代码
- show options：查看设置选项，设置目标IP地址
- exploit：建立连接，获得反弹shell

wireshark 抓取 ftp 数据包。

**12. wireshark 辅助工具**

★12.1 Tshark(wireshark 命令行工具)

常见命令：

- tshark -D：查看当前网卡
- tshark -i eth0：指定eth0网卡为抓取目标
- tshark -f 'tcp dst port 80'：抓取特定数据包(目标端口为 80 的 TCP 数据包，其实也就是 http 包)
- tshark -i eth0 -f 'tcp dst port 80' -R 'http.request'：抓取 HTTP 请求包
- tshark -w 文件名：输出 cap 文件
- tshark -r 文件名：读取 cap 文件

12.2 Dumpcap

类似 Tshark 工具，优势在于资源消耗比较小

常见命令：

- dumpcap：默认抓取 eth0 网卡的数据包
- dumpcap -D：显示网卡
- dumpcap -i eth0 -f 'tcp dst port 80'：抓取 eth0 网卡上目标端口为 80 的TCP数据包

详细文档：www.wireshark.org/docs/man-pages/dumpcap.html

12.3 Editcap

功能：**分割大文件为小文件**，Editcap 可以通过开始时间和结束时间来获取数据包文件的子集，删除数据包文件中的重复数据。

- editcap -r infile outfile 1-10：提取前10个数据包为新文件

  注：使用 -r 参数，否则原始数据包被删除

- editcap -c 2 infile outfile(.pcapng格式)：将数据包文件拆分，按照每2个数据包为一个新文件

- editcap -d infile outfile：删除数据包中重复内容

注：默认是5个数据包，可以通过 -D 100 指定大小

12.4 Mergecap

功能：**合并多个文件为一个文件**。

常用命令：mergecap -w outfile(.pcapng格式) infile1 infile2 ...

12.5 Capinfos

功能：**显示数据包文件信息**

常用命令：

- capinfos 数据包名称：显示数据包所有信息
- capinfos -c 数据包名称：显示数据包的数量
- capinfos -t 数据包名称：显示数据包的类型(后缀名)

12.6 命令行工具帮助信息获取

例如：wireshark 安装目录下的 wireshark.html

**13. wireshark 扩展**

设置 wireshark 为中文：Edit -> Preferences -> Appearance -> language

wireshark 支持编程开发接口 （Lua 语言）：工具 -> Lua -> Evaluate -> 输入 Lua 程序

wireshark 解析协议(新)的原理：

- 协议使用的端口不同
- 协议中的数据格式不同

查看 wireshark 支持的所有协议端口信息：视图 -> 内部 -> Dissector Table

★wireshark 新协议注册：

- 添加新协议：local test = Proto(name,description)
- 添加解析器：function test.dissector(tvb,pinfo,tree) end

注：tvb 表示缓冲数据包；pinfo 表示协议信息；tree 表示展示的树状结构

- 注册新协议到 wireshark ：
  - DissectorTable.get('表名'):add(端口,协议名称)
  - 保存 lua 文件到全局配置中

★wireshark 解析器编写：编写 dissector 函数，以之前注册的 test 协议为例

Lua 语言中的 ProtoField 表示协议字段，可以使用 uint8、unit16、unit32等类型

假设 test 协议包含三部分的内容：

- Trans_ID(16bit)：Trans_ID = ProtoField.unit16("test.ID","ID")
- Msg_Type(16bit)：Msg_Type = ProtoField.unit16("test.Type","Type")
- Msg_Data(32bit)：Msg_Data = ProtoField.unit32("test.Data","Type")
- 合并字段：test.field = {Trans_ID,Msg_Type,Msg_Data}

解析函数编写：

- 设置 wireshark 报文列表上 Protocol 列文本：pinfo.cols.protocol = test.name
- 添加树状新节点：local subtree = tree:add(test,tvb(0))
- 添加协议解析树：
  - subtree:add(Trans_ID,tvb(0,2))
  - subtree:add(Msg_Type,tvb(2,2))
  - subtree:add(Msg_Data,tvb(4,4))

新协议测试：使用 xcap 自定义发包工具(建议在win 7 中使用)

