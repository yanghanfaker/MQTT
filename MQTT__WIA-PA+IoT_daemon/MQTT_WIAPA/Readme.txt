
守护程序

启动命令: iot_daemon -s /dev/ttyS0 aaaa::1/64

成功启动守护程序需要linux /dev目录中存在相应的设备文件。一个为"-s"所指定的slip接口设备，另外一为虚拟网络设备----tun.
"-s"所指定的slip接口设备要根据实际情况指定。当slip接口设备为USB设备时，设备名称为ttyACM0。当slip接口设备为RS232串口
设备是，在S3C2440 ARM网关中的设备名称为s3c2410_serialX。虚拟网络设备"tun"需要存放在/dev/net目录中，当"tun"设备不存在
时，通过加载tun.ko内核模块添加该设备文件，命令为"insmod /lib/modules/tun.ko"。

守护程序除为协调器或IOT设备提供slip通信接口、在Linux内建立相应的虚拟网络设备之外，还作为后台管理软件(手机和电脑上的)
、TR069代理软件等客户端软件的TCP服务器。在守护程序内部为每一种客户端分别提供了一个独立的监听端口，端口分配情况如下所示。
TR069_SERVER_PORT4	5222	//for tr069 proxier 
MPBMS_SERVER_PORT4	5225	//for mobile phone background managment software
PCBMS_SERVER_PORT4	5226	//for pc background managment software



1.add the opc ua node to wiapa folder 2021.07.23



