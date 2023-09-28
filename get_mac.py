# 使用前需要安装WinPcap
# 需要使用ipconfig查看windows网络适配器名称



from scapy.all import ARP, Ether, srp

def get_local_mac_addresses(interface):
    # 创建ARP请求包，目标IP设置为局域网地址
    arp = ARP(pdst='192.168.1.0/24')
    # 创建以太网帧，目标MAC地址设置为广播地址
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    # 组合ARP请求包和以太网帧
    packet = ether/arp

    # 发送ARP请求包并接收响应
    result = srp(packet, timeout=3, verbose=0, iface=interface)[0]
    # 解析响应数据，提取每个设备的IP和MAC地址
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

# 指定网络接口
interface = '以太网'
# 获取局域网中的设备MAC地址
devices = get_local_mac_addresses(interface)
# 打印设备的IP和MAC地址
for device in devices:
    print(f"IP: {device['ip']}\tMAC: {device['mac']}")