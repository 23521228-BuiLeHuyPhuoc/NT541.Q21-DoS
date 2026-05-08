#!/usr/bin/env python3
"""
topology_nhom4.py — TV2 (Phúc) — Task 2.1 & 2.2
Topology V4: 12 hosts, 5 switches, OF1.3, QoS+Mirror ON.
Dùng để mô phỏng mạng và thu thập dữ liệu tấn công DoS.
"""

import os
import sys
import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

# --- CẤU HÌNH HỆ THỐNG ---
CTRL_IP = '127.0.0.1'
CTRL_PORT = 6653
OF_PROTO = 'OpenFlow13'
MIRROR_PORT = 99  # s2-eth99

# --- THÔNG SỐ ĐƯỜNG TRUYỀN ---
LINK_EXT  = dict(bw=10,  delay='2ms')   # Nhánh Attacker (Bóp băng thông)
LINK_SRV  = dict(bw=100, delay='1ms')   # Nhánh Server
LINK_PC   = dict(bw=50,  delay='1ms')   # Nhánh PC thường
LINK_HOST = dict(bw=100, delay='0.5ms') # Từ Host đến Switch

def build_topology():
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch,
                  link=TCLink, autoSetMacs=True, build=False)
                  
    info('*** Adding Controller\n')
    net.addController('c0', controller=RemoteController, ip=CTRL_IP, port=CTRL_PORT)

    info('*** Adding Switches\n')
    s1 = net.addSwitch('s1', dpid='0000000000000001', protocols=OF_PROTO) 
    s2 = net.addSwitch('s2', dpid='0000000000000002', protocols=OF_PROTO)  
    s3 = net.addSwitch('s3', dpid='0000000000000003', protocols=OF_PROTO)  
    s4 = net.addSwitch('s4', dpid='0000000000000004', protocols=OF_PROTO)  
    s5 = net.addSwitch('s5', dpid='0000000000000005', protocols=OF_PROTO)  

    info('*** Adding Hosts\n')
    # Nhánh External/Attacker (nối vào s1)
    h_att1 = net.addHost('h_att1', ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')
    h_att2 = net.addHost('h_att2', ip='10.0.1.11/24', defaultRoute='via 10.0.1.1')
    h_att3 = net.addHost('h_att3', ip='10.0.1.12/24', defaultRoute='via 10.0.1.1')
    h_ext1 = net.addHost('h_ext1', ip='10.0.1.20/24', defaultRoute='via 10.0.1.1')

    # Nhánh Web/DNS Server (nối vào s3)
    h_web1 = net.addHost('h_web1', ip='10.0.2.10/24', defaultRoute='via 10.0.2.1')
    h_dns1 = net.addHost('h_dns1', ip='10.0.2.11/24', defaultRoute='via 10.0.2.1')

    # Nhánh App/DB Server (nối vào s4)
    h_db1  = net.addHost('h_db1',  ip='10.0.3.10/24', defaultRoute='via 10.0.3.1')
    h_app1 = net.addHost('h_app1', ip='10.0.3.11/24', defaultRoute='via 10.0.3.1')

    # Nhánh Client PC (nối vào s5)
    h_pc1 = net.addHost('h_pc1', ip='10.0.4.10/24', defaultRoute='via 10.0.4.1')
    h_pc2 = net.addHost('h_pc2', ip='10.0.4.11/24', defaultRoute='via 10.0.4.1')
    h_pc3 = net.addHost('h_pc3', ip='10.0.4.12/24', defaultRoute='via 10.0.4.1')
    h_pc4 = net.addHost('h_pc4', ip='10.0.4.13/24', defaultRoute='via 10.0.4.1')

    info('*** Creating Links\n')
    # Liên kết giữa các Switch
    net.addLink(s1, s2, cls=TCLink, **LINK_EXT)  
    net.addLink(s3, s2, cls=TCLink, **LINK_SRV)  
    net.addLink(s4, s2, cls=TCLink, **LINK_SRV)  
    net.addLink(s5, s2, cls=TCLink, **LINK_PC)   

    # Liên kết Host vào Switch
    for h in (h_att1, h_att2, h_att3, h_ext1):
        net.addLink(h, s1, cls=TCLink, **LINK_HOST)
    net.addLink(h_web1, s3, cls=TCLink, **LINK_HOST)
    net.addLink(h_dns1, s3, cls=TCLink, **LINK_HOST)
    net.addLink(h_db1,  s4, cls=TCLink, **LINK_HOST)
    net.addLink(h_app1, s4, cls=TCLink, **LINK_HOST)
    for h in (h_pc1, h_pc2, h_pc3, h_pc4):
        net.addLink(h, s5, cls=TCLink, **LINK_HOST)
    
    return net

def setup_qos():
    """Thiết lập Linux HTB QoS trên cổng s2-eth1 (Cổng chính ra Internet)"""
    info('*** Configuring HTB QoS on s2-eth1\n')
    os.system(
        'ovs-vsctl -- set port s2-eth1 qos=@newqos '
        '-- --id=@newqos create qos type=linux-htb '
        'other-config:max-rate=10000000 '
        'queues=0=@q0,1=@q1,2=@q2 '
        '-- --id=@q0 create queue other-config:min-rate=5000000 '
        '-- --id=@q1 create queue other-config:min-rate=3000000 '
        '-- --id=@q2 create queue other-config:max-rate=1000000'
    )

def setup_mirror():
    """Thiết lập Port Mirroring: Toàn bộ traffic qua s2-eth1 sẽ copy sang s2-eth99"""
    info('*** Setting up port mirror s2-eth1 -> s2-eth%d\n' % MIRROR_PORT)
    os.system(f'ip link add s2-eth{MIRROR_PORT} type dummy 2>/dev/null || true')
    os.system(f'ip link set s2-eth{MIRROR_PORT} up')
    os.system(f'ovs-vsctl add-port s2 s2-eth{MIRROR_PORT} 2>/dev/null || true')
    os.system(
        'ovs-vsctl -- --id=@p get port s2-eth1 '
        f'-- --id=@m get port s2-eth{MIRROR_PORT} '
        '-- --id=@mirror create mirror name=m0 select-all=true output-port=@m '
        '-- set bridge s2 mirrors=@mirror'
    )

def cleanup_qos_mirror():
    """Dọn dẹp cấu hình QoS và Mirror khi thoát để tránh lỗi device busy"""
    info('*** Cleaning QoS + mirror\n')
    os.system('ovs-vsctl -- --all destroy qos -- --all destroy queue')
    os.system('ovs-vsctl clear bridge s2 mirrors')
    os.system('ovs-vsctl -- --all destroy mirror')
    os.system(f'ip link del s2-eth{MIRROR_PORT} 2>/dev/null || true')

def main():
    setLogLevel('info')
    net = build_topology()
    net.build()
    net.start()
    
    info('*** Waiting 3s for switches to connect Ryu...\n')
    time.sleep(3)
    
    try:
        setup_qos()
        setup_mirror()
        info('\n*** Topology V4 ready. 12 hosts, 5 switches, OF1.3, QoS+Mirror ON\n')
        CLI(net)
    finally:
        cleanup_qos_mirror()
        net.stop()

if __name__ == '__main__':
    # Kiểm tra quyền root
    if os.geteuid() != 0:
        print('Phải chạy với sudo (Mininet cần quyền root).')
        sys.exit(1)
    main()
