<<<<<<< HEAD
#!/usr/bin/env python3
"""
topology_v4.py — Topology nâng cấp cho đề tài phát hiện DoS trên SDN (đơn nguồn).
"""
import os
import sys
import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

CTRL_IP, CTRL_PORT = '127.0.0.1', 6653
OF_PROTO = 'OpenFlow13'
LINK_EXT = dict(bw=10,  delay='2ms')   
LINK_SRV = dict(bw=100, delay='1ms')   
LINK_PC  = dict(bw=50,  delay='1ms')   
LINK_HOST = dict(bw=100, delay='0.5ms')  
MIRROR_PORT = 99  

def build_topology():
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch,
                  link=TCLink, autoSetMacs=True, build=False)
                  
    c0 = net.addController('c0', controller=RemoteController, ip=CTRL_IP, port=CTRL_PORT)

    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, dpid='0000000000000001', protocols=OF_PROTO) 
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch, dpid='0000000000000002', protocols=OF_PROTO)  
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch, dpid='0000000000000003', protocols=OF_PROTO)  
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch, dpid='0000000000000004', protocols=OF_PROTO)  
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch, dpid='0000000000000005', protocols=OF_PROTO)  

    h_att1 = net.addHost('h_att1', ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')
    h_att2 = net.addHost('h_att2', ip='10.0.1.11/24', defaultRoute='via 10.0.1.1')
    h_att3 = net.addHost('h_att3', ip='10.0.1.12/24', defaultRoute='via 10.0.1.1')
    h_ext1 = net.addHost('h_ext1', ip='10.0.1.20/24', defaultRoute='via 10.0.1.1')

    h_web1 = net.addHost('h_web1', ip='10.0.2.10/24', defaultRoute='via 10.0.2.1')
    h_dns1 = net.addHost('h_dns1', ip='10.0.2.11/24', defaultRoute='via 10.0.2.1')

    h_db1  = net.addHost('h_db1',  ip='10.0.3.10/24', defaultRoute='via 10.0.3.1')
    h_app1 = net.addHost('h_app1', ip='10.0.3.11/24', defaultRoute='via 10.0.3.1')

    h_pc1 = net.addHost('h_pc1', ip='10.0.4.10/24', defaultRoute='via 10.0.4.1')
    h_pc2 = net.addHost('h_pc2', ip='10.0.4.11/24', defaultRoute='via 10.0.4.1')
    h_pc3 = net.addHost('h_pc3', ip='10.0.4.12/24', defaultRoute='via 10.0.4.1')
    h_pc4 = net.addHost('h_pc4', ip='10.0.4.13/24', defaultRoute='via 10.0.4.1')

    net.addLink(s1, s2, cls=TCLink, **LINK_EXT)  
    net.addLink(s3, s2, cls=TCLink, **LINK_SRV)  
    net.addLink(s4, s2, cls=TCLink, **LINK_SRV)  
    net.addLink(s5, s2, cls=TCLink, **LINK_PC)   

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
    if os.geteuid() != 0:
        sys.exit('Phải chạy với sudo (Mininet cần quyền root).')
    main()
=======
#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6653)

    info( '*** Add switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, dpid='1')  # External zone
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch, dpid='2')  # Router trung tam
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch, dpid='3')  # Server zone 1
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch, dpid='4')  # Server zone 2
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch, dpid='5')  # PC zone

    info( '*** Add hosts\n')
    # Zone 1 (External)
    h_att1 = net.addHost('h_att1', cls=Host, ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')
    h_ext1 = net.addHost('h_ext1', cls=Host, ip='10.0.1.20/24', defaultRoute='via 10.0.1.1')
    
    # Zone 2 (Web/DNS)
    h_web1 = net.addHost('h_web1', cls=Host, ip='10.0.2.10/24', defaultRoute='via 10.0.2.1')
    h_dns1 = net.addHost('h_dns1', cls=Host, ip='10.0.2.11/24', defaultRoute='via 10.0.2.1')
    
    # Zone 3 (DB/App)
    h_db1 = net.addHost('h_db1', cls=Host, ip='10.0.3.10/24', defaultRoute='via 10.0.3.1')
    h_app1 = net.addHost('h_app1', cls=Host, ip='10.0.3.11/24', defaultRoute='via 10.0.3.1')
    
    # Zone 4 (PCs)
    h_pc1 = net.addHost('h_pc1', cls=Host, ip='10.0.4.10/24', defaultRoute='via 10.0.4.1')
    h_pc2 = net.addHost('h_pc2', cls=Host, ip='10.0.4.11/24', defaultRoute='via 10.0.4.1')

    info( '*** Add links\n')
    # Switch to Router links
    net.addLink(s1, s2)
    net.addLink(s3, s2)
    net.addLink(s4, s2)
    net.addLink(s5, s2)
    
    # Host to Switch links
    net.addLink(s1, h_att1)
    net.addLink(s1, h_ext1)
    net.addLink(s3, h_web1)
    net.addLink(s3, h_dns1)
    net.addLink(s4, h_db1)
    net.addLink(s4, h_app1)
    net.addLink(s5, h_pc1)
    net.addLink(s5, h_pc2)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s1').start([c0])
    net.get('s2').start([c0])
    net.get('s3').start([c0])
    net.get('s4').start([c0])
    net.get('s5').start([c0])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()
>>>>>>> 146781253b0a2d0e5172a42e8310cd201f866d65
