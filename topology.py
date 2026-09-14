from mininet.net import Mininet
from mininet.node import Node, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()

def build():
    net = Mininet(link=TCLink)

    router = net.addHost('router', cls=LinuxRouter, ip='192.168.10.1/24')
    victim = net.addHost('victim', ip='192.168.10.10/24', defaultRoute='via 192.168.10.1')
    attacker = net.addHost('attacker', ip='192.168.10.50/24', defaultRoute='via 192.168.10.1')
    server = net.addHost('server', ip='192.168.20.100/24', defaultRoute='via 192.168.20.1')

    switchA = net.addSwitch('s1', cls=OVSSwitch, failMode='standalone')
    switchB = net.addSwitch('s2', cls=OVSSwitch, failMode='standalone')

    net.addLink(victim, switchA)
    net.addLink(attacker, switchA)
    net.addLink(router, switchA, intfName1='router-eth0', params1={'ip': '192.168.10.1/24'})

    net.addLink(server, switchB)
    net.addLink(router, switchB, intfName1='router-eth1', params1={'ip': '192.168.20.1/24'})

    net.start()

    # Configure victim for the ICMP redirect attack scenario
    for setting, value in [
        ('accept_redirects', 1),
        ('secure_redirects', 0),
        ('forwarding', 0),
        ('rp_filter', 0),
    ]:
        for scope in ['all', 'default', 'victim-eth0']:
            victim.cmd(f'sysctl -w net.ipv4.conf.{scope}.{setting}={value}')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    build()