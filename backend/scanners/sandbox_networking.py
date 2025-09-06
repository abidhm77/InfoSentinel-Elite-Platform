import docker
from scapy.all import *
import logging

class CyberRangeNetwork:
    def __init__(self):
        self.client = docker.from_env()
        self.macvlan_network = None
        self.mirror_interface = 'mirror0'

    def create_isolated_network(self):
        """Create macvlan network with strict isolation"""
        try:
            self.macvlan_network = self.client.networks.create(
                name='cyber-range',
                driver='macvlan',
                options={
                    'macvlan_mode': 'bridge',
                    'parent': 'eth0'
                },
                check_duplicate=True
            )
            logging.info('Created isolated macvlan network')
        except docker.errors.APIError as e:
            logging.error(f'Network creation failed: {e}')
            raise

    def configure_traffic_mirror(self):
        """Set up traffic mirroring using tcpreplay"""
        os.system(f'ip link add {self.mirror_interface} type dummy')
        os.system(f'tc qdisc add dev eth0 handle ffff: ingress')
        os.system(f'tc filter add dev eth0 parent ffff: \
                  protocol all u32 match u8 0 0 \
                  action mirred egress mirror dev {self.mirror_interface}')

    def capture_mirrored_traffic(self, timeout=60):
        """Capture mirrored packets for analysis"""
        packets = sniff(
            iface=self.mirror_interface,
            timeout=timeout,
            filter='tcp or udp',
            prn=lambda x: x.summary()
        )
        wrpcap('/tmp/mirrored.pcap', packets)
        return len(packets)

    def deploy_honeypot(self, service_port=2222):
        """Deploy SSH honeypot container"""
        return self.client.containers.run(
            'dionach/cmdly',
            ports={f'{service_port}/tcp': service_port},
            network='cyber-range',
            detach=True,
            remove=True
        )

    def teardown(self):
        """Clean up network resources"""
        if self.macvlan_network:
            self.macvlan_network.remove()
        os.system(f'ip link del {self.mirror_interface}')
        logging.info('Sandbox networking resources cleaned')