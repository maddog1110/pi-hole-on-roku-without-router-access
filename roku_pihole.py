from scapy.all import *
import sys
import time
import threading
import argparse
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

class RokuPihole:
    def __init__(self, roku_ip, router_ip, pihole_ip):
        self.roku_ip = roku_ip
        self.router_ip = router_ip
        self.pihole_ip = pihole_ip
        self.running = False
        self.my_mac = None
        
    def get_mac(self, ip):
        """Get MAC address for an IP"""
        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            ans, _ = srp(arp_request, timeout=2, verbose=False)
            if ans:
                return ans[0][1].hwsrc
        except Exception as e:
            print(f"Error getting MAC for {ip}: {e}")
        return None

    def handle_dns_packet(self, packet):
        """Handle intercepted DNS packets"""
        try:
            if packet.haslayer(DNS) and packet.haslayer(IP) and packet.haslayer(UDP):
                # Only process DNS queries (not responses)
                if packet[DNS].qr == 0 and packet[IP].src == self.roku_ip:
                    # Get the original DNS query
                    dns_query = packet[DNSQR].qname.decode('utf-8')
                    print(f"Intercepted DNS query from Roku: {dns_query}")

                    # Create new packet to forward to Pi-hole
                    new_packet = IP(dst=self.pihole_ip)/\
                               UDP(dport=53)/\
                               DNS(rd=1, qd=DNSQR(qname=dns_query))
                    
                    # Send to Pi-hole and wait for response
                    response = sr1(new_packet, timeout=2, verbose=False)
                    
                    if response and response.haslayer(DNS):
                        print(f"Got response from Pi-hole for {dns_query}")
                        # Forward response back to Roku
                        reply = IP(dst=self.roku_ip)/\
                               UDP(dport=packet[UDP].sport, sport=53)/\
                               DNS(
                                   id=packet[DNS].id,
                                   qr=1,
                                   rd=1,
                                   ra=1,
                                   qd=packet[DNS].qd,
                                   an=response[DNS].an
                               )
                        send(reply, verbose=False)
        except Exception as e:
            print(f"Error handling DNS packet: {e}")

    def spoof(self, target_ip, spoof_ip, target_mac):
        """Send ARP packet to spoof IP address"""
        if not self.my_mac:
            # Get our MAC address
            my_iface = conf.iface
            if hasattr(my_iface, 'mac'):
                self.my_mac = my_iface.mac
            else:
                print("Could not get local MAC address")
                return False
                
        packet = Ether(src=self.my_mac, dst=target_mac) / ARP(
            op=2,  # is-at (response)
            hwsrc=self.my_mac,
            psrc=spoof_ip,
            hwdst=target_mac,
            pdst=target_ip
        )
        try:
            sendp(packet, verbose=False)
            return True
        except Exception as e:
            print(f"Error sending ARP packet: {e}")
            return False

    def restore_arp(self, target_ip, source_ip, target_mac, source_mac):
        """Restore normal ARP entries"""
        packet = Ether(src=source_mac, dst=target_mac) / ARP(
            op=2,
            hwsrc=source_mac,
            psrc=source_ip,
            hwdst=target_mac,
            pdst=target_ip
        )
        try:
            sendp(packet, count=5, verbose=False)
        except Exception as e:
            print(f"Error restoring ARP: {e}")

    def start_dns_sniffing(self):
        """Start sniffing DNS packets in a separate thread"""
        sniff_thread = threading.Thread(target=self.sniff_dns)
        sniff_thread.daemon = True
        sniff_thread.start()

    def sniff_dns(self):
        """Sniff DNS packets"""
        try:
            sniff(
                filter=f"udp port 53 and host {self.roku_ip}",
                prn=self.handle_dns_packet,
                store=0,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            print(f"Error sniffing DNS: {e}")

    def start(self):
        """Start DNS redirection and ARP spoofing"""
        print(f"\nGetting MAC addresses...")
        roku_mac = self.get_mac(self.roku_ip)
        router_mac = self.get_mac(self.router_ip)
        
        if not roku_mac:
            print(f"Could not find Roku device at {self.roku_ip}")
            return
        if not router_mac:
            print(f"Could not find router at {self.router_ip}")
            return

        print(f"\nStarting Roku -> Pi-hole redirection:")
        print(f"Roku: {self.roku_ip} ({roku_mac})")
        print(f"Router: {self.router_ip} ({router_mac})")
        print(f"Pi-hole: {self.pihole_ip}")
        print("\nPress Ctrl+C to stop...")

        # Start DNS sniffing
        self.running = True
        self.start_dns_sniffing()

        try:
            while self.running:
                # Tell Roku we are the router
                if not self.spoof(self.roku_ip, self.router_ip, roku_mac):
                    print("Failed to spoof Roku")
                    break
                    
                # Tell router we are the Roku
                if not self.spoof(self.router_ip, self.roku_ip, router_mac):
                    print("Failed to spoof router")
                    break
                    
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nRestoring network settings...")
        finally:
            self.running = False
            # Restore ARP tables
            self.restore_arp(self.router_ip, self.roku_ip, router_mac, roku_mac)
            self.restore_arp(self.roku_ip, self.router_ip, roku_mac, router_mac)

def main():
    parser = argparse.ArgumentParser(description='Redirect Roku DNS queries to Pi-hole')
    parser.add_argument('--roku', required=True, help='Roku IP address')
    parser.add_argument('--router', help='Router IP address (will try to detect if not provided)')
    parser.add_argument('--pihole', default='192.168.50.66', help='Pi-hole IP address')
    
    args = parser.parse_args()
    
    if not args.router:
        # Try to get default gateway
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            args.router = '.'.join(local_ip.split('.')[:-1] + ['1'])
            print(f"Using router IP: {args.router}")
        except:
            print("Could not detect router IP. Please provide it with --router")
            return
    
    redirector = RokuPihole(args.roku, args.router, args.pihole)
    redirector.start()

if __name__ == "__main__":
    if os.name == 'nt':  # Windows
        print("Make sure you:")
        print("1. Have Npcap installed (https://npcap.com/)")
        print("2. Are running this script as Administrator")
    main()
