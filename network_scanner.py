import scapy.layers.l2 as scapy_l2
import scapy.packet as scapy_packet
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip_range", help="Target IP range for which to scan for connected clients.")
    options = parser.parse_args()[0]
    if not options.target_ip_range:
        parser.error("[-] Please specify a target IP range, use --help for more info.")
    return options


def scan(ip_address):
    arp_request = scapy_l2.ARP(pdst=ip_address)
    broadcast = scapy_l2.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy_l2.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac_address": element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


def print_result(results_list):
    answered_list_len = len(results_list)
    print(f"{answered_list_len} Captured ARP Req/Rep packets, from {answered_list_len} hosts.")
    print("______________________________________________")
    print("IP\t\t\tAt MAC Address")
    print("----------------------------------------------")
    for client in results_list:
        print(f"{client['ip']}\t\t{client['mac_address']}")


options = get_arguments()
scan_result = scan(options.target_ip_range)
print_result(scan_result)
