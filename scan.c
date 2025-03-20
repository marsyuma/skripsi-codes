#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define VM_140_IP "192.168.1.140"  // Change to actual IP of VM 140
#define SNMP_TRAP_CMD "snmptrap -v 2c -c public 192.168.1.1 '' 1.3.6.1.4.1.8072.2.3.0.1"

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Ethernet header is 14 bytes
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + 14 + (ip_header->ip_hl * 4));

    // Check if the packet is ICMP and from VM 140
    if (ip_header->ip_p == IPPROTO_ICMP && icmp_header->type == ICMP_ECHO) {
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);

        if (strcmp(src_ip, VM_140_IP) == 0) {
            printf("Ping detected from VM 140 (%s). Sending SNMP trap...\n", src_ip);
            system(SNMP_TRAP_CMD); // Send SNMP trap
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the network interface for packet capture
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }

    // Capture only ICMP packets
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "icmp", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not set filter\n");
        return 1;
    }

    printf("Listening for ICMP packets...\n");
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
