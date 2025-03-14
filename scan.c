#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#define TRAP_DESTINATION "192.168.0.140"
#define COMMUNITY "public"
#define OID ".1.3.6.1.4.1.8072.9999.1" // Custom OID
#define NETWORK_PREFIX "192.168.0."
#define INTERFACE "ens18" // Change to your network interface

volatile sig_atomic_t keep_running = 1;

// Handle Ctrl+C to exit gracefully
void handle_signal(int sig) {
    if (sig == SIGINT) {
        printf("\nTerminating program...\n");
        keep_running = 0;
    }
}

// Function to send SNMP trap
void send_snmp_trap(const char *message) {
    struct snmp_session session, *ss;
    snmp_sess_init(&session);
    session.peername = strdup(TRAP_DESTINATION);
    session.version = SNMP_VERSION_2c;
    session.community = (u_char *)strdup(COMMUNITY);
    session.community_len = strlen(COMMUNITY);

    // Open SNMP session
    ss = snmp_open(&session);
    if (!ss) {
        snmp_perror("SNMP session open failed");
        return;
    }
    printf("[DEBUG] SNMP session opened successfully.\n");

    // Convert OID
    oid anOID[MAX_OID_LEN];
    size_t anOID_len = MAX_OID_LEN;
    if (!read_objid(OID, anOID, &anOID_len)) {
        fprintf(stderr, "[ERROR] OID parsing failed: %s\n", OID);
        snmp_close(ss);
        return;
    }
    printf("[DEBUG] OID parsed successfully: %s\n", OID);

    // Create SNMP trap PDU
    netsnmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
    snmp_add_var(pdu, anOID, anOID_len, 's', message);

    // Send SNMP trap
    if (snmp_send(ss, pdu) == 0) {
        snmp_perror("[ERROR] SNMP send failed");
    } else {
        printf("[INFO] SNMP trap sent successfully for message: %s\n", message);
    }

    snmp_close(ss);
}

// Packet handler for sniffing ICMP requests
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + 14 + (ip_header->ip_hl * 4));

    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);

    // Check if it is an ICMP echo request (ping)
    if (icmp_header->type == ICMP_ECHO) {
        if (strncmp(src_ip, NETWORK_PREFIX, strlen(NETWORK_PREFIX)) == 0) {
            printf("[INFO] Ping detected from %s, sending SNMP trap...\n", src_ip);
            send_snmp_trap(src_ip);
        } else if (strcmp(src_ip, "192.168.0.140") == 0) {
            printf("[INFO] Ping detected from 192.168.0.140, sending SNMP trap...\n");
            send_snmp_trap(src_ip);
        }
    }
}

int main() {
    signal(SIGINT, handle_signal); // Handle Ctrl+C

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(INTERFACE, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "[ERROR] Could not open device %s: %s\n", INTERFACE, errbuf);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "icmp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "[ERROR] Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[ERROR] Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    printf("[INFO] Listening for ICMP ping requests on %s...\n", INTERFACE);
    while (keep_running) {
        pcap_dispatch(handle, 10, packet_handler, NULL);
    }

    pcap_close(handle);
    printf("[INFO] Program exited successfully.\n");
    return 0;
}
