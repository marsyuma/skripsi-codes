#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#define TRAP_DESTINATION "192.168.0.140"
#define COMMUNITY "public"
#define OID ".1.3.6.1.4.1.8072.9999.1" // Custom OID

// List of domains to check
const char *domains[] = {
    "example.com",
    "google.com",
    "yahoo.com"
};

int check_connection(const char *hostname) {
    struct hostent *host;
    struct sockaddr_in addr;

    host = gethostbyname(hostname);
    if (!host) {
        return 0; // No connection
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    addr.sin_addr = *((struct in_addr *)host->h_addr);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return 0;
    }

    int connected = connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0;
    close(sock);
    return connected;
}

void send_snmp_trap(const char *message) {
    struct snmp_session session, *ss;
    snmp_sess_init(&session);
    session.peername = strdup(TRAP_DESTINATION);
    session.version = SNMP_VERSION_2c;
    session.community = (u_char *)strdup(COMMUNITY);
    session.community_len = strlen(COMMUNITY);

    ss = snmp_open(&session);
    if (!ss) {
        snmp_perror("snmp_open");
        return;
    }

    netsnmp_variable_list *var_list = NULL;
    snmp_varlist_add_variable(&var_list,
                              oid_str2oid(OID),
                              OID_LENGTH(oid_str2oid(OID)),
                              ASN_OCTET_STR,
                              (u_char *)message, strlen(message));

    send_v2trap(var_list);
    snmp_free_varbind(var_list);
    snmp_close(ss);
}

int main() {
    for (int i = 0; i < sizeof(domains) / sizeof(domains[0]); i++) {
        if (check_connection(domains[i])) {
            printf("Connection detected to %s, sending SNMP trap...\n", domains[i]);
            send_snmp_trap(domains[i]);
        }
    }
    return 0;
}
