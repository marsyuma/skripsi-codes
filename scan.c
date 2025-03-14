#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#define TRAP_DESTINATION "192.168.0.140"
#define COMMUNITY "public"
#define OID ".1.3.6.1.4.1.8072.9999.1" // Custom OID
#define CHECK_INTERVAL 3 // Time in seconds to check connections

// List of domains to check
const char *domains[] = {
    "example.com",
    "google.com",
    "yahoo.com"
};

volatile sig_atomic_t keep_running = 1; // Flag to control loop execution

void handle_signal(int sig) {
    if (sig == SIGINT) {  // Catch Ctrl+C
        printf("\nTerminating program...\n");
        keep_running = 0;
    }
}

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

    oid anOID[MAX_OID_LEN];
    size_t anOID_len = MAX_OID_LEN;
    if (!read_objid(OID, anOID, &anOID_len)) {
        fprintf(stderr, "Error parsing OID\n");
        return;
    }

    netsnmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
    snmp_add_var(pdu, anOID, anOID_len, 's', message);
    
    if (snmp_send(ss, pdu) == 0) {
        snmp_perror("snmp_send");
    }

    snmp_close(ss);
}

int main() {
    signal(SIGINT, handle_signal); // Handle Ctrl+C

    while (keep_running) {
        for (int i = 0; i < sizeof(domains) / sizeof(domains[0]); i++) {
            if (check_connection(domains[i])) {
                printf("Connection detected to %s, sending SNMP trap...\n", domains[i]);
                send_snmp_trap(domains[i]);
            } else {
                printf("No connection to %s\n", domains[i]);
            }
        }
        sleep(CHECK_INTERVAL); // Wait before the next check
    }

    printf("Program exited successfully.\n");
    return 0;
}
