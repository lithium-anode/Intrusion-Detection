#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/if_packet.h>

#define SNAP_LEN 65536
#define LOG_FILE "alerts.log"
#define MAX_TRACKED 1024

typedef struct {
    in_addr_t src_ip;
    time_t timestamps[20]; // store last 20 timestamps
    int count;
} SynTracker;

SynTracker syn_table[MAX_TRACKED];
int syn_table_size = 0;

volatile sig_atomic_t keep_running = 1;
FILE* log_file;

void handle_sigint(int sig) {
    // printf("\n[*] Caught signal %d, stopping capture...\n", sig);
    keep_running = 0;
}

void log_alert(const char* msg, uint32_t ip_addr) {
    struct in_addr src_ip;
    src_ip.s_addr = ip_addr;

    time_t now = time(NULL);
    char* time_str = strtok(ctime(&now), "\n");

    fprintf(log_file, "[%s] ALERT: %s - Source IP: %s\n", time_str, msg, inet_ntoa(src_ip));
    fflush(log_file);

    // printf("[!] ALERT: %s - Source IP: %s\n", msg, inet_ntoa(src_ip));
}

void track_syn_packet(in_addr_t src_ip) {
    time_t now = time(NULL);

    // Find existing tracker or create new
    SynTracker* tracker = NULL;
    for (int i = 0; i < syn_table_size; ++i) {
        if (syn_table[i].src_ip == src_ip) {
            tracker = &syn_table[i];
            break;
        }
    }

    if (!tracker) {
        if (syn_table_size >= MAX_TRACKED) return; // skip if full
        tracker = &syn_table[syn_table_size++];
        tracker->src_ip = src_ip;
        tracker->count = 0;
    }

    // Clean old timestamps (>5 seconds ago)
    int valid = 0;
    for (int i = 0; i < tracker->count; ++i) {
        if (now - tracker->timestamps[i] <= 5) {
            tracker->timestamps[valid++] = tracker->timestamps[i];
        }
    }

    // Add current timestamp
    tracker->timestamps[valid++] = now;
    tracker->count = valid;

    // Trigger alert if count threshold met
    if (tracker->count >= 10) {
        struct in_addr addr;
        addr.s_addr = src_ip;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        log_alert("ALERT: Possible SYN Scan Attempt!", src_ip);
        tracker->count = 0; // reset after alert
    }
}

void track_shellshock(unsigned char* payload, int payload_len, in_addr_t src_ip) {
    char* header_end = memmem(payload, payload_len, "\r\n\r\n", 4);
    size_t header_len = header_end ? (size_t)(header_end - (char*) payload) : payload_len;

    if (memmem(payload, header_len, "() { :;};", 9)) log_alert("ALERT: Possible Shellshock Exploit Attempt!", src_ip);
}

void track_xss(unsigned char* payload, in_addr_t src_ip) {
    if (strstr((char*) payload, "<script>alert(1)</script>")) log_alert("ALERT: Possible XSS Attempt", src_ip);
}

int main() {
    int sock;
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);
    unsigned char* buffer = (unsigned char*) malloc(SNAP_LEN);

    const char* iface = "eth0";

    signal(SIGINT, handle_sigint);

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void*) &ifr, sizeof(ifr)) < 0) {
        perror("Failed to bind to interface");
        close(sock);
        return 1;
    }

    log_file = fopen(LOG_FILE, "w");
    if (!log_file) {
        perror("Could not open log file");
        close(sock);
        return 1;
    }

    // printf("[*] Capturing packets on %s. Press Ctrl+C to stop...\n", iface);

    fd_set readfds;
    struct timeval timeout;

    while (keep_running) {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int sel = select(sock + 1, &readfds, NULL, NULL, &timeout);
        if (sel < 0) {
            if (errno == EINTR) continue;
            perror("select error");
            break;
        } else if (sel == 0) {
            continue;
        }

        if (FD_ISSET(sock, &readfds)) {
            int packet_size = recvfrom(sock, buffer, SNAP_LEN, 0, &saddr, &saddr_len);
            if (packet_size < 0) {
                if (errno == EINTR) continue;
                perror("Error receiving packet");
                break;
            }

            struct ethhdr *eth = (struct ethhdr *)buffer;
            if (ntohs(eth->h_proto) == ETH_P_IP) {
                struct iphdr* ip = (struct iphdr*) (buffer + sizeof(struct ethhdr));
                int ip_header_len = ip->ihl * 4;

                // check icmp flooding
                if ((ip->protocol == IPPROTO_ICMP) && (packet_size > 1500)) {
                    log_alert("ALERT: Possible ICMP Flooding Attempt!", ip->saddr);
                } else if (ip->protocol == IPPROTO_TCP) {
                    struct tcphdr* tcp = (struct tcphdr*) (buffer + sizeof(struct ethhdr) + ip_header_len);
                    int tcp_hdr_len = tcp->doff * 4;
                    int payload_offset = sizeof(struct ethhdr) + ip_header_len + tcp_hdr_len;
                    int payload_len = packet_size - payload_offset;
                    unsigned char* payload = buffer + payload_offset;

                    // check port syn scan
                    if (tcp->syn && !tcp->ack) {
                        track_syn_packet(ip->saddr);
                    }

                    // check port shellshock and xss
                    if (ntohs(tcp->dest) == 80 || ntohs(tcp->dest) == 8080) {
                        track_shellshock(payload, payload_len, ip->saddr);
                        track_xss(payload, ip->saddr);
                    }
                }
            }
        }
    }

    // printf("[*] Capture finished. Closing files...\n");
    fclose(log_file);
    close(sock);
    free(buffer);
    // printf("[*] Alerts saved to %s\n", LOG_FILE);
    return 0;
}