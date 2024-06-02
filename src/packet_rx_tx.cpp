#include <stdlib.h>
#include <stdio.h>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <unistd.h>
#include <iomanip>
#include <pcap.h>
#include <string>
#include <chrono>
#include <thread>
#include <sys/ioctl.h>

#include "packet_rx_tx.h"
#include "stealthcom_pkt_handler.h"
#include "input_handler.h"
#include "utils.h"
#include "packet_queue.h"

std::mutex queueMutex;
std::condition_variable queueCV;
std::queue<std::unique_ptr<struct packet_wrapper>> destQueue;

const uint8_t *this_MAC;
const char *netif;

static inline bool is_own_mac(const uint8_t *MAC) {
    for(int x = 0; x < 6; x++) {
        if(MAC[x] != this_MAC[x]) {
            return false;
        }
    }
    return true;
}

static inline bool is_stealthcom_probe(const uint8_t *MAC) {
    for(int x = 0; x < 6; x++) {
        if(MAC[x] != 0xAA) {
            return false;
        }
    }
    return true;
}

void packet_capture_wrapper() {
    int sockfd;
    char buffer[ETH_FRAME_LEN];
    struct ifreq ifr;
    struct sockaddr_ll sll;

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, netif, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        return;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sockfd);
        return;
    }

    while (true) {
        ssize_t numbytes = recvfrom(sockfd, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
        if (numbytes < 0) {
            perror("recvfrom");
            break;
        }

        packet_rx(buffer, numbytes);
    }

    close(sockfd);
}

void packet_rx(void *buffer, int buffer_len) {
    radiotap_header_t *radiotap_header = (radiotap_header_t *)buffer;
    wifi_mac_hdr_t *mac_hdr = (wifi_mac_hdr_t *)((uint8_t *)buffer + radiotap_header->it_len);

    if(mac_hdr->frame_ctrl[0] == 0x40) {
        if(is_stealthcom_probe(&mac_hdr->addr1[0])) {
            std::cout << "PROBE RECEIVED" << std::endl;
        }
    }
}

void packet_tx() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(netif, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "pcap_open_live() failed: " << errbuf << std::endl;
        return;
    }

    while(true) {
        std::unique_ptr<packet_wrapper> packet;

        {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCV.wait(lock, [] { return !destQueue.empty();});

            if (!destQueue.empty()) {
                packet = std::move(destQueue.front());
                destQueue.pop();
            } else {
                continue;
            }
        }

        if (packet && pcap_sendpacket(handle, (const u_char*)packet->buf, packet->buf_len) != 0) {
            std::cerr << "Error sending packet: " << pcap_geterr(handle) << std::endl;
        } else if (packet) {
            std::cout << "Packet sent successfully!" << std::endl;
        }
    }

    pcap_close(handle);
}

bool set_sys_info(const char *device) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        return false;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, device, IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        return false;
    }

    close(fd);

    this_MAC = (uint8_t *)malloc(6);
    memcpy((void*)&this_MAC[0], ifr.ifr_hwaddr.sa_data, 6);
    netif = device;

    return true; // TODO: return false if device doesnt exist as a network interface
}
