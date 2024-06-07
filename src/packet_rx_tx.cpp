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
#include "io_handler.h"
#include "utils.h"
#include "user_data.h"

static std::shared_ptr<PacketQueue> rx_queue;
static std::shared_ptr<PacketQueue> tx_queue;

const char *netif;

static inline bool is_stealthcom_probe(const uint8_t *MAC) {
    for(int x = 0; x < 6; x++) {
        if(MAC[x] != 0xAA) {
            return false;
        }
    }
    return true;
}

static const u_char * append_radiotap_header(const char *buf, int buf_len, int *final_packet_size) {
    static const radiotap_header_t default_radiotap_header = {
        .it_version = 0,
        .it_pad = 0,
        .it_len = sizeof(radiotap_header_t),
        .it_present = 0
    };

    *final_packet_size = buf_len + sizeof(radiotap_header_t);
    u_char* new_buf = new u_char[*final_packet_size];

    memcpy(new_buf, &default_radiotap_header, sizeof(radiotap_header_t));
    memcpy(new_buf + sizeof(radiotap_header_t), buf, buf_len);

    return new_buf;
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
        //    output_push_msg("Probe received");
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

    while (true) {
        auto raw_packet = tx_queue->pop();
        int final_packet_size;
        const u_char *final_packet = append_radiotap_header(raw_packet->buf, raw_packet->buf_len, &final_packet_size);
        if (final_packet && pcap_sendpacket(handle, final_packet, final_packet_size) != 0) {
            std::cerr << "Error sending packet: " << pcap_geterr(handle) << std::endl;
        } else if (final_packet) {
        //    output_push_msg("Packet sent successfully");
        }
    }

    pcap_close(handle);
}

bool packet_rx_tx_init(const char *device, std::shared_ptr<PacketQueue> rx, std::shared_ptr<PacketQueue> tx) {
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

    set_MAC((uint8_t *)ifr.ifr_hwaddr.sa_data);
    netif = device;

    rx_queue = rx;
    tx_queue = tx;

    return true;
}
