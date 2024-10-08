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

/**
 * @brief Check if a packet is a stealthcom packet (source MAC is AA:AA:AA:AA:AA:AA)
 * 
 * @param hdr the MAC header to check
 * @return true if the packet is a stealthcom packet
 * @return false if the packet is not a stealthcom packet
 */
static inline bool is_stealthcom_packet(const wifi_mac_hdr_t *hdr) {
    for(int x = 0; x < 6; x++) {
        if(hdr->addr2[x] != 0xAA) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Append a radiotap header at the beginning of the packet to be sent by packet_tx thread
 * 
 * @param buf the packet to append the header to
 * @param buf_len the length of buf
 * @param final_packet_size the length of the new buffer
 * @return const u_char* A pointer to a new buffer with containing the original packet with the radiotap header appended at the start
 */
static const u_char * append_radiotap_header(void *buf, int buf_len, int *final_packet_size) {
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

/**
 * @brief (thread) Open a raw socket, then send give all received packets to packet_rx
 * 
 */
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

/**
 * @brief Handle all packets received via netif
 * 
 * @param buffer incoming packet buffer
 * @param buffer_len length of buf
 */
void packet_rx(void *buffer, int buffer_len) {
    radiotap_header_t *radiotap_header = (radiotap_header_t *)buffer;
    wifi_mac_hdr_t *mac_hdr = (wifi_mac_hdr_t *)((uint8_t *)buffer + radiotap_header->it_len);

    if(!is_stealthcom_packet(mac_hdr)) {
        return;
    }

    int final_packet_size = buffer_len - radiotap_header->it_len;

    auto pkt_wrapper = std::make_unique<packet_wrapper>();
    pkt_wrapper->buf = new uint8_t[final_packet_size];
    pkt_wrapper->buf_len = final_packet_size;

    memcpy(pkt_wrapper->buf, mac_hdr, final_packet_size);

    rx_queue->push(std::move(pkt_wrapper));
    
}

/**
 * @brief (thread) Transmit packets in the tx_queue
 * 
 */
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
        }
    }

    pcap_close(handle);
}

/**
 * @brief Initialize rx_queue, tx_queue, and retrieve MAC address of the network interface controller from the system
 * 
 * @param device the network interface to use for the duration of the program
 * @param rx packet queue for packets to be transmitted
 * @param tx packet queue for received packets
 * @return true if the initialization was successful
 * @return false if the initalization was not successful
 */
bool packet_rx_tx_init(const char *device, std::shared_ptr<PacketQueue> rx, std::shared_ptr<PacketQueue> tx) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        return false;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);

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
