#ifndef PACKET_RX_TX_H
#define PACKET_RX_TX_H

#include "thread_safe_queue.h"

struct packet_wrapper {
    void *buf;
    int buf_len;

    ~packet_wrapper() {
        free(buf);
    }
};

using PacketQueue = ThreadSafeQueue<std::unique_ptr<packet_wrapper>>;

typedef struct {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __attribute__((packed)) radiotap_header_t;

typedef struct {
    uint8_t frame_ctrl[2];
    uint8_t duration_id[2];
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint8_t seq_ctrl[2];
} __attribute__((packed)) wifi_mac_hdr_t;

void packet_capture_wrapper();
void packet_rx(void *buffer, int buffer_len);
void packet_tx();
bool packet_rx_tx_init(const char *device, std::shared_ptr<PacketQueue> rx, std::shared_ptr<PacketQueue> tx);

#endif
