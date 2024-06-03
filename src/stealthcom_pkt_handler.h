#ifndef STEALTHCOM_PKT_HANDLER_H
#define STEALTHCOM_PKT_HANDLER_H

#include <cstdint>
#include <memory>

#include "packet_queue.h"

typedef struct {
    uint8_t type;
    uint8_t source_MAC[6];
    uint8_t dest_MAC[6];
    char user_id[16];
    char payload[64];
} __attribute__((packed)) stealthcom_header_t;

void user_advertise_thread();

void handle_packet(const stealthcom_header_t *pkt);
void stealthcom_pkt_handler_init(std::shared_ptr<PacketQueue> rx, std::shared_ptr<PacketQueue> tx);

#endif