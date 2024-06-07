#ifndef STEALTHCOM_PKT_HANDLER_H
#define STEALTHCOM_PKT_HANDLER_H

#include <cstdint>
#include <memory>

#include "packet_queue.h"
#include "stealthcom_logic.h"

struct __attribute__((packed)) stealthcom_probe_extension {
    uint8_t source_MAC[6];
    uint8_t user_ID_len;
    char user_ID[USER_ID_MAX_LEN];
};

void user_advertise_thread();

void handle_packet(void *pkt);
void stealthcom_pkt_handler_init(std::shared_ptr<PacketQueue> rx, std::shared_ptr<PacketQueue> tx);

#endif