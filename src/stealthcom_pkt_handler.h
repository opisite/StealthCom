#ifndef STEALTHCOM_PKT_HANDLER_H
#define STEALTHCOM_PKT_HANDLER_H

#include <cstdint>
#include <memory>

#include "packet_queue.h"
#include "stealthcom_logic.h"

enum class stealthcom_pkt_type : uint8_t {
    PROBE = 0,
    CONNECT_REQUEST,
    KEY_EXCHANGE,
};

struct __attribute__((packed)) stealthcom_L2_extension {
    stealthcom_pkt_type type;
    uint8_t source_MAC[6];
    uint8_t user_ID_len;
    char user_ID[USER_ID_MAX_LEN];
    uint8_t payload; // Variable length of data
};

struct __attribute__((packed)) stealthcom_header {
    uint8_t frame_ctrl[2];
    uint8_t duration_id[2];
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint8_t seq_ctrl[2];
    uint8_t SSID_params[2];
    uint8_t supported_rate_params[2];
    struct stealthcom_L2_extension ext;
};

void user_advertise_thread();
void packet_handler_thread();
void stealthcom_pkt_handler_init(std::shared_ptr<PacketQueue> rx, std::shared_ptr<PacketQueue> tx);
void set_advertise(int set);
void send_conn_request(StealthcomUser *user);

#endif