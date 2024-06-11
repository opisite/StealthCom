#ifndef STEALTHCOM_PKT_HANDLER_H
#define STEALTHCOM_PKT_HANDLER_H

#include <cstdint>
#include <memory>

#include "packet_queue.h"
#include "stealthcom_logic.h"

enum class stealthcom_pkt_type : uint8_t {
    BEACON = 0,
    CONNECT_REQUEST,
    KEY_EXCHANGE,
};

struct __attribute__((packed)) stealthcom_L2_extension {
    stealthcom_pkt_type type;
    uint8_t source_MAC[6];
    uint8_t dest_mac[6];
    uint8_t user_ID_len;
    char user_ID[USER_ID_MAX_LEN];
    uint8_t payload_len;
    uint8_t payload[1]; // Variable length of data

    static stealthcom_L2_extension * create(uint8_t payload_len) {
        void* mem = std::malloc(sizeof(stealthcom_L2_extension) + payload_len - 1);
        if (!mem) {
            throw std::bad_alloc();
        }
        return new (mem) stealthcom_L2_extension(payload_len);
    }


    stealthcom_L2_extension(uint8_t payload_size) : payload_len(payload_len) {}
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
};

void user_advertise_thread();
void packet_handler_thread();
void stealthcom_pkt_handler_init(std::shared_ptr<PacketQueue> rx, std::shared_ptr<PacketQueue> tx);
void set_advertise(int set);
void send_conn_request(StealthcomUser *user);

#endif
