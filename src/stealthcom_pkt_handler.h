#ifndef STEALTHCOM_PKT_HANDLER_H
#define STEALTHCOM_PKT_HANDLER_H

#include <cstdint>
#include <memory>

#include "packet_rx_tx.h"
#include "stealthcom_logic.h"

#define EXT_TYPE_BIT_SHIFT  4
#define EXT_TYPE_BITMASK    0xF0
#define EXT_SUBTYPE_BITMASK 0x0F

// TYPE ENUMERATION
#define BEACON  0 << EXT_TYPE_BIT_SHIFT
#define CONNECT 1 << EXT_TYPE_BIT_SHIFT
#define DATA    2 << EXT_TYPE_BIT_SHIFT

// CONNECT SUBTYPE ENUMERATION
#define REQUEST    0
#define ACCEPT     1
#define REFUSE     2
#define ACCEPT_ACK 3
#define DISCONNECT 4

// DATA SUBTYPE ENUMERATION
#define DATA_PAYLOAD 0
#define DATA_ACK     1


typedef uint8_t sc_pkt_type_t;

struct __attribute__((packed)) stealthcom_L2_extension {
    sc_pkt_type_t type;
    uint8_t source_MAC[6];
    uint8_t dest_MAC[6];
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


    stealthcom_L2_extension(uint8_t payload_size) : payload_len(payload_size) {}
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
stealthcom_L2_extension * generate_ext(sc_pkt_type_t type, std::array<uint8_t, 6> dest_MAC);
stealthcom_L2_extension * generate_ext(sc_pkt_type_t type, std::array<uint8_t, 6> dest_MAC, uint8_t payload_len, const char *payload);
stealthcom_L2_extension * generate_ext(sc_pkt_type_t type);
void send_packet(stealthcom_L2_extension * ext);



#endif
