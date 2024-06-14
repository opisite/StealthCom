#include <string.h>
#include <thread>
#include <chrono>
#include <iostream>
#include <string>
#include <atomic>

#include "stealthcom_pkt_handler.h"
#include "packet_rx_tx.h"
#include "utils.h"
#include "packet_queue.h"
#include "user_data.h"
#include "user_registry.h"
#include "io_handler.h"

std::atomic<bool> advertise_stop_flag;

static std::shared_ptr<PacketQueue> rx_queue;
static std::shared_ptr<PacketQueue> tx_queue;

static void send_packet(stealthcom_L2_extension * ext) {
    static stealthcom_header hdr_template = {
        .frame_ctrl =               {0x40, 0x00},
        .duration_id =              {0x00, 0x00},
        .addr1 =                    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .addr2 =                    {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA},
        .addr3 =                    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .seq_ctrl =                 {0x00, 0x00},
        .SSID_params =              {0x00, 0x00},
        .supported_rate_params =    {0x00, 0x00},
    };

    int ext_len = (sizeof(stealthcom_L2_extension) - 1) + ext->payload_len;

    stealthcom_header *hdr = (stealthcom_header *)malloc(sizeof(stealthcom_header) + ext_len);

    memcpy(hdr, &hdr_template, sizeof(stealthcom_header));
    memcpy((uint8_t*)hdr + sizeof(stealthcom_header), ext, ext_len);

    std::unique_ptr<packet_wrapper> packet = std::make_unique<packet_wrapper>();

    packet->buf = hdr;
    packet->buf_len = sizeof(stealthcom_header) + sizeof(stealthcom_L2_extension) + ext->payload_len;

    tx_queue->push(std::move(packet));
}

static stealthcom_L2_extension * generate_ext(stealthcom_pkt_type type, uint8_t payload_len) {
    const uint8_t *this_MAC = get_MAC();
    std::string this_user_ID = get_user_ID();
    int user_ID_len = this_user_ID.length();

    struct stealthcom_L2_extension *ext = stealthcom_L2_extension::create(0);
    ext->type = type;
    memcpy(ext->source_MAC, this_MAC, 6);
    memset(ext->dest_mac, 0xFF, 6);
    strncpy(ext->user_ID, this_user_ID.c_str(), user_ID_len);
    ext->user_ID_len = user_ID_len;
    ext->payload_len = 0;

    return ext;
}

static stealthcom_L2_extension * generate_ext(stealthcom_pkt_type type, std::array<uint8_t, 6> dest_MAC, uint8_t payload_len) {
    const uint8_t *this_MAC = get_MAC();
    std::string this_user_ID = get_user_ID();
    int user_ID_len = this_user_ID.length();

    struct stealthcom_L2_extension *ext = stealthcom_L2_extension::create(0);
    ext->type = type;
    memcpy(ext->source_MAC, this_MAC, 6);
    memcpy(ext->dest_mac, dest_MAC.data(), 6);
    strncpy(ext->user_ID, this_user_ID.c_str(), user_ID_len);
    ext->user_ID_len = user_ID_len;
    ext->payload_len = 0;

    return ext;
}

static void handle_stealthcom_beacon(struct stealthcom_L2_extension *ext) {
    char user_ID_buf[USER_ID_MAX_LEN + 1];
    memcpy(user_ID_buf, ext->user_ID, ext->user_ID_len);
    user_ID_buf[ext->user_ID_len] = '\0';

    user_registry->add_or_update_entry(&ext->source_MAC[0], user_ID_buf);
}

static void handle_stealthcom_conn_request(struct stealthcom_L2_extension *ext) {
    char user_ID_buf[USER_ID_MAX_LEN + 1];
    memcpy(user_ID_buf, ext->user_ID, ext->user_ID_len);
    user_ID_buf[ext->user_ID_len] = '\0';
    std::string user_ID_str(user_ID_buf);

    system_push_msg("Connection request received from user [" + user_ID_str + "] with address [" + mac_addr_to_str(&ext->source_MAC[0]) + "]");
}

void stealthcom_pkt_handler_init(std::shared_ptr<PacketQueue> rx, std::shared_ptr<PacketQueue> tx) {
    rx_queue = rx;
    tx_queue = tx;

    advertise_stop_flag.store(false);
}

void packet_handler_thread() {
    while(true) {
        std::unique_ptr<packet_wrapper> pkt_wrapper = rx_queue->pop();
        int packet_len = pkt_wrapper->buf_len;
        stealthcom_header *hdr = (stealthcom_header *)pkt_wrapper->buf;
        stealthcom_L2_extension *ext = (stealthcom_L2_extension *)((uint8_t *)hdr + sizeof(stealthcom_header));

        if(is_self(&ext->source_MAC[0])) {
            continue;
        }

        stealthcom_pkt_type type = ext->type;

        switch(type) {
            case stealthcom_pkt_type::BEACON: {
                handle_stealthcom_beacon(ext);
                break;
            }
            case stealthcom_pkt_type::CONNECT_REQUEST: {
                handle_stealthcom_conn_request(ext);
                break;
            }
        }
    }
}

void send_conn_request(StealthcomUser *user) {
    std::array<uint8_t, 6> MAC = user->getMAC();
    system_push_msg("Sending connection request to user [" + user->getName() + "] with address [" + mac_addr_to_str(MAC.data()) + "]");

    stealthcom_L2_extension *ext = generate_ext(stealthcom_pkt_type::CONNECT_REQUEST, MAC, 0);

    send_packet(ext);
}

void set_advertise(int set) {
    if(set == 0) {
        advertise_stop_flag.store(true);
    } else {
        std::thread advertiseThread(user_advertise_thread);
        advertiseThread.detach();
    }
}

void user_advertise_thread() {
    stealthcom_L2_extension *ext = generate_ext(stealthcom_pkt_type::BEACON, 0);

    while(!advertise_stop_flag.load()) {
        send_packet(ext);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    advertise_stop_flag.store(false);
}
