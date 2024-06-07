#include <string.h>
#include <thread>
#include <chrono>
#include <iostream>
#include <string>

#include "stealthcom_pkt_handler.h"
#include "packet_rx_tx.h"
#include "utils.h"
#include "packet_queue.h"
#include "user_data.h"
#include "user_registry.h"
#include "io_handler.h"

static std::shared_ptr<PacketQueue> rx_queue;
static std::shared_ptr<PacketQueue> tx_queue;

static inline bool is_stealthcom_probe(const uint8_t *MAC) {
    for(int x = 0; x < 6; x++) {
        if(MAC[x] != 0xAA) {
            return false;
        }
    }
    return true;
}

static void handle_stealthcom_probe(void *buf) {
    struct stealthcom_probe_request *probe = (stealthcom_probe_request *)buf;
    struct stealthcom_probe_extension *probe_ext = &probe->probe_ext;

    char user_ID_buf[USER_ID_MAX_LEN + 1];
    memcpy(user_ID_buf, &probe_ext->user_ID, probe_ext->user_ID_len);
    user_ID_buf[probe_ext->user_ID_len] = '\0';

    user_registry->add_or_update_entry(&probe_ext->source_MAC[0], user_ID_buf);
}

void stealthcom_pkt_handler_init(std::shared_ptr<PacketQueue> rx, std::shared_ptr<PacketQueue> tx) {
    rx_queue = rx;
    tx_queue = tx;

    // TODO
}

void packet_handler_thread() {
    while(true) {
        std::unique_ptr<packet_wrapper> pkt_wrapper = rx_queue->pop();
        int packet_len = pkt_wrapper->buf_len;
        wifi_mac_hdr_t *mac_hdr = (wifi_mac_hdr_t *)pkt_wrapper->buf;
        
        if(mac_hdr->frame_ctrl[0] == 0x40) { // Probe request
            if(is_stealthcom_probe(&mac_hdr->addr1[0])) {
                handle_stealthcom_probe(mac_hdr);
            }
        }
    }
}

void user_advertise_thread() {
    const uint8_t *this_MAC = get_MAC();
    std::string this_user_ID = get_user_ID();
    int user_ID_len = this_user_ID.length();

    struct stealthcom_probe_extension ext;
    memcpy(ext.source_MAC, this_MAC, 6);
    strncpy(ext.user_ID, this_user_ID.c_str(), user_ID_len);
    ext.user_ID_len = user_ID_len;

    struct stealthcom_probe_request {
        uint8_t frame_ctrl[2];
        uint8_t duration_id[2];
        uint8_t addr1[6];
        uint8_t addr2[6];
        uint8_t addr3[6];
        uint8_t seq_ctrl[2];
        uint8_t SSID_params[2];
        uint8_t supported_rate_params[2];
        struct stealthcom_probe_extension probe_ext;
    } probe = {
        .frame_ctrl =               {0x40, 0x00},
        .duration_id =              {0x00, 0x00},
        .addr1 =                    {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA},
        .addr2 =                    {this_MAC[0], this_MAC[1], this_MAC[2], this_MAC[3], this_MAC[4], this_MAC[5]},
        .addr3 =                    {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA},
        .seq_ctrl =                 {0x00, 0x00},
        .SSID_params =              {0x00, 0x00},
        .supported_rate_params =    {0x00, 0x00},
        .probe_ext =                ext,
    };

    while(true) {
        auto packet = std::make_unique<packet_wrapper>();

        packet->buf = new char[sizeof(probe)];
        packet->buf_len = sizeof(probe);

        memcpy((void*)(packet->buf), &probe, sizeof(probe));

        tx_queue->push(std::move(packet));

        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
}
