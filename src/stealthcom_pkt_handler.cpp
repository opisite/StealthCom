#include <string.h>
#include <thread>
#include <chrono>

#include "stealthcom_pkt_handler.h"
#include "packet_rx_tx.h"
#include "utils.h"
#include "packet_queue.h"
#include "user_data.h"

static std::shared_ptr<PacketQueue> rx_queue;
static std::shared_ptr<PacketQueue> tx_queue;

void stealthcom_pkt_handler_init(std::shared_ptr<PacketQueue> rx, std::shared_ptr<PacketQueue> tx) {
    rx_queue = rx;
    tx_queue = tx;

    // TODO
}

void handle_packet(void *pkt) {
    // TODO
}

void user_advertise_thread() {
    const uint8_t *this_MAC = get_MAC();
    std::string this_user_ID = get_user_ID();
    uint8_t user_ID_len = static_cast<uint8_t>(this_user_ID.length());

    struct stealthcom_probe_extension ext;
    memcpy(ext.source_MAC, this_MAC, 6);
    strncpy(ext.user_ID, this_user_ID.c_str(), user_ID_len);

    static struct __attribute__((packed)) stealthcom_probe_request {
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