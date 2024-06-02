#include <string.h>
#include <thread>
#include <chrono>

#include "stealthcom_pkt_handler.h"
#include "packet_rx_tx.h"
#include "utils.h"
#include "packet_queue.h"

void handle_packet(const stealthcom_header_t *pkt) {
    // TODO
}


void user_advertise_thread() {
    static struct __attribute__((packed)) stealthcom_probe_request_t {
        uint8_t frame_ctrl[2];
        uint8_t duration_id[2];
        uint8_t addr1[6];
        uint8_t addr2[6];
        uint8_t addr3[6];
        uint8_t seq_ctrl[2];
        uint8_t SSID_params[2];
        uint8_t supported_rate_params[2];
    } stealthcom_probe_request = {
        .frame_ctrl =               {0x40, 0x00},
        .duration_id =              {0x00, 0x00},
        .addr1 =                    {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA},
        .addr2 =                    {this_MAC[0], this_MAC[1], this_MAC[2], this_MAC[3], this_MAC[4], this_MAC[5]},
        .addr3 =                    {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA},
        .seq_ctrl =                 {0x00, 0x00},
        .SSID_params =              {0x00, 0x00},
        .supported_rate_params =    {0x00, 0x00},
    };

    while(true) {
        auto packet = std::make_unique<packet_wrapper>();

        packet->buf = new char[sizeof(stealthcom_probe_request)];
        packet->buf_len = sizeof(stealthcom_probe_request);

        memcpy((void*)(packet->buf), &stealthcom_probe_request, sizeof(stealthcom_probe_request));

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            destQueue.push(std::move(packet));
            queueCV.notify_one();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
}