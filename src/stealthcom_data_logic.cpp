#include <vector>
#include <mutex>
#include <chrono>
#include <ctime>
#include <cstring>
#include <memory>
#include "packet_rx_tx.h"
#include "stealthcom_data_logic.h"
#include "stealthcom_state_machine.h"
#include "stealthcom_pkt_handler.h"

using MessageQueue = ThreadSafeQueue<std::unique_ptr<Message>>;

std::vector<Message> messages;
std::mutex messages_mtx;

static inline std::time_t get_current_time() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::system_clock::to_time_t(now);
}

void send_message(const std::string& input) {
    static uint32_t sequence_num = 0;
    uint8_t input_len = input.size() - 1;

    std::unique_ptr<Message> msg = std::make_unique<Message>(input_len);
    msg->timestamp = get_current_time();
    msg->delivered = false;
    msg->outbound = true;
    msg->sequence_num = sequence_num++;
    msg->msg_len = input_len;
    std::memcpy(msg->payload, input.c_str(), input_len);

    ConnectionContext context = state_machine->get_connection_context();

    
    //stealthcom_L2_extension * ext = generate_ext(DATA | DATA_PAYLOAD, this);
}

