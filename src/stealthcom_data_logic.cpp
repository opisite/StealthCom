#include <vector>
#include <mutex>
#include <chrono>
#include <ctime>
#include <cstring>
#include <memory>
#include <thread>
#include "packet_rx_tx.h"
#include "stealthcom_data_logic.h"
#include "stealthcom_state_machine.h"
#include "stealthcom_pkt_handler.h"
#include "data_registry.h"

using MessageQueue = ThreadSafeQueue<const Message*>;

std::mutex messages_mtx;
static MessageQueue *outbound_message_queue;
static MessageQueue *inbound_message_queue;
static std::vector<MessageWrapper> outbound_messages;
static std::vector<Message> inbound_messages;
static uint32_t sequence_number = 0;

static inline std::time_t get_current_time() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::system_clock::to_time_t(now);
}

static void deliver_messages_thread() {
    while(true) {
        const Message *msg = outbound_message_queue->pop();

        MessageWrapper wrapper;
        wrapper.status = MessageStatus::NOT_DELIVERED;
        wrapper.msg = msg;
        outbound_messages.push_back(wrapper);

        data_registry->add_entry(msg->sequence_num);
        send_message(msg);
    }
}

void resend_message(uint32_t seq_number) {
    send_message(outbound_messages[seq_number].msg);
}

void send_message(const Message *msg) {
    ConnectionContext context = state_machine->get_connection_context();
    StealthcomUser *user = context.user;
    uint8_t msg_size = (sizeof(Message) - 1) + msg->msg_len;

    stealthcom_L2_extension *ext = generate_ext(DATA | DATA_PAYLOAD, user->getMAC(), msg_size, (const char *)ext);
    send_packet(ext);
}

void data_logic_init() {
    outbound_message_queue = new MessageQueue();
    inbound_message_queue = new MessageQueue();

    std::thread DeliverMessagesThread(deliver_messages_thread);
    DeliverMessagesThread.detach();
}

void data_logic_reset() {
    sequence_number = 0;
}

void create_message(const std::string& input) {
    uint8_t input_len = input.size() - 1;

    Message* msg = Message::create(input_len);
    msg->timestamp = get_current_time();
    msg->sequence_num = sequence_number++;
    msg->msg_len = input_len;
    std::memcpy(msg->payload, input.c_str(), input_len);

    outbound_message_queue->push(msg);
}
