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
#include "data_registry.h"
#include "io_handler.h"


static MessageQueue *outbound_message_queue;
static std::shared_ptr<PacketQueue> inbound_packet_queue;
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

static void send_data_ack(const uint32_t seq_num) {
    ConnectionContext context = state_machine->get_connection_context();
    StealthcomUser *user = context.user;
    stealthcom_L2_extension *ext = generate_ext(DATA | DATA_ACK, user->getMAC(), sizeof(seq_num), (const char *)&seq_num);

    send_packet(ext);
}

static void handle_data_ack(stealthcom_L2_extension *ext) {
    system_push_msg("DATA ACK");
    uint32_t *ack_num = (uint32_t *)ext->payload;

    if(data_registry->entry_exists(*ack_num)) {
        uint32_t seq_num = *ack_num;
        outbound_messages[seq_num].status = MessageStatus::DELIVERED;
    }
}

static void handle_data(stealthcom_L2_extension *ext) {
    system_push_msg("DATA");
    Message *msg = (Message *)ext->payload;

    send_data_ack(msg->sequence_num);

    inbound_messages.push_back(*msg);
}

static void handle_data_thread() {
    while(true) {
        std::unique_ptr<packet_wrapper> ext_wrapper = inbound_packet_queue->pop();
        stealthcom_L2_extension *ext = (stealthcom_L2_extension *)ext_wrapper->buf;

        sc_pkt_type_t subtype = ext->type & EXT_SUBTYPE_BITMASK;

        if(subtype == DATA_ACK) {
            handle_data_ack(ext);
        } else if(subtype == DATA) {
            handle_data(ext);
        }
    }
}

void resend_message(uint32_t seq_number) {
    send_message(outbound_messages[seq_number].msg);
}

void send_message(const Message *msg) {
    ConnectionContext context = state_machine->get_connection_context();
    StealthcomUser *user = context.user;
    uint8_t msg_size = (sizeof(Message) - 1) + msg->msg_len;

    stealthcom_L2_extension *ext = generate_ext(DATA | DATA_PAYLOAD, user->getMAC(), msg_size, (const char *)msg);
    send_packet(ext);
}

void data_worker_init(std::shared_ptr<PacketQueue> inbound_queue) {
    outbound_message_queue = new MessageQueue();
    inbound_packet_queue = inbound_queue;

    std::thread DeliverMessagesThread(deliver_messages_thread);
    DeliverMessagesThread.detach();
    std::thread HandleDataThread(handle_data_thread);
    HandleDataThread.detach();
}

void data_logic_reset() {
    sequence_number = 0;
}

void create_message(const std::string& input) {
    uint8_t input_len = input.size() - 1;

    Message *msg = Message::create(input_len);
    msg->timestamp = get_current_time();
    msg->sequence_num = sequence_number++;
    msg->msg_len = input_len;
    std::memcpy(msg->payload, input.c_str(), input_len);

    outbound_message_queue->push(msg);
}
