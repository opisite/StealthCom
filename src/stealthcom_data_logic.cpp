#include <vector>
#include <algorithm>
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

static std::mutex msg_mutex;
static MessageQueue *outbound_message_queue;
static std::shared_ptr<PacketQueue> data_pkt_queue;
static std::vector<MessageWrapper> outbound_messages;
static std::vector<const Message*> inbound_messages;
static sequence_num_t sequence_number = 0;

static inline uint64_t get_current_time() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::seconds>(duration).count();
}

static bool compare_msg_sequence(const Message* a, const Message* b) {
    return a->sequence_num < b->sequence_num;
}

static void deliver_messages_thread() {
    while(true) {
        const Message *msg = outbound_message_queue->pop();

        MessageWrapper wrapper;
        wrapper.status = MessageStatus::NOT_DELIVERED;
        wrapper.msg = msg;

        {
            std::lock_guard<std::mutex> lock(msg_mutex);
            outbound_messages.push_back(wrapper);
        }
        display_messages();

        data_registry->add_entry(msg->sequence_num);
        send_message(msg);
    }
}

static void send_data_ack(const sequence_num_t seq_num) {
    ConnectionContext context = state_machine->get_connection_context();
    StealthcomUser *user = context.user;
    stealthcom_L2_extension *ext = generate_ext(DATA | DATA_ACK, user->getMAC(), sizeof(seq_num), (const char *)&seq_num);

    send_packet(ext);
}

static void handle_data_ack(stealthcom_L2_extension *ext) {
    sequence_num_t *ack_num = (sequence_num_t *)ext->payload;
    if(data_registry->entry_exists(*ack_num)) {
        sequence_num_t seq_num = *ack_num;
        system_push_msg("Message sent, seq num: " + std::to_string(seq_num));
        data_registry->remove_entry(seq_num);
        {
            std::lock_guard<std::mutex> lock(msg_mutex);
            outbound_messages[seq_num].status = MessageStatus::DELIVERED;
        }
        display_messages();
    }
}

static void handle_data(stealthcom_L2_extension *ext) {
    Message *msg = (Message *)ext->payload;
    send_data_ack(msg->sequence_num);
    system_push_msg("Message Received, seq num: " + std::to_string(msg->sequence_num));

    if(data_registry->data_received(msg->sequence_num)) {
        return;
    }
    data_registry->register_incoming_data(msg->sequence_num);

    uint8_t msg_size = (sizeof(Message) - 1) + msg->msg_len;
    Message *msg_c = (Message *)malloc(msg_size);
    memcpy(msg_c, msg, msg_size);

    msg_c->timestamp = get_current_time();
    {
        std::lock_guard<std::mutex> lock(msg_mutex);
        inbound_messages.push_back(msg_c);
        sort(inbound_messages.begin(), inbound_messages.end(), compare_msg_sequence);
    }
    display_messages();
}

static void handle_data_thread() {
    while(true) {
        std::unique_ptr<packet_wrapper> ext_wrapper = data_pkt_queue->pop();
        stealthcom_L2_extension *ext = (stealthcom_L2_extension *)ext_wrapper->buf;
        sc_pkt_type_t subtype = ext->type & EXT_SUBTYPE_BITMASK;

        if(subtype == DATA_ACK) {
            handle_data_ack(ext);
        } else if(subtype == DATA_PAYLOAD) {
            handle_data(ext);
        }
    }
}

void resend_message(sequence_num_t seq_number) {
    send_message(outbound_messages[seq_number].msg);
}

void send_message(const Message *msg) {
    ConnectionContext context = state_machine->get_connection_context();
    StealthcomUser *user = context.user;
    uint16_t msg_size = (sizeof(Message) - 1) + msg->msg_len;

    stealthcom_L2_extension *ext = generate_ext(DATA | DATA_PAYLOAD, user->getMAC(), msg_size, (const char *)msg);
    send_packet(ext);
}

void data_worker_init(std::shared_ptr<PacketQueue> inbound_queue) {
    outbound_message_queue = new MessageQueue();
    data_pkt_queue = inbound_queue;

    std::thread DeliverMessagesThread(deliver_messages_thread);
    DeliverMessagesThread.detach();
    std::thread HandleDataThread(handle_data_thread);
    HandleDataThread.detach();
}

void data_logic_reset() {
    sequence_number = 0;
}

void create_message(const std::string& input) {
    uint8_t input_len = input.size() + 1; // Including space for a null character

    Message *msg = Message::create(input_len);
    msg->timestamp = get_current_time();
    msg->sequence_num = sequence_number++;
    msg->msg_len = input_len;
    std::memcpy(msg->payload, input.c_str(), input_len);

    outbound_message_queue->push(msg);
}

void notify_send_fail(sequence_num_t seq_num) {
    {
        std::lock_guard<std::mutex> lock(msg_mutex);
        outbound_messages[seq_num].status = MessageStatus::FAILED;
    }
    display_messages();
}

static void print_inbound_msg(const Message *msg) {
    StealthcomUser *user = state_machine->get_connection_context().user;
    main_push_msg(user->getName() + ": " + std::string(msg->payload));
}

static void print_outbound_msg(const MessageWrapper msg) {
    std::string status_str;
    switch (msg.status) {
        case MessageStatus::NOT_DELIVERED: {
            status_str = "[N]";
            break;
        }
        case MessageStatus::DELIVERED: {
            status_str = "[D]";
            break;
        }
        case MessageStatus::FAILED: {
            status_str = "[F]";
            break;
        }
    }

    main_push_msg(status_str + " - " + std::string(msg.msg->payload));
}


void display_messages() {
    if(state_machine->get_state() != CHAT) {
        return;
    }

    io_clr_output();

    std::lock_guard<std::mutex> lock(msg_mutex);
    int inbound_index = 0;
    int outbound_index = 0;

    while(true) {
        if(inbound_index < inbound_messages.size() && outbound_index < outbound_messages.size()) {
            if(inbound_messages[inbound_index]->timestamp < outbound_messages[outbound_index].msg->timestamp) {
                print_inbound_msg(inbound_messages[inbound_index]);
                inbound_index++;
            } else {
                print_outbound_msg(outbound_messages[outbound_index]);
                outbound_index++;
            }
        } else if(inbound_index < inbound_messages.size()) {
            print_inbound_msg(inbound_messages[inbound_index]);
            inbound_index++;
        } else if(outbound_index < outbound_messages.size()) {
            print_outbound_msg(outbound_messages[outbound_index]);
            outbound_index++;
        } else {
            break;
        }
    }
}
