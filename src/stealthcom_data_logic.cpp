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
#include "crypto.h"

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

/**
 * @brief A comparator to check the order of 2 messages (by sequence number)
 * 
 * @param a message a
 * @param b message b
 * @return true if a came before b
 * @return false if b came before a
 */
static bool compare_msg_sequence(const Message* a, const Message* b) {
    return a->sequence_num < b->sequence_num;
}

/**
 * @brief (thread) deliver all messages in the outbound_message_queue
 * 
 */
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

/**
 * @brief Send an ACK for an incoming message
 * 
 * @param seq_num the sequence number of the incoming message
 */
static void send_data_ack(const sequence_num_t seq_num) {
    ConnectionContext context = state_machine->get_connection_context();
    StealthcomUser *user = context.user;
    stealthcom_L2_extension *ext = generate_ext(DATA | DATA_ACK, user->getMAC(), sizeof(seq_num), (const char *)&seq_num);

    send_packet(ext);
}

/**
 * @brief handle an incoming ACK
 * 
 * @param ext the extension containing the sequence number that is being ACK'ed
 */
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

/**
 * @brief Handle and incoming data packet
 * 
 * @param ext the extention containing the data
 */
static void handle_data(stealthcom_L2_extension *ext) {
    unsigned char *encrypted_msg = ext->payload;
    uint16_t decrypted_msg_size;
    Message *msg = (Message *)decrypt(encrypted_msg, ext->payload_len, decrypted_msg_size);

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

/**
 * @brief handle all incoming packets with type DATA
 * 
 */
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

/**
 * @brief Resend a message with a particular sequence number
 * 
 * @param seq_number the sequence number of the packet to resend
 */
void resend_message(sequence_num_t seq_number) {
    send_message(outbound_messages[seq_number].msg);
}

/**
 * @brief generate a stealthcom_L2_extension with a message appended to the end and send it as a packet
 * 
 * @param msg the message to send
 */
void send_message(const Message *msg) {
    ConnectionContext context = state_machine->get_connection_context();
    StealthcomUser *user = context.user;

    uint16_t msg_size = (sizeof(Message) - 1) + msg->msg_len;
    uint16_t encrypted_msg_size;
    void *encrypted_msg = encrypt((const unsigned char *)msg, msg_size, encrypted_msg_size);

    stealthcom_L2_extension *ext = generate_ext(DATA | DATA_PAYLOAD, user->getMAC(), encrypted_msg_size, (const char *)encrypted_msg);
    send_packet(ext);
}

/**
 * @brief Initialize the threads needed to send and receive data as well as the shared resources needed by them
 * 
 * @param inbound_queue a shared queue for inbound data packets
 */
void data_worker_init(std::shared_ptr<PacketQueue> inbound_queue) {
    outbound_message_queue = new MessageQueue();
    data_pkt_queue = inbound_queue;

    std::thread DeliverMessagesThread(deliver_messages_thread);
    DeliverMessagesThread.detach();
    std::thread HandleDataThread(handle_data_thread);
    HandleDataThread.detach();
}

/**
 * @brief reset data logic
 * 
 */
void data_logic_reset() {
    sequence_number = 0;
    // TODO: empty all vectors and queues used by this module
    // TODO: empty data registry
}

/**
 * @brief Create and push to outbound queue a Message struct containing the users message
 * 
 * @param input user string to be used to create a message
 */
void create_message(const std::string& input) {
    uint8_t input_len = input.size() + 1; // Including space for a null character

    Message *msg = Message::create(input_len);
    msg->timestamp = get_current_time();
    msg->sequence_num = sequence_number++;
    msg->msg_len = input_len;
    std::memcpy(msg->payload, input.c_str(), input_len);

    outbound_message_queue->push(msg);
}

/**
 * @brief To be called by the data registry if a message fails to be delivered.
 *          changes the status of the message and updates the screen to display the message status
 * 
 * @param seq_num the sequence number of the message that failed to send
 */
void notify_send_fail(sequence_num_t seq_num) {
    {
        std::lock_guard<std::mutex> lock(msg_mutex);
        outbound_messages[seq_num].status = MessageStatus::FAILED;
    }
    display_messages();
}

/**
 * @brief print a single formatted inbound message to the main window
 * 
 * @param msg the message to be displayed
 */
static void print_inbound_msg(const Message *msg) {
    StealthcomUser *user = state_machine->get_connection_context().user;
    main_push_msg(user->getName() + ": " + std::string(msg->payload));
}

/**
 * @brief print a single formatted outbound message to the main window
 * 
 * @param msg a MessageWrapper containing the message to be displayed as well as its sent status
 */
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

/**
 * @brief Display all messages to the screen
 * 
 */
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
