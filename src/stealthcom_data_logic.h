#ifndef STEALTHCOM_DATA_LOGIC_H
#define STEALTHCOM_DATA_LOGIC_H

#include <string>
#include <vector>
#include <ctime>

enum class MessageStatus : uint8_t {
    NOT_DELIVERED,
    DELIVERED,
    FAILED,
};

struct Message {
    std::time_t timestamp;
    uint32_t sequence_num;
    uint8_t msg_len;
    char payload[1]; // Variable length of data

    Message(uint8_t msg_len) : msg_len(msg_len) {}

    static Message * create(uint8_t payload_len) {
        void* mem = std::malloc(sizeof(Message) + payload_len - 1);
        if (!mem) {
            throw std::bad_alloc();
        }
        return new (mem) Message(payload_len);
    }

};

struct MessageWrapper {
    MessageStatus status;
    const Message *msg;
};

void data_logic_init();
void data_logic_reset();
void resend_message(uint32_t seq_number);
void send_message(const Message *msg);
void set_msg_status();
void create_message(const std::string& input);

#endif
