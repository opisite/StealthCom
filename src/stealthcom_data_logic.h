#ifndef STEALTHCOM_DATA_LOGIC_H
#define STEALTHCOM_DATA_LOGIC_H

#include <string>
#include <vector>
#include <ctime>

struct Message {
    bool delivered;
    bool outbound;
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

void send_message(const std::string& input);

#endif