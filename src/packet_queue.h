#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>

struct packet_wrapper {
    void *buf;
    int buf_len;
};

class PacketQueue {
public:
    void push(std::unique_ptr<packet_wrapper> packet);
    std::unique_ptr<packet_wrapper> pop();

private:
    std::queue<std::unique_ptr<packet_wrapper>> queue;
    std::mutex mtx;
    std::condition_variable cv;
};

#endif