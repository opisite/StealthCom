#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>

struct packet_wrapper {
    const char *buf;
    int buf_len;
};

extern std::queue<std::unique_ptr<struct packet_wrapper>> destQueue;
extern std::mutex queueMutex; 
extern std::condition_variable queueCV;

#endif