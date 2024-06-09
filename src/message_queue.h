#ifndef MESSAGE_QUEUE_H
#define MESSAGE_QUEUE_H

#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>

class MessageQueue {
public:
    void push(std::string msg);
    std::string pop();
    bool empty();

private:
    std::queue<std::string> queue;
    std::mutex mtx;
    std::condition_variable cv;
};

#endif
