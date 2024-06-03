#ifndef OUTPUT_QUEUE_H
#define OUTPUT_QUEUE_H

#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>

class OutputQueue {
public:
    void push(std::string msg);
    std::string pop();

private:
    std::queue<std::string> queue;
    std::mutex mtx;
    std::condition_variable cv;
};

#endif