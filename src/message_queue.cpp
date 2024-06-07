#include "message_queue.h"

void MessageQueue::push(std::string msg) {
    {
        std::lock_guard<std::mutex> lock(mtx);
        queue.push(std::move(msg));
    }
    cv.notify_one();
}

std::string MessageQueue::pop() {
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait(lock, [this] { return !queue.empty(); });
    auto msg = std::move(queue.front());
    queue.pop();
    return msg;
}

bool MessageQueue::empty() {
    std::unique_lock<std::mutex> lock(mtx);
    return queue.empty();
}
