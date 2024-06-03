#include "packet_queue.h"

void PacketQueue::push(std::unique_ptr<packet_wrapper> packet) {
    {
        std::lock_guard<std::mutex> lock(mtx);
        queue.push(std::move(packet));
    }
    cv.notify_one();
}

std::unique_ptr<packet_wrapper> PacketQueue::pop() {
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait(lock, [this] { return !queue.empty(); });
    auto packet = std::move(queue.front());
    queue.pop();
    return packet;
}
