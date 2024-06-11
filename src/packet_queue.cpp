#include "packet_queue.h"
#include "io_handler.h"

void PacketQueue::push(std::unique_ptr<packet_wrapper> packet) {
    static int ID = 0;
    {
        std::lock_guard<std::mutex> lock(mtx);
     //   system_push_msg("Pushing packet: " + std::to_string(ID++));
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
