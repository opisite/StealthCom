#ifndef REGISTRY_H
#define REGISTRY_H

#include <mutex>
#include <thread>
#include <chrono>

template <typename T>
class BaseRegistry {
protected:
    std::mutex registryMutex;
    bool running;
    std::thread registryManagerThread;

    virtual int get_initial_ttl() = 0;
    virtual bool should_erase_item(T* item) = 0;
    virtual void decrement_ttl_and_remove_expired() = 0;

    void registry_manager_thread() {
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            decrement_ttl_and_remove_expired();
        }
    }

public:
    BaseRegistry() : running(true), registryManagerThread([this] { registry_manager_thread(); }) {}
    virtual ~BaseRegistry() {
        running = false;
        if (registryManagerThread.joinable()) {
            registryManagerThread.join();
        }
    }
};

#endif
