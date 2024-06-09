#include <iostream>
#include <chrono>

#include "user_registry.h"
#include "utils.h"
#include "io_handler.h"
#include "stealthcom_user.h"

#define TIME_TO_LIVE 30
#define CONNECTED_TIME_TO_LIVE 120

UserRegistry::UserRegistry() : running(true), registryManagerThread([this] { registry_manager_thread(); }) {}

UserRegistry::~UserRegistry() {
    running = false;
    if (registryManagerThread.joinable()) {
        registryManagerThread.join();
    }
}

void UserRegistry::add_or_update_entry(const uint8_t *MAC, std::string user_ID) {
    std::string MAC_str = mac_addr_to_str(MAC);

    std::lock_guard<std::mutex> lock(registryMutex);

    auto it = registry.find(MAC_str);
    if (it != registry.end()) {
        RegistryEntry *value = &it->second;
        if(value->user->getName() != user_ID) { // User ID doesnt match what the registry has for this MAC address
            delete value->user;
            value->user = new StealthcomUser(user_ID, MAC);
            value->connected = false;
        }
        value->ttl = value->connected ? CONNECTED_TIME_TO_LIVE : TIME_TO_LIVE;
    } else {
        auto &entry = registry[MAC_str];

        entry.user = new StealthcomUser(user_ID, MAC);
        entry.connected = false;
        entry.ttl = TIME_TO_LIVE;
    }
}

void UserRegistry::registry_manager_thread() {
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::lock_guard<std::mutex> lock(registryMutex);
        for (auto it = registry.begin(); it != registry.end(); ) {
            if(--it->second.ttl <= 0) {
                delete it->second.user;
                it = registry.erase(it);
            } else {
                it++;
            }
        }
    }
}

std::vector<StealthcomUser*> UserRegistry::get_users() {
    std::lock_guard<std::mutex> lock(registryMutex);
    std::vector<StealthcomUser*> users;
    for (const auto& entry : registry) {
        users.push_back(entry.second.user);
    }
    return users;
}
