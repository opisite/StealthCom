#include "request_registry.h"
#include "user_registry.h"
#include "utils.h"

#define TIME_TO_LIVE 15

RequestRegistry::RequestRegistry() : BaseRegistry() {}

RequestRegistry::~RequestRegistry() {
    std::lock_guard<std::mutex> lock(registryMutex);
    for (auto& entry : registry) {
        delete entry.second->user;
        delete entry.second;
    }
}

void RequestRegistry::decrement_ttl_and_remove_expired() {
    std::lock_guard<std::mutex> lock(registryMutex);
    for (auto it = registry.begin(); it != registry.end(); ) {
        if (--it->second->ttl <= 0) {
            delete it->second;
            it = registry.erase(it);
        } else {
            ++it;
        }
    }
}

void RequestRegistry::add_or_update_entry(const uint8_t* MAC) {
    std::string MAC_str = mac_addr_to_str(MAC);

    std::lock_guard<std::mutex> lock(registryMutex);

    StealthcomUser *user = user_registry->get_user(MAC_str);

    if(user == nullptr) {
        return;
    }

    auto it = registry.find(MAC_str);
    if (it != registry.end()) {
        RequestRegistryEntry* entry = it->second;
        entry->ttl = TIME_TO_LIVE;
    } else {
        registry[MAC_str] = new RequestRegistryEntry(user, TIME_TO_LIVE);
    }
}

std::vector<StealthcomUser*> RequestRegistry::get_requests() {
    std::lock_guard<std::mutex> lock(registryMutex);
    std::vector<StealthcomUser*> users;
    for (const auto& entry : registry) {
        users.push_back(entry.second->user);
    }
    return users;
}
