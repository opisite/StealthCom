#include "user_registry.h"
#include "utils.h"

#define TIME_TO_LIVE 30
#define CONNECTED_TIME_TO_LIVE 300

UserRegistry::UserRegistry() : Registry() {}

UserRegistry::~UserRegistry() {
    std::lock_guard<std::mutex> lock(registryMutex);
    for (auto& entry : registry) {
        delete entry.second->user;
        delete entry.second;
    }
}

void UserRegistry::decrement_ttl_and_remove_expired() {
    std::lock_guard<std::mutex> lock(registryMutex);
    for (auto it = registry.begin(); it != registry.end(); ) {
        if (--it->second->ttl <= 0) {
            delete it->second->user;
            delete it->second;
            it = registry.erase(it);
        } else {
            ++it;
        }
    }
}

void UserRegistry::add_or_update_entry(const uint8_t* MAC, std::string user_ID) {
    std::string MAC_str = mac_addr_to_str(MAC);

    std::lock_guard<std::mutex> lock(registryMutex);

    auto it = registry.find(MAC_str);
    if (it != registry.end()) {
        UserRegistryEntry* entry = it->second;
        if (entry->user->getName() != user_ID) {
            delete entry->user;
            entry->user = new StealthcomUser(user_ID, MAC);
            entry->connected = false;
        }
        entry->ttl = entry->connected ? CONNECTED_TIME_TO_LIVE : TIME_TO_LIVE;
    } else {
        registry[MAC_str] = new UserRegistryEntry(new StealthcomUser(user_ID, MAC), TIME_TO_LIVE, false);
    }
}

std::vector<StealthcomUser*> UserRegistry::get_users() {
    std::lock_guard<std::mutex> lock(registryMutex);
    std::vector<StealthcomUser*> users;
    for (const auto& entry : registry) {
        users.push_back(entry.second->user);
    }
    return users;
}

StealthcomUser * UserRegistry::get_user(std::string& MAC) {
    std::lock_guard<std::mutex> lock(registryMutex);
    auto it = registry.find(MAC);
    if (it != registry.end()) {
        UserRegistryEntry* entry = it->second;
        return entry->user;
    } else {
        return nullptr;
    }
}
