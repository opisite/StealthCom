#include "user_registry.h"
#include "utils.h"

#define TIME_TO_LIVE 30
#define CONNECTED_TIME_TO_LIVE 120

UserRegistry::UserRegistry() : BaseRegistry() {}

UserRegistry::~UserRegistry() {
    std::lock_guard<std::mutex> lock(registryMutex);
    for (auto& entry : registry) {
        delete entry.second->user;
        delete entry.second;
    }
}

int UserRegistry::get_initial_ttl() {
    return TIME_TO_LIVE;
}

bool UserRegistry::should_erase_item(UserRegistryEntry* item) {
    return false; // Additional conditions for erasing an entry can be added here
}

void UserRegistry::decrement_ttl_and_remove_expired() {
    std::lock_guard<std::mutex> lock(registryMutex);
    for (auto it = registry.begin(); it != registry.end(); ) {
        if (--(it->second->ttl) <= 0 || should_erase_item(it->second)) {
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