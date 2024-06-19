#include "user_registry.h"
#include "utils.h"
#include "request_registry.h"
#include "stealthcom_state_machine.h"

#define TIME_TO_LIVE 10
#define CONNECTED_TIME_TO_LIVE 60

UserRegistry::UserRegistry() : Registry(), registry_updated(true) {}

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
        UserRegistryEntry* entry = it->second;
        if (--entry->ttl <= 0 && !request_registry->has_active_request(it->first) && !users_protected.load()) {
            if(entry->connected) {
                state_machine->reset_connection_context();
            }
            delete entry->user;
            delete entry;
            it = registry.erase(it);
            registry_updated = true;
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
        registry_updated = true;
    }
}

std::vector<StealthcomUser*> UserRegistry::get_users() {
    std::lock_guard<std::mutex> lock(registryMutex);
    std::vector<StealthcomUser*> users;
    for (const auto& entry : registry) {
        users.push_back(entry.second->user);
    }
    registry_updated = false;
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

void UserRegistry::notify_connect(std::string& MAC) {
    auto it = registry.find(MAC);
    if (it != registry.end()) {
        UserRegistryEntry* entry = it->second;
        entry->ttl = CONNECTED_TIME_TO_LIVE;
        entry->connected = true;
    }
}

void UserRegistry::protect_users() {
    users_protected.store(true);
}

void UserRegistry::unprotect_users() {
    users_protected.store(false);
}

bool UserRegistry::registry_update() {
    return registry_updated;
}

void UserRegistry::raise_update_flag() {
    registry_updated = true;
}
