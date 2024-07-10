#include "request_registry.h"
#include "user_registry.h"
#include "stealthcom_state_machine.h"
#include "io_handler.h"
#include "utils.h"

#define TIME_TO_LIVE 30

RequestRegistry::RequestRegistry() : Registry(), registry_updated(true) {}

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
        RequestRegistryEntry* entry = it->second;
        if (--entry->ttl <= 0) {
            if(entry->direction == OUTBOUND && state_machine->get_connection_context().connection_state == AWAITING_CONNECTION_RESPONSE) {
                state_machine->reset_connection_context();
                system_push_msg("Connection to user [" + entry->user->getName() + "] timed out");
            }
            delete entry;
            it = registry.erase(it);
            registry_updated = true;
        } else {
            ++it;
        }
    }
}

void RequestRegistry::add_or_update_entry(const uint8_t* MAC, bool direction) {
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
        if(direction == INBOUND && entry->direction == OUTBOUND) {
            entry->direction = INBOUND;
        }
    } else {
        registry[MAC_str] = new RequestRegistryEntry(user, TIME_TO_LIVE, direction);
        registry_updated = true;
        std::string user_str = user_registry->get_user(MAC_str)->getName();
        if(direction == INBOUND) {
            system_push_msg("Connection request received from user [" + user_str + "] with address [" + MAC_str + "]");
        }
    }
}

std::vector<StealthcomUser*> RequestRegistry::get_requests() {
    std::lock_guard<std::mutex> lock(registryMutex);
    std::vector<StealthcomUser*> users;
    for (const auto& entry : registry) {
        if(!entry.second->direction) {
            users.push_back(entry.second->user);
        }
    }
    registry_updated = false;
    return users;
}

bool RequestRegistry::has_active_request(const std::string& MAC) {
    std::lock_guard<std::mutex> lock(registryMutex);
    auto it = registry.find(MAC);
    return it != registry.end();
}

bool RequestRegistry::registry_update() {
    return registry_updated;
}

void RequestRegistry::raise_update_flag() {
    registry_updated = true;;
}
