#include "request_registry.h"
#include "user_registry.h"
#include "stealthcom_state_machine.h"
#include "io_handler.h"
#include "utils.h"

#define TIME_TO_LIVE 30

/**
 * @brief Construct a new Request Registry:: Request Registry object
 * 
 */
RequestRegistry::RequestRegistry() : Registry(), registry_updated(true) {}

/**
 * @brief Destroy the Request Registry:: Request Registry object
 * 
 */
RequestRegistry::~RequestRegistry() {
    std::lock_guard<std::mutex> lock(registryMutex);
    for (auto& entry : registry) {
        delete entry.second->user;
        delete entry.second;
    }
}

/**
 * @brief To be called by the registry manager thread once every second.
 *          Once per call, decrement all TTL values and remove expired entries
 */
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

/**
 * @brief Add an entry to the request registry or update the entry of an existing user
 * 
 * @param MAC the MAC address of the user to be added (or updated) to the registry
 * @param direction the inbound or outbound direction of the request being sent
 */
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

/**
 * @brief Get a list of all connection requests (excluding outbound)
 * 
 * @return std::vector<StealthcomUser*> a vector containing all requests
 */
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

/**
 * @brief Check if there is an active connection request associated with a MAC address
 * 
 * @param MAC the MAC address to check against
 * @return true if a connection request exists associated with MAC
 * @return false if no connection request exists associated with MAC
 */
bool RequestRegistry::has_active_request(const std::string& MAC) {
    std::lock_guard<std::mutex> lock(registryMutex);
    auto it = registry.find(MAC);
    return it != registry.end();
}

/**
 * @brief check to see if registry has been updated since the last time this was called
 * 
 * @return true if the registry was updated since the last call
 * @return false if the registry was not updated since the last call
 */
bool RequestRegistry::registry_update() {
    return registry_updated;
}

/**
 * @brief Raise the updated flag
 * 
 */
void RequestRegistry::raise_update_flag() {
    registry_updated = true;;
}
