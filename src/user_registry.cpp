#include "user_registry.h"
#include "utils.h"
#include "request_registry.h"
#include "stealthcom_state_machine.h"

#define TIME_TO_LIVE 10
#define CONNECTED_TIME_TO_LIVE 60

/**
 * @brief Construct a new User Registry:: User Registry object
 * 
 */
UserRegistry::UserRegistry() : Registry(), registry_updated(true) {}

/**
 * @brief Destroy the User Registry:: User Registry object
 * 
 */
UserRegistry::~UserRegistry() {
    std::lock_guard<std::mutex> lock(registryMutex);
    for (auto& entry : registry) {
        delete entry.second->user;
        delete entry.second;
    }
}

/**
 * @brief To be called by the registry manager thread once every second.
 *          Once per call, decrement all TTL values and remove expired entries
 * 
 */
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

/**
 * @brief Add an entry to the user registry or update the entry of an existing user
 * 
 * @param MAC the MAC address of the user to be added (or updated) to the registry
 * @param user_ID the user ID of the user to be added (or updated) to the registry
 */
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

/**
 * @brief Get a list of all known users
 * 
 * @return std::vector<StealthcomUser*> a vector containing pointers to all known users 
 */
std::vector<StealthcomUser*> UserRegistry::get_users() {
    std::lock_guard<std::mutex> lock(registryMutex);
    std::vector<StealthcomUser*> users;
    for (const auto& entry : registry) {
        users.push_back(entry.second->user);
    }
    registry_updated = false;
    return users;
}

/**
 * @brief Get a StealthcomUser object by MAC address
 * 
 * @param MAC the MAC address to search for in the registry
 * @return StealthcomUser* a pointer to the corresponding StealthcomUser
 *         nullptr if there is no user corresponding to MAC
 */
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

/**
 * @brief To be called once the connection state changes to CONNECTED
 * 
 * @param user the StealthcomUser that is connectedc to
 */
void UserRegistry::notify_connect(StealthcomUser *user) {
    std::string MAC_str = mac_addr_to_str(user->getMAC().data());
    auto it = registry.find(MAC_str);
    if (it != registry.end()) {
        UserRegistryEntry* entry = it->second;
        entry->ttl = CONNECTED_TIME_TO_LIVE;
        entry->connected = true;
    }
}

/**
 * @brief prevent the registry manager from removing expired entries
 * 
 */
void UserRegistry::protect_users() {
    users_protected.store(true);
}

/**
 * @brief allow the registry manager to remove expired entries
 * 
 */
void UserRegistry::unprotect_users() {
    users_protected.store(false);
}

/**
 * @brief check to see if registry has been updated since the last time this was called
 * 
 * @return true if the registry was updated since the last call
 * @return false if the registry was not updated since the last call
 */
bool UserRegistry::registry_update() {
    return registry_updated;
}

/**
 * @brief Raise the updated flag
 * 
 */
void UserRegistry::raise_update_flag() {
    registry_updated = true;
}
