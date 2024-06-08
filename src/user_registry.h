#ifndef USER_REGISTRY_H
#define USER_REGISTRY_H

#include <unordered_map>
#include <mutex>
#include <string>
#include <thread>
#include <memory>
#include <vector>

#include "stealthcom_user.h"

class UserRegistry {
private:
    struct RegistryEntry {
        StealthcomUser *user;
        int ttl;
    };

    std::unordered_map<std::string, RegistryEntry> registry;
    std::mutex registryMutex;
    bool running;
    bool alert;
    std::thread worker;

    void registry_manager();

public:
    UserRegistry();
    ~UserRegistry();

    void add_or_update_entry(const uint8_t *MAC, std::string user_ID);
    void check_and_remove_expired();
    std::vector<StealthcomUser*> get_users();
};

extern std::shared_ptr<UserRegistry> user_registry;

#endif