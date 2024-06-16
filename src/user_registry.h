#ifndef USER_REGISTRY_H
#define USER_REGISTRY_H

#include <unordered_map>
#include <string>
#include <vector>
#include <memory>
#include "registry.h"
#include "stealthcom_user.h"

class UserRegistryEntry {
public:
    StealthcomUser* user;
    int ttl;
    bool connected;

    UserRegistryEntry(StealthcomUser* u, int time_to_live, bool conn)
        : user(u), ttl(time_to_live), connected(conn) {}
};

class UserRegistry : public Registry<UserRegistryEntry> {
private:
    std::unordered_map<std::string, UserRegistryEntry*> registry;

protected:
    void decrement_ttl_and_remove_expired() override;

public:
    UserRegistry();
    ~UserRegistry();

    void add_or_update_entry(const uint8_t* MAC, std::string user_ID);
    std::vector<StealthcomUser*> get_users();
    StealthcomUser * get_user(std::string& MAC);
};

extern std::shared_ptr<UserRegistry> user_registry;

#endif // USER_REGISTRY_H
