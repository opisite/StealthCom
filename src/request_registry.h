#ifndef REQUEST_REGISTRY_H
#define REQUEST_REGISTRY_H

#include <unordered_map>
#include <string>
#include <vector>
#include <memory>
#include "registry.h"
#include "stealthcom_user.h"

class RequestRegistryEntry {
public:
    StealthcomUser* user;
    int ttl;

    RequestRegistryEntry(StealthcomUser* u, int time_to_live, bool conn)
        : user(u), ttl(time_to_live) {}
};

class RequestRegistry : public BaseRegistry<RequestRegistryEntry> {
private:
    std::unordered_map<std::string, RequestRegistryEntry*> registry;

protected:
    void decrement_ttl_and_remove_expired() override;

public:
    RequestRegistry();
    ~RequestRegistry();

    void add_or_update_entry(const uint8_t* MAC, std::string user_ID);
    std::vector<StealthcomUser*> get_requests();
};

extern std::shared_ptr<RequestRegistry> request_registry;

#endif