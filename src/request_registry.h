#ifndef REQUEST_REGISTRY_H
#define REQUEST_REGISTRY_H

#include <unordered_map>
#include <string>
#include <vector>
#include <memory>
#include "registry.h"
#include "stealthcom_user.h"

#define OUTBOUND true
#define INBOUND  false

class RequestRegistryEntry {
public:
    StealthcomUser* user;
    int ttl;
    bool direction;

    RequestRegistryEntry(StealthcomUser* u, int time_to_live, bool direction)
        : user(u), ttl(time_to_live), direction(direction) {}
};

class RequestRegistry : public Registry<RequestRegistryEntry> {
private:
    std::unordered_map<std::string, RequestRegistryEntry*> registry;
    bool registry_updated;

protected:
    void decrement_ttl_and_remove_expired() override;

public:
    RequestRegistry();
    ~RequestRegistry();

    void add_or_update_entry(const uint8_t* MAC, bool direction);
    std::vector<StealthcomUser*> get_requests();
    bool has_active_request(const std::string& MAC);
    bool registry_update();
    void raise_update_flag();
};

extern std::shared_ptr<RequestRegistry> request_registry;

#endif