#ifndef DATA_REGISTRY_H
#define DATA_REGISTRY_H

#include <unordered_map>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include "registry.h"

#define DATA_REGISTRY_TTL 3
#define MAX_RETRIES       3

class DataRegistryEntry {
public:
    int ttl;
    int retries;

    DataRegistryEntry()
        : ttl(DATA_REGISTRY_TTL), retries(MAX_RETRIES) {}
};

class DataRegistry : public Registry<DataRegistryEntry> {
private:
    std::unordered_map<uint32_t, DataRegistryEntry*> registry;
    bool registry_updated;

protected:
    void decrement_ttl_and_remove_expired() override;

public:
    DataRegistry();
    ~DataRegistry();

    void add_entry(const uint32_t seq_num);
    void remove_entry(const uint32_t seq_num);
    bool registry_update();
    void raise_update_flag();
};

extern std::shared_ptr<DataRegistry> data_registry;

#endif