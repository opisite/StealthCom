#ifndef DATA_REGISTRY_H
#define DATA_REGISTRY_H

#include <unordered_map>
#include <set>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include "registry.h"
#include "stealthcom_data_logic.h"

#define DATA_REGISTRY_TTL 3
#define MAX_RETRIES       3

class DataRegistryEntry {
public:
    int ttl;
    int retries;

    DataRegistryEntry()
        : ttl(DATA_REGISTRY_TTL), retries(0) {}
};

class DataRegistry : public Registry<DataRegistryEntry> {
private:
    std::unordered_map<sequence_num_t, DataRegistryEntry*> outbound_seq_nums;
    std::set<sequence_num_t> inbound_seq_nums;

protected:
    void decrement_ttl_and_remove_expired() override;

public:
    DataRegistry();
    ~DataRegistry();

    void add_entry(const sequence_num_t seq_num);
    void remove_entry(const sequence_num_t seq_num);
    bool registry_update();
    bool entry_exists(const sequence_num_t seq_num);
    void register_incoming_data(const sequence_num_t seq_num);
    bool data_received(const sequence_num_t seq_num);
};

extern std::shared_ptr<DataRegistry> data_registry;

#endif
