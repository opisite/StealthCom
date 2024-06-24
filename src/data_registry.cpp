#include "data_registry.h"
#include "stealthcom_data_logic.h"
#include "io_handler.h"

DataRegistry::DataRegistry() : Registry(), registry_updated(true) {}

DataRegistry::~DataRegistry() {
    std::lock_guard<std::mutex> lock(registryMutex);
    for (auto& entry : registry) {
        delete entry.second;
    }
}

void DataRegistry::add_entry(const uint32_t seq_num) {
    std::lock_guard<std::mutex> lock(registryMutex);
    registry[seq_num] = new DataRegistryEntry();
    registry_updated = true;
}

void DataRegistry::remove_entry(const uint32_t seq_num) {
    std::lock_guard<std::mutex> lock(registryMutex);
    auto it = registry.find(seq_num);
    if(it != registry.end()) {
        DataRegistryEntry* entry = it->second;
        delete entry;
        registry.erase(it);
    }
}

void DataRegistry::decrement_ttl_and_remove_expired() {
    std::lock_guard<std::mutex> lock(registryMutex);
    for (auto it = registry.begin(); it != registry.end(); ) {
        uint32_t seq_number = it->first;
        DataRegistryEntry* entry = it->second;
        if (--entry->ttl <= 0) {
            if(entry->retries == MAX_RETRIES) {
                system_push_msg("Message failed to deliver (Sequence #: " + std::to_string(it->first) + ")");
                delete entry;
                it = registry.erase(it);
                registry_updated = true;
            } else {
                resend_message(seq_number);
                entry->ttl = DATA_REGISTRY_TTL;
                entry->retries++;
            }
        } else {
            ++it;
        }
    }
}

bool DataRegistry::registry_update() {
    return registry_updated;
}

void DataRegistry::raise_update_flag() {
    registry_updated = true;
}

bool DataRegistry::entry_exists(const uint32_t seq_num) {
    std::lock_guard<std::mutex> lock(registryMutex);
    auto it = registry.find(seq_num);
    return it != registry.end();
}
