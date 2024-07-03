#include "data_registry.h"
#include "io_handler.h"

DataRegistry::DataRegistry() : Registry() {}

DataRegistry::~DataRegistry() {
    std::lock_guard<std::mutex> lock(registryMutex);
    for (auto& entry : outbound_seq_nums) {
        delete entry.second;
    }
}

void DataRegistry::add_entry(const sequence_num_t seq_num) {
    std::lock_guard<std::mutex> lock(registryMutex);
    outbound_seq_nums[seq_num] = new DataRegistryEntry();
}

void DataRegistry::remove_entry(const sequence_num_t seq_num) {
    std::lock_guard<std::mutex> lock(registryMutex);
    auto it = outbound_seq_nums.find(seq_num);
    if(it != outbound_seq_nums.end()) {
        DataRegistryEntry* entry = it->second;
        delete entry;
        outbound_seq_nums.erase(it);
    }
}

void DataRegistry::decrement_ttl_and_remove_expired() {
    std::lock_guard<std::mutex> lock(registryMutex);
    for (auto it = outbound_seq_nums.begin(); it != outbound_seq_nums.end(); ) {
        sequence_num_t seq_number = it->first;
        DataRegistryEntry* entry = it->second;
        if (--entry->ttl <= 0) {
            if(entry->retries == MAX_RETRIES) {
                system_push_msg("Message failed to deliver (Sequence #: " + std::to_string(it->first) + ")");
                notify_send_fail(it->first);
                delete entry;
                it = outbound_seq_nums.erase(it);
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

bool DataRegistry::entry_exists(const sequence_num_t seq_num) {
    std::lock_guard<std::mutex> lock(registryMutex);
    auto it = outbound_seq_nums.find(seq_num);
    return it != outbound_seq_nums.end();
}

void DataRegistry::register_incoming_data(const sequence_num_t seq_num) {
    std::lock_guard<std::mutex> lock(registryMutex);
    inbound_seq_nums.insert(seq_num);
}
    
bool DataRegistry::data_received(const sequence_num_t seq_num) {
    std::lock_guard<std::mutex> lock(registryMutex);
    return (inbound_seq_nums.find(seq_num) != inbound_seq_nums.end());
}
