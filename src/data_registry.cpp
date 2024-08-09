#include "data_registry.h"
#include "io_handler.h"

DataRegistry::DataRegistry() : Registry() {}

/**
 * @brief Destroy the Data Registry:: Data Registry object
 * 
 */
DataRegistry::~DataRegistry() {
    std::lock_guard<std::mutex> lock(registryMutex);
    for (auto& entry : outbound_seq_nums) {
        delete entry.second;
    }
}

/**
 * @brief Add an entry to the data registry
 * 
 * @param seq_num the sequence number to be tracked by the registry (for outbound sequence numbers)
 */
void DataRegistry::add_entry(const sequence_num_t seq_num) {
    std::lock_guard<std::mutex> lock(registryMutex);
    outbound_seq_nums[seq_num] = new DataRegistryEntry();
}

/**
 * @brief remove an entry from the data registry
 * 
 * @param seq_num the sequence number to be removed
 */
void DataRegistry::remove_entry(const sequence_num_t seq_num) {
    std::lock_guard<std::mutex> lock(registryMutex);
    auto it = outbound_seq_nums.find(seq_num);
    if(it != outbound_seq_nums.end()) {
        DataRegistryEntry* entry = it->second;
        delete entry;
        outbound_seq_nums.erase(it);
    }
}

/**
 * @brief decrement TTL values and remove expired entries in the registry
 *          to be called once per second by the registry manager thread
 * 
 */
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

/**
 * @brief check if a particular sequence number exists in the registry
 * 
 * @param seq_num the sequence number to check for
 * @return true if found
 * @return false if not found
 */
bool DataRegistry::entry_exists(const sequence_num_t seq_num) {
    std::lock_guard<std::mutex> lock(registryMutex);
    auto it = outbound_seq_nums.find(seq_num);
    return it != outbound_seq_nums.end();
}

/**
 * @brief register sequence numbers that have been received by peer
 * 
 * @param seq_num the incoming sequence number
 */
void DataRegistry::register_incoming_data(const sequence_num_t seq_num) {
    std::lock_guard<std::mutex> lock(registryMutex);
    inbound_seq_nums.insert(seq_num);
}

/**
 * @brief Check if a particular sequence number has already been received
 * 
 * @param seq_num 
 * @return true if seq_num exists in the list of received sequence numbers
 * @return false if seq_num does not exist in the list of received sequence numbers
 */
bool DataRegistry::data_received(const sequence_num_t seq_num) {
    std::lock_guard<std::mutex> lock(registryMutex);
    return (inbound_seq_nums.find(seq_num) != inbound_seq_nums.end());
}
