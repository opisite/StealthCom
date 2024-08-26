#include <string.h>
#include <thread>
#include <chrono>
#include <iostream>
#include <string>
#include <atomic>

#include "stealthcom_pkt_handler.h"
#include "utils.h"
#include "thread_safe_queue.h"
#include "user_data.h"
#include "user_registry.h"
#include "request_registry.h"
#include "io_handler.h"
#include "stealthcom_connection_logic.h"
#include "stealthcom_data_logic.h"
#include "crypto.h"
#include "stealthcom_state_machine.h"

std::atomic<bool> advertise_stop_flag;

static std::shared_ptr<PacketQueue> rx_queue;
static std::shared_ptr<PacketQueue> tx_queue;
static std::shared_ptr<PacketQueue> connect_pkt_queue;
static std::shared_ptr<PacketQueue> data_pkt_queue;

/**
 * @brief Initialize the packet handler
 * 
 * @param rx packet queue containing received packets from packet_rx_tx.c
 * @param tx packets queue containing packets to be transmitted
 */
void stealthcom_pkt_handler_init(std::shared_ptr<PacketQueue> rx, std::shared_ptr<PacketQueue> tx) {
    rx_queue = rx;
    tx_queue = tx;

    connect_pkt_queue = std::make_shared<PacketQueue>();
    data_pkt_queue = std::make_shared<PacketQueue>();

    connection_worker_init(connect_pkt_queue);
    data_worker_init(data_pkt_queue);
    
    std::thread connectWorkerThread(connection_worker_thread);
    connectWorkerThread.detach();

    advertise_stop_flag.store(false);
}

/**
 * @brief Transmit a stealthcom_L2_extension. Appends a dummy probe request to the beginning then hands the buffer over to tx_queue
 * 
 * @param ext the extenstion to be transmitted
 */
void send_packet(stealthcom_L2_extension * ext) {
    static stealthcom_header hdr_template = {
        .frame_ctrl =               {0x40, 0x00},
        .duration_id =              {0x00, 0x00},
        .addr1 =                    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .addr2 =                    {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA},
        .addr3 =                    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .seq_ctrl =                 {0x00, 0x00},
        .SSID_params =              {0x00, 0x00},
        .supported_rate_params =    {0x00, 0x00},
    };

    int ext_len = (sizeof(stealthcom_L2_extension) - 1) + ext->payload_len;

    stealthcom_header *hdr = (stealthcom_header *)malloc(sizeof(stealthcom_header) + ext_len);

    memcpy(hdr, &hdr_template, sizeof(stealthcom_header));
    memcpy((uint8_t*)hdr + sizeof(stealthcom_header), ext, ext_len);

    std::unique_ptr<packet_wrapper> packet = std::make_unique<packet_wrapper>();

    packet->buf = hdr;
    packet->buf_len = sizeof(stealthcom_header) + ext_len;

    tx_queue->push(std::move(packet));
}

/**
 * @brief Generate a stealthcom_L2_extension with type only
 * 
 * @param type the type of stealthcom_L2_extension to generate
 * @return stealthcom_L2_extension* a pointer to stealthcom_L2_extension with type (type)
 */
stealthcom_L2_extension * generate_ext(sc_pkt_type_t type) {
    const uint8_t *this_MAC = get_MAC();
    std::string this_user_ID = get_user_ID();
    int user_ID_len = this_user_ID.length();

    struct stealthcom_L2_extension *ext = stealthcom_L2_extension::create(0);
    ext->type = type;
    memcpy(ext->source_MAC, this_MAC, 6);
    memset(ext->dest_MAC, 0xFF, 6);
    strncpy(ext->user_ID, this_user_ID.c_str(), user_ID_len);
    ext->user_ID_len = user_ID_len;
    ext->payload_len = 0;

    return ext;
}

/**
 * @brief Generate a stealthcom_L2_extension with destination address
 * 
 * @param type the type of stealthcom_L2_extension to generate
 * @param dest_MAC the MAC address to address the extenstion to
 * @return stealthcom_L2_extension* stealthcom_L2_extension* a pointer to stealthcom_L2_extension with type (type) and dest_MAC (dest_MAC)
 */
stealthcom_L2_extension * generate_ext(sc_pkt_type_t type, std::array<uint8_t, 6> dest_MAC) {
    const uint8_t *this_MAC = get_MAC();
    std::string this_user_ID = get_user_ID();
    int user_ID_len = this_user_ID.length();

    struct stealthcom_L2_extension *ext = stealthcom_L2_extension::create(0);
    ext->type = type;
    memcpy(ext->source_MAC, this_MAC, 6);
    memcpy(ext->dest_MAC, dest_MAC.data(), 6);
    strncpy(ext->user_ID, this_user_ID.c_str(), user_ID_len);
    ext->user_ID_len = user_ID_len;
    ext->payload_len = 0;

    return ext;
}

/**
 * @brief Generate a stealthcom_L2_extension with destination address and payload
 * 
 * @param type the type of stealthcom_L2_extension to generate
 * @param dest_MAC the MAC address to address the extenstion to
 * @param payload_len length of the payload to append to the end of the stealthcom_L2_extension
 * @param payload a pointer to a buffer with length payload_len
 * @return stealthcom_L2_extension* a pointer to stealthcom_L2_extension with type (type) and dest_MAC (dest_MAC) and a paylaod (paylaod) appended to the end
 */
stealthcom_L2_extension * generate_ext(sc_pkt_type_t type, std::array<uint8_t, 6> dest_MAC, ext_payload_len_t payload_len, const char *payload) {
    const uint8_t *this_MAC = get_MAC();
    std::string this_user_ID = get_user_ID();
    int user_ID_len = this_user_ID.length();

    struct stealthcom_L2_extension *ext = stealthcom_L2_extension::create(payload_len);
    ext->type = type;
    memcpy(ext->source_MAC, this_MAC, 6);
    memcpy(ext->dest_MAC, dest_MAC.data(), 6);
    strncpy(ext->user_ID, this_user_ID.c_str(), user_ID_len);
    memcpy(ext->payload, payload, payload_len);
    ext->user_ID_len = user_ID_len;
    ext->payload_len = payload_len;

    return ext;
}

/**
 * @brief Check if a received stealthcom packet is being broadcast (beacon)
 * 
 * @param ext the received buffer
 * @return true if the packet is broadcast
 * @return false if the packet is not broadcast
 */
static inline bool check_dest_beacon(const struct stealthcom_L2_extension *ext) {
    for(int x = 0; x < 6; x++) {
        if(ext->dest_MAC[x] != 0xFF) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Check if a received stealthcom packet is addressed to self
 * 
 * @param ext the received buffer
 * @return true if the packet is addressed to self
 * @return false if the packet is not addressed to self
 */
static inline bool check_dest_self(const struct stealthcom_L2_extension *ext) {
    for(int x = 0; x < 6; x++) {
        if(ext->dest_MAC[x] != this_MAC[x]) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Check if the source of a stealthcom packet is self
 * 
 * @param ext the received buffer
 * @return true if the packet is comes from self
 * @return false if the packet does not come from self
 */
static inline bool check_source_self(const struct stealthcom_L2_extension *ext) {
    for(int x = 0; x < 6; x++) {
        if(ext->source_MAC[x] != this_MAC[x]) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Check if this is the intended recipient of a stealthcom packet
 * 
 * @param ext the received buffer
 * @return true if recipient
 * @return false if not recipient
 */
static inline bool is_recipient(const struct stealthcom_L2_extension *ext) {
    return (!check_source_self(ext) && (check_dest_self(ext) || check_dest_beacon(ext)));
}

/**
 * @brief Check if an incoming stealthcom packet comes from a valid source
 * 
 * @param ext stealthcom packet
 * @return true if source valid
 * @return false if source not valid
 */
static inline bool valid_source(const struct stealthcom_L2_extension *ext) {
    ConnectionContext ctx = state_machine->get_connection_context();
    if(ctx.connection_state == UNASSOCIATED) {
        return true;
    }

    std::array<uint8_t, 6> ctx_user_MAC = ctx.user->getMAC();
    for(int x = 0; x < 6; x++) {
        if(ctx_user_MAC[x] != ext->source_MAC[x]) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Handle a stealthcom packet with type BEACON
 * 
 * @param ext 
 */
static void handle_stealthcom_beacon(struct stealthcom_L2_extension *ext) {
    return;
}

/**
 * @brief (thread) handle all received stealthcom packets
 * 
 */
void packet_handler_thread() {
    while(true) {
        std::unique_ptr<packet_wrapper> pkt_wrapper = rx_queue->pop();
        int packet_len = pkt_wrapper->buf_len;
        stealthcom_header *hdr = (stealthcom_header *)pkt_wrapper->buf;
        stealthcom_L2_extension *ext = (stealthcom_L2_extension *)((uint8_t *)hdr + sizeof(stealthcom_header));

        if(!is_recipient(ext)) {
            continue;
        }

        if(!valid_source(ext)) {
            continue;
        }

        char user_ID_buf[USER_ID_MAX_LEN + 1];
        memcpy(user_ID_buf, ext->user_ID, ext->user_ID_len);
        user_ID_buf[ext->user_ID_len] = '\0';

        user_registry->add_or_update_entry(&ext->source_MAC[0], user_ID_buf);
        sc_pkt_type_t type = ext->type & EXT_TYPE_BITMASK;

        switch(type) {
            case BEACON: {
                //system_push_msg("BEACON");
                break;
            }
            case CONNECT: {
                stealthcom_L2_extension *ext_c = (stealthcom_L2_extension *)malloc(sizeof(stealthcom_L2_extension) - 1);
                memcpy(ext_c, ext, sizeof(stealthcom_L2_extension) - 1);
                std::unique_ptr<packet_wrapper> ext_wrapper = std::make_unique<packet_wrapper>();
                ext_wrapper->buf_len = packet_len - sizeof(stealthcom_header);
                ext_wrapper->buf = ext_c;
                connect_pkt_queue->push(std::move(ext_wrapper));
                break;
            }
            case DATA: {
                int ext_size = (sizeof(stealthcom_L2_extension) - 1) + ext->payload_len;
                stealthcom_L2_extension *ext_c = (stealthcom_L2_extension *)malloc(ext_size);
                memcpy(ext_c, ext, ext_size);
                std::unique_ptr<packet_wrapper> ext_wrapper = std::make_unique<packet_wrapper>();
                ext_wrapper->buf_len = packet_len - sizeof(stealthcom_header);
                ext_wrapper->buf = ext_c;
                data_pkt_queue->push(std::move(ext_wrapper));
                break;
            }
            case KEY_EX: {
                key_exchange_packet_handler(ext);
            }
        }
    }
}

/**
 * @brief Set this user advertising
 * 
 * @param set 0 to stop advertising - 1 to start advertising
 */
void set_advertise(int set) {
    if(set == 0) {
        advertise_stop_flag.store(true);
    } else {
        std::thread advertiseThread(user_advertise_thread);
        advertiseThread.detach();
    }
}

/**
 * @brief (thread) transmit a beacon frame once per second
 * 
 */
void user_advertise_thread() {
    stealthcom_L2_extension *ext = generate_ext(BEACON);

    while(!advertise_stop_flag.load()) {
        send_packet(ext);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    advertise_stop_flag.store(false);
}
