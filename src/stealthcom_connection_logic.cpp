#include <thread>
#include <string>
#include <string.h>
#include <atomic>
#include <iostream>
#include "stealthcom_connection_logic.h"
#include "stealthcom_state_machine.h"
#include "stealthcom_pkt_handler.h"
#include "user_registry.h"
#include "user_data.h"
#include "request_registry.h"
#include "io_handler.h"
#include "utils.h"
#include "stealthcom_data_logic.h"
#include "crypto.h"

static std::shared_ptr<PacketQueue> connect_pkt_queue;

/**
 * @brief Initialize connection worker
 * 
 * @param queue packet queue containing received packets from stealthcom_pkt_handler.c
 */
void connection_worker_init(std::shared_ptr<PacketQueue> queue) {
    connect_pkt_queue = queue;
}

/**
 * @brief Enter connected state
 * 
 * @param user the user that is being connected to
 */
void begin_connection(StealthcomUser *user) {
    user_registry->notify_connect(user);
    state_machine->set_connection_state(CONNECTED);
}

/**
 * @brief Handle an incoming connection request
 * 
 * @param ext stealthcom_L2_extension with subtype REQUEST
 * @param user_ID_str user ID associated with the incoming ext
 */
static void handle_stealthcom_conn_request(struct stealthcom_L2_extension *ext, std::string& user_ID_str) {
    request_registry->add_or_update_entry(&ext->source_MAC[0], INBOUND);
}

/**
 * @brief Handle an incoming connection request refusal
 * 
 * @param ext stealthcom_L2_extension with subtype REFUSE
 * @param user_ID_str user ID associated with the incoming ext
 */
static void handle_stealthcom_conn_refuse(struct stealthcom_L2_extension *ext, std::string& user_ID_str) {
    ConnectionContext context = state_machine->get_connection_context();
    std::string MAC_str = mac_addr_to_str(&ext->source_MAC[0]);
    StealthcomUser *user = user_registry->get_user(MAC_str);

    if(context.user != user || context.connection_state != AWAITING_CONNECTION_RESPONSE) {
        return;
    }
    
    state_machine->reset_connection_context();
    system_push_msg("User [" + user_ID_str + "] with address [" + MAC_str + "] declined your connection request");
}

/**
 * @brief Send a connection request accept ack
 * 
 * @param user user to send the ack to
 */
static void send_conn_accept_ack(StealthcomUser *user) {
    std::array<uint8_t, 6> MAC = user->getMAC();

    stealthcom_L2_extension *ext = generate_ext(CONNECT | ACCEPT_ACK, MAC);

    for(int x = 0; x < 3; x++) {
        send_packet(ext);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    free(ext);
}

/**
 * @brief Handle an incoming connection request accept
 * 
 * @param ext stealthcom_L2_extension with subtype ACCEPT
 * @param user_ID_str user ID associated with the incoming ext
 */
static void handle_stealthcom_conn_accept(struct stealthcom_L2_extension *ext, std::string& user_ID_str) {
    std::string MAC_str = mac_addr_to_str(&ext->source_MAC[0]);
    StealthcomUser *user = user_registry->get_user(MAC_str);
    ConnectionContext context = state_machine->get_connection_context();
    if(context.user != user || context.connection_state != AWAITING_CONNECTION_RESPONSE) {
        return;
    }

    system_push_msg("User [" + user_ID_str + "] with address [" + MAC_str + "] accepted your connection request - beginning key exchange");

    state_machine->set_connection_state(KEY_EXCHANGE);
    std::thread keyExchangeThread(key_exchange_thread, user, true);
    keyExchangeThread.detach();

    send_conn_accept_ack(user);
}

/**
 * @brief Handle an incoming connection request accept ACK
 * 
 * @param ext stealthcom_L2_extension with subtype ACCEPT_ACK
 * @param user_ID_str user ID associated with the incoming ext
 */
static void handle_stealthcom_conn_accept_ack(struct stealthcom_L2_extension *ext, std::string& user_ID_str) {
    std::string MAC_str = mac_addr_to_str(&ext->source_MAC[0]);
    StealthcomUser *user = user_registry->get_user(MAC_str);
    ConnectionContext context = state_machine->get_connection_context();
    if(context.user != user || context.connection_state != AWAITING_CONNECTION_RESPONSE) {
        return;
    }

    system_push_msg("User [" + user_ID_str + "] with address [" + MAC_str + "] acknowledged your accept - beginning key exchange");

    state_machine->set_connection_state(KEY_EXCHANGE);
    std::thread keyExchangeThread(key_exchange_thread, user, false);
    keyExchangeThread.detach(); 
}

/**
 * @brief Handle an incoming disconnect
 * 
 * @param ext stealthcom_L2_extension with subtype DISCONNECT
 * @param user_ID_str user ID associated with the incoming ext
 */
static void handle_stealthcom_disconnect(struct stealthcom_L2_extension *ext, std::string& user_ID_str) {
    // TODO: check if the disconnect is coming from valid user
    if(state_machine->get_connection_context().connection_state != CONNECTED) {
        return;
    }
    system_push_msg(user_ID_str + " disconnected");
    state_machine->reset_connection_context();
}

/**
 * @brief (thread) handles all incoming stealthcom packets with type CONNECT
 * 
 */
void connection_worker_thread() {
    while(true) {
        std::unique_ptr<packet_wrapper> pkt_wrapper = connect_pkt_queue->pop();
        int packet_len = pkt_wrapper->buf_len;
        stealthcom_L2_extension *ext = (stealthcom_L2_extension *)pkt_wrapper->buf;

        uint8_t subtype = (uint8_t)ext->type & EXT_SUBTYPE_BITMASK;

        char user_ID_buf[USER_ID_MAX_LEN + 1];
        memcpy(user_ID_buf, ext->user_ID, ext->user_ID_len);
        user_ID_buf[ext->user_ID_len] = '\0';
        std::string user_ID_str(user_ID_buf);

        switch(subtype) {
            case REQUEST: {
                handle_stealthcom_conn_request(ext, user_ID_str);
                break;
            }
            case ACCEPT: {
                handle_stealthcom_conn_accept(ext, user_ID_str);
                break;
            }
            case REFUSE: {
                handle_stealthcom_conn_refuse(ext, user_ID_str);
                break;
            }
            case ACCEPT_ACK: {
                handle_stealthcom_conn_accept_ack(ext, user_ID_str);
                break;
            }
            case DISCONNECT: {
                handle_stealthcom_disconnect(ext, user_ID_str);
                break;
            }
        }
    }
}

/**
 * @brief Send a connection request
 * 
 * @param user user to send the request to
 */
void send_conn_request(StealthcomUser *user) {
    std::array<uint8_t, 6> MAC = user->getMAC();
    system_push_msg("Sending connection request to user [" + user->getName() + "] with address [" + mac_addr_to_str(MAC.data()) + "]");

    stealthcom_L2_extension *ext = generate_ext(CONNECT | REQUEST, MAC);

    for(int x = 0; x < 3; x++) {
        send_packet(ext);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    free(ext);

    request_registry->add_or_update_entry(&ext->dest_MAC[0], OUTBOUND);

    state_machine->set_connection_state_and_user(AWAITING_CONNECTION_RESPONSE, user);
}

/**
 * @brief Send a connection request response
 * 
 * @param user uset to send the response to
 * @param accept whether the request is being accepted or declined
 */
void send_conn_request_response(StealthcomUser *user, bool accept) {
    std::array<uint8_t, 6> MAC = user->getMAC();

    stealthcom_L2_extension *ext;
    if(accept) {
        ext = generate_ext(CONNECT | ACCEPT, MAC);
        state_machine->set_connection_state_and_user(AWAITING_CONNECTION_RESPONSE, user);
    } else {
        ext = generate_ext(CONNECT | REFUSE, MAC);
    }

    for(int x = 0; x < 3; x++) {
        send_packet(ext);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    free(ext);

    request_registry->add_or_update_entry(&ext->dest_MAC[0], OUTBOUND);
}

/**
 * @brief Send a disconnect
 * 
 */
void send_disconnect() {
    StealthcomUser *user = state_machine->get_connection_context().user;
    std::array<uint8_t, 6> MAC = user->getMAC();

    stealthcom_L2_extension *ext = generate_ext(CONNECT | DISCONNECT, MAC);

    for(int x = 0; x < 3; x++) {
        send_packet(ext);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    free(ext);
}
