#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <chrono>
#include <thread>
#include "crypto.h"
#include "io_handler.h"
#include "stealthcom_connection_logic.h"
#include "stealthcom_state_machine.h"
#include "user_registry.h"

#define PARAM_LEN_BITS   2048
#define PARAM_LEN_BYTES  ((PARAM_LEN_BITS + 7) / 8)

typedef struct {
    StealthcomUser *user;
    std::atomic<bool> key_exchange_stop_flag;
    std::atomic<bool> have_peer_pub_key;
    std::atomic<bool> dh_params_delivered;
} ex_status;

typedef struct {
    std::vector<unsigned char> pub_key_byte_vector;
    std::vector<unsigned char> priv_key_byte_vector;
    std::vector<unsigned char> p_byte_vector;
    std::vector<unsigned char> g_byte_vector;
    std::vector<unsigned char> peer_pub_key_byte_vector;
} dh_params;

struct dh_params_payload {
    int item_len_bits;
    unsigned char pub_key[PARAM_LEN_BYTES];
    unsigned char p[PARAM_LEN_BYTES];
    unsigned char g[PARAM_LEN_BYTES];
};

struct pub_key_payload {
    int key_len_bits;
    unsigned char pub_key[PARAM_LEN_BYTES];
};

static ex_status *status;
static dh_params *params;

static void status_init(StealthcomUser *user) {
    status->user = user;
    status->key_exchange_stop_flag.store(false);
    status->have_peer_pub_key.store(false);
    status->dh_params_delivered.store(false);
}

static void terminate_key_exchange() {
    state_machine->reset_connection_context();
    status->key_exchange_stop_flag.store(true);
}

static void populate_payload(dh_params_payload *payload) {
    if (params->pub_key_byte_vector.size() != PARAM_LEN_BYTES ||
        params->p_byte_vector.size() != PARAM_LEN_BYTES ||
        params->g_byte_vector.size() != PARAM_LEN_BYTES) {
        system_push_msg("Error: Vector sizes do not match PARAM_LEN_BYTES");
        return;
    }

    payload->item_len_bits = PARAM_LEN_BITS;
    std::copy(params->pub_key_byte_vector.begin(), params->pub_key_byte_vector.end(), payload->pub_key);
    std::copy(params->p_byte_vector.begin(), params->p_byte_vector.end(), payload->p);
    std::copy(params->g_byte_vector.begin(), params->g_byte_vector.end(), payload->g);
}

static void populate_payload(pub_key_payload *payload) {
    if (params->pub_key_byte_vector.size() != PARAM_LEN_BYTES) {
        system_push_msg("Error: Vector size does not match PARAM_LEN_BYTES");
        return;
    }

    payload->key_len_bits = PARAM_LEN_BITS;
    std::copy(params->pub_key_byte_vector.begin(), params->pub_key_byte_vector.end(), payload->pub_key);
}

static void generate_private_key() {

}

static void save_dh_params(stealthcom_L2_extension *ext) {
    dh_params_payload *incoming_params = (dh_params_payload *)&ext->payload;

    if(incoming_params->item_len_bits != PARAM_LEN_BITS) {
        system_push_msg("Key exchange error: length of incoming DH parameters do not match local");
    }

    std::vector<unsigned char> p_byte_vector(PARAM_LEN_BYTES);
    std::vector<unsigned char> g_byte_vector(PARAM_LEN_BYTES);
    std::vector<unsigned char> peer_pub_key_byte_vector(PARAM_LEN_BYTES);

    std::copy(incoming_params->p, incoming_params->p + PARAM_LEN_BYTES, p_byte_vector.begin());
    std::copy(incoming_params->g, incoming_params->g + PARAM_LEN_BYTES, g_byte_vector.begin());
    std::copy(incoming_params->pub_key, incoming_params->pub_key + PARAM_LEN_BYTES, peer_pub_key_byte_vector.begin());

    params->p_byte_vector = p_byte_vector;
    params->g_byte_vector = g_byte_vector;
    params->peer_pub_key_byte_vector = peer_pub_key_byte_vector;

    generate_private_key();
}

static void deliver_pub_key() {
    while(!status->dh_params_delivered.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

static void dh_responder() {
    while(!status->have_peer_pub_key.load() && !status->key_exchange_stop_flag.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    if(status->have_peer_pub_key.load()) {

        deliver_pub_key();
    }
}

static inline void wait_for_pub_key() {
    while(!status->have_peer_pub_key.load() && !status->key_exchange_stop_flag.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

static bool dh_initiator() {
    generate_dh_key_pair();

    dh_params_payload payload;
    uint16_t payload_size = sizeof(payload);
    populate_payload(&payload);

    stealthcom_L2_extension *ext = generate_ext(KEY_EX | DH_PARAMS,
                                                status->user->getMAC(),
                                                payload_size,
                                                (const char *)&payload);

    while(!status->dh_params_delivered.load() && !status->key_exchange_stop_flag.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        send_packet(ext);
    }

    wait_for_pub_key();

    free(ext);
}

void key_exchange_thread(StealthcomUser *user, bool initiator) {
    user_registry->protect_users();
    state_machine->set_connection_state(KEY_EXCHANGE);

    ex_status s;
    status = &s;
    status_init(user);

    dh_params p;
    params = &p;

    status->key_exchange_stop_flag.store(false);

    if(initiator) {
        dh_initiator();
    } else {
        dh_responder();
    }

    user_registry->unprotect_users();
}

void key_exchange_packet_handler(stealthcom_L2_extension *ext) {
    uint8_t subtype = (uint8_t)ext->type & EXT_SUBTYPE_BITMASK;

    switch(subtype) {
        case DH_PARAMS: {
            save_dh_params(ext);
            status->have_peer_pub_key.store(true);
            break;
        }
        case DH_PARAMS_ACK: {
            status->dh_params_delivered.store(true);
            break;
        }
        case PUB_KEY: {
            break;
        }
        case PUB_KEY_ACK: {
            status->dh_params_delivered.store(true);
            break;
        }
    }
}

void generate_dh_key_pair() {
    DH* dh = DH_new();

    if (dh == nullptr) {
        system_push_msg("Failed to create DH object");
        terminate_key_exchange();
        return;
    }

    if (DH_generate_parameters_ex(dh, PARAM_LEN_BITS, DH_GENERATOR_2, nullptr) != 1) {
        DH_free(dh);
        system_push_msg("Failed to generate DH parameters");
        terminate_key_exchange();
        return;
    }

    const BIGNUM* p = nullptr;
    const BIGNUM* g = nullptr;
    DH_get0_pqg(dh, &p, nullptr, &g);

    std::vector<unsigned char> p_byte_vector(BN_num_bytes(p));
    BN_bn2bin(p, p_byte_vector.data());
    std::vector<unsigned char> g_byte_vector(BN_num_bytes(g));
    BN_bn2bin(g, g_byte_vector.data());

    params->p_byte_vector = p_byte_vector;
    params->g_byte_vector = g_byte_vector;

    if (DH_generate_key(dh) != 1) {
        DH_free(dh);
        system_push_msg("Failed to generate DH key pair");
        terminate_key_exchange();
        return;
    }

    const BIGNUM* pub_key = nullptr;
    const BIGNUM* priv_key = nullptr;
    DH_get0_key(dh, &pub_key, &priv_key);

    std::vector<unsigned char> public_key(BN_num_bytes(pub_key));
    BN_bn2bin(pub_key, public_key.data());
    params->pub_key_byte_vector = public_key;

    std::vector<unsigned char> private_key(BN_num_bytes(priv_key));
    BN_bn2bin(priv_key, private_key.data());
    params->priv_key_byte_vector = private_key;

    DH_free(dh);
}

std::vector<unsigned char> compute_shared_secret(const std::vector<unsigned char>& private_key, const std::vector<unsigned char>& public_key) {

}

std::string encrypt_message(const std::string& message, const std::vector<unsigned char>& key) {

}

std::string decrypt_message(const std::string& message, const std::vector<unsigned char>& key) {
    
}
