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
#include "stealthcom_pkt_handler.h"
#include "user_registry.h"

#define PARAM_LEN_BITS   2048
#define PARAM_LEN_BYTES  (PARAM_LEN_BITS / 8)

typedef struct {
    StealthcomUser *user;
    std::atomic<bool> key_exchange_stop_flag;
    std::atomic<bool> have_local_dh_params;
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
    unsigned char pub_key[PARAM_LEN_BYTES];
    unsigned char p[PARAM_LEN_BYTES];
    unsigned char g[PARAM_LEN_BYTES];
};

static ex_status *status;
static dh_params *params;

static void status_init(StealthcomUser *user) {
    status->user = user;
    status->key_exchange_stop_flag.store(false);
    status->have_local_dh_params.store(false);
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

    std::copy(params->pub_key_byte_vector.begin(), params->pub_key_byte_vector.end(), payload->pub_key);
    std::copy(params->p_byte_vector.begin(), params->p_byte_vector.end(), payload->p);
    std::copy(params->g_byte_vector.begin(), params->g_byte_vector.end(), payload->g);
}

static void receive_dh_params() {

}

static bool initiate_dh() {
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

    free(ext);
}

void key_exchange_thread(StealthcomUser *user, bool initiatior) {
    user_registry->protect_users();
    state_machine->set_connection_state(KEY_EXCHANGE);

    ex_status s;
    status = &s;
    status_init(user);

    dh_params p;
    params = &p;

    status->key_exchange_stop_flag.store(false);

    std::pair<std::vector<unsigned char>, std::vector<unsigned char>> key_pair;

    if(initiatior) {
        initiate_dh();
    } else {
        receive_dh_params();
    }


    std::vector<unsigned char> this_pub_key = key_pair.first;
    std::vector<unsigned char> priv_key = key_pair.second;
    std::vector<unsigned char> peer_pub_key;
    bool pub_key_received = false;

    while(true) {
        if(status->key_exchange_stop_flag.load()) {
            system_push_msg("Key exchange terminated");
            break;
        }
    }

    user_registry->unprotect_users();
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

    status->have_local_dh_params.store(true);

    DH_free(dh);
}

std::vector<unsigned char> compute_shared_secret(const std::vector<unsigned char>& private_key, const std::vector<unsigned char>& public_key) {

}

std::string encrypt_message(const std::string& message, const std::vector<unsigned char>& key) {

}

std::string decrypt_message(const std::string& message, const std::vector<unsigned char>& key) {
    
}
