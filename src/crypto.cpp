#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <chrono>
#include <thread>
#include "crypto.h"
#include "io_handler.h"
#include "stealthcom_connection_logic.h"
#include "stealthcom_state_machine.h"
#include "user_registry.h"

#define PARAM_LEN_BITS   2048
#define PARAM_LEN_BYTES  ((PARAM_LEN_BITS + 7) / 8)

#define KEY_LEN_BITS     256
#define KEY_LEN_BYTES    (KEY_LEN_BITS / 8)

typedef struct {
    StealthcomUser *user;
    bool initiator;
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

static std::vector<unsigned char> encryption_key;

static void status_init(StealthcomUser *user, bool initiator) {
    status->user = user;
    status->initiator = initiator;
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
        system_push_msg("Crypto Error: Vector size does not match PARAM_LEN_BYTES");
        return;
    }

    payload->key_len_bits = PARAM_LEN_BITS;
    std::copy(params->pub_key_byte_vector.begin(), params->pub_key_byte_vector.end(), payload->pub_key);
}

static void generate_private_key() {
    system_push_msg("Crypto: Generating private key...");

    BIGNUM* priv_key = BN_new();
    if (!priv_key) {
        system_push_msg("Crypto Error: Failed to allocate memory for BIGNUM");
        BN_free(priv_key);
        return;
    }

    if (!BN_rand(priv_key, PARAM_LEN_BITS, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) {
        system_push_msg("Crypto Error: Failed to generate " + std::to_string(PARAM_LEN_BITS) + " bit private key");
        BN_free(priv_key);
        return;
    }

    std::vector<unsigned char> priv_key_byte_vector(BN_num_bytes(priv_key));
    BN_bn2bin(priv_key, priv_key_byte_vector.data());
    params->priv_key_byte_vector = priv_key_byte_vector;

    BN_free(priv_key);
}

static void generate_public_key() {
    system_push_msg("Crypto: Generating public key...");

    if (params->priv_key_byte_vector.empty() || 
        params->p_byte_vector.empty() || 
        params->g_byte_vector.empty()) {
        system_push_msg("Crypto Error: Missing private key or DH parameters");
        return;
    }

    DH* dh = DH_new();
    if (dh == nullptr) {
        system_push_msg("Crypto Error: Failed to create DH object");
        return;
    }

    BIGNUM* p = BN_bin2bn(params->p_byte_vector.data(), params->p_byte_vector.size(), nullptr);
    BIGNUM* g = BN_bin2bn(params->g_byte_vector.data(), params->g_byte_vector.size(), nullptr);
    BIGNUM* priv_key = BN_bin2bn(params->priv_key_byte_vector.data(), params->priv_key_byte_vector.size(), nullptr);

    if (p == nullptr || g == nullptr || priv_key == nullptr) {
        system_push_msg("Crypto Error: Failed to convert parameters to BIGNUM");
        BN_free(p);
        BN_free(g);
        BN_free(priv_key);
        DH_free(dh);
        return;
    }

    if (DH_set0_pqg(dh, p, nullptr, g) != 1) {
        system_push_msg("Crypto Error: Failed to set DH parameters");
        BN_free(p);
        BN_free(g);
        BN_free(priv_key);
        DH_free(dh);
        return;
    }

    if (DH_set0_key(dh, nullptr, priv_key) != 1) {
        system_push_msg("Crypto Error: Failed to set private key");
        BN_free(priv_key);
        DH_free(dh);
        return;
    }

    if (DH_generate_key(dh) != 1) {
        system_push_msg("Crypto Error: Failed to generate public key");
        DH_free(dh);
        return;
    }

    const BIGNUM* pub_key = nullptr;
    DH_get0_key(dh, &pub_key, nullptr);

    if (pub_key == nullptr) {
        system_push_msg("Crypto Error: Failed to retrieve public key");
        DH_free(dh);
        return;
    }

    std::vector<unsigned char> pub_key_byte_vector(BN_num_bytes(pub_key));
    BN_bn2bin(pub_key, pub_key_byte_vector.data());
    params->pub_key_byte_vector = pub_key_byte_vector;

    DH_free(dh);
}

static void send_ack(int subtype) {
    stealthcom_L2_extension *ext = generate_ext(KEY_EX | subtype,
                                                status->user->getMAC());

    for(int x = 0; x < 3; x++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        send_packet(ext);
    }
}

static void save_dh_params(stealthcom_L2_extension *ext) {
    dh_params_payload *payload = (dh_params_payload *)&ext->payload;

    if(payload->item_len_bits != PARAM_LEN_BITS) {
        system_push_msg("Crypto Error: length of incoming DH parameters do not match local");
    }

    std::vector<unsigned char> p_byte_vector(PARAM_LEN_BYTES);
    std::vector<unsigned char> g_byte_vector(PARAM_LEN_BYTES);
    std::vector<unsigned char> peer_pub_key_byte_vector(PARAM_LEN_BYTES);

    std::copy(payload->p, payload->p + PARAM_LEN_BYTES, p_byte_vector.begin());
    std::copy(payload->g, payload->g + PARAM_LEN_BYTES, g_byte_vector.begin());
    std::copy(payload->pub_key, payload->pub_key + PARAM_LEN_BYTES, peer_pub_key_byte_vector.begin());

    params->p_byte_vector = p_byte_vector;
    params->g_byte_vector = g_byte_vector;
    params->peer_pub_key_byte_vector = peer_pub_key_byte_vector;

    status->have_peer_pub_key.store(true);

    send_ack(DH_PARAMS);

    system_push_msg("Crypto: Received DH params from peer");
}

static void save_pub_key(stealthcom_L2_extension *ext) {
    pub_key_payload *payload = (pub_key_payload *)ext->payload;

    if(payload ->key_len_bits != PARAM_LEN_BITS) {
        system_push_msg("Crypto Error: length of incoming DH parameters do not match local");
    }

    std::vector<unsigned char> peer_pub_key_byte_vector(PARAM_LEN_BYTES);
    std::copy(payload->pub_key, payload->pub_key + PARAM_LEN_BYTES, peer_pub_key_byte_vector.begin());

    status->have_peer_pub_key.store(true);

    send_ack(PUB_KEY);

    system_push_msg("Crypto: Received pubkey from peer");
}

static void deliver_pub_key() {
    pub_key_payload payload;
    uint16_t payload_size = sizeof(payload);
    populate_payload(&payload);

    stealthcom_L2_extension *ext = generate_ext(KEY_EX | PUB_KEY,
                                                status->user->getMAC(),
                                                payload_size,
                                                (const char *)&payload);

    while(!status->dh_params_delivered.load() && !status->key_exchange_stop_flag.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        system_push_msg("Crypto: Sending pubkey...");
        send_packet(ext);
    }

    if(status->dh_params_delivered.load()) {
        system_push_msg("Crypto: Pubkey delivered");
    }
}

static inline void wait_for_pub_key() {
    while(!status->have_peer_pub_key.load() && !status->key_exchange_stop_flag.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    if(status->have_peer_pub_key.load()) {
        system_push_msg("Crpyto: Received pubkey");
    }
}

static bool deliver_dh_params() {
    dh_params_payload payload;
    uint16_t payload_size = sizeof(payload);
    populate_payload(&payload);

    stealthcom_L2_extension *ext = generate_ext(KEY_EX | DH_PARAMS,
                                                status->user->getMAC(),
                                                payload_size,
                                                (const char *)&payload);

    while(!status->dh_params_delivered.load() && !status->key_exchange_stop_flag.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        system_push_msg("Crypto: Sending DH params...");
        send_packet(ext);
    }

    if(status->dh_params_delivered.load()) {
        system_push_msg("Crypto: DH Params delivered");
    }
}

static void generate_dh_key_pair() {
    system_push_msg("Crypto: Generating DH key pair as initiator");

    DH* dh = DH_new();

    if (dh == nullptr) {
        system_push_msg("Crypto Error: Failed to create DH object");
        terminate_key_exchange();
        return;
    }

    if (DH_generate_parameters_ex(dh, PARAM_LEN_BITS, DH_GENERATOR_2, nullptr) != 1) {
        DH_free(dh);
        system_push_msg("Crypto Error: Failed to generate DH parameters");
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
        system_push_msg("Crypto Error: Failed to generate DH key pair");
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

    system_push_msg("Crypto: Generated DH params");
}

static std::vector<unsigned char> compute_shared_secret() {
    system_push_msg("Crypto: Received all DH parameters, generating shared secret");
    if (params->priv_key_byte_vector.empty() || params->peer_pub_key_byte_vector.empty() ||
        params->p_byte_vector.empty() || params->g_byte_vector.empty()) {
        system_push_msg("Crypto Error: Missing DH parameters or keys for shared secret computation");
        return {};
    }

    DH* dh = DH_new();
    if (dh == nullptr) {
        system_push_msg("Crypto Error: Failed to create DH object");
        return {};
    }

    BIGNUM* p = BN_bin2bn(params->p_byte_vector.data(), params->p_byte_vector.size(), nullptr);
    BIGNUM* g = BN_bin2bn(params->g_byte_vector.data(), params->g_byte_vector.size(), nullptr);
    BIGNUM* priv_key = BN_bin2bn(params->priv_key_byte_vector.data(), params->priv_key_byte_vector.size(), nullptr);
    BIGNUM* peer_pub_key = BN_bin2bn(params->peer_pub_key_byte_vector.data(), params->peer_pub_key_byte_vector.size(), nullptr);

    if (p == nullptr || g == nullptr || priv_key == nullptr || peer_pub_key == nullptr) {
        system_push_msg("Crypto Error: Failed to convert parameters to BIGNUM");
        BN_free(p);
        BN_free(g);
        BN_free(priv_key);
        BN_free(peer_pub_key);
        DH_free(dh);
        return {};
    }

    if (DH_set0_pqg(dh, p, nullptr, g) != 1) {
        system_push_msg("Crypto Error: Failed to set DH parameters");
        BN_free(p);
        BN_free(g);
        BN_free(priv_key);
        BN_free(peer_pub_key);
        DH_free(dh);
        return {};
    }

    if (DH_set0_key(dh, nullptr, priv_key) != 1) {
        system_push_msg("Crypto Error: Failed to set private key");
        BN_free(priv_key);
        BN_free(peer_pub_key);
        DH_free(dh);
        return {};
    }

    std::vector<unsigned char> shared_secret(DH_size(dh));
    int secret_size = DH_compute_key(shared_secret.data(), peer_pub_key, dh);

    if (secret_size <= 0) {
        system_push_msg("Crypto Error: Failed to compute shared secret");
        BN_free(peer_pub_key);
        DH_free(dh);
        return {};
    }

    shared_secret.resize(secret_size);

    BN_free(peer_pub_key);
    DH_free(dh);

    system_push_msg("Crypto: Generated shared secret");

    return shared_secret;
}


static std::vector<unsigned char> derive_encryption_key(const std::vector<unsigned char>& shared_secret) {
    system_push_msg("Crypto: Deriving encryption key");

    std::vector<unsigned char> encryption_key(KEY_LEN_BYTES);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) {
        system_push_msg("Crypto Error: Failed to create EVP_PKEY_CTX for HKDF");
        return {};
    }

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        system_push_msg("Crypto Error: Failed to initialize HKDF derivation");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        system_push_msg("Crypto Error: Failed to set HKDF hash function");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, nullptr, 0) <= 0) {
        system_push_msg("Crypto Error: Failed to set empty HKDF salt");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret.data(), shared_secret.size()) <= 0) {
        system_push_msg("Crypto Error: Failed to set HKDF key");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, nullptr, 0) <= 0) {
        system_push_msg("Crypto Error: Failed to set empty HKDF info");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    size_t key_len = KEY_LEN_BYTES;
    if (EVP_PKEY_derive(pctx, encryption_key.data(), &key_len) <= 0) {
        system_push_msg("Crypto Error: Failed to derive encryption key");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    EVP_PKEY_CTX_free(pctx);

    system_push_msg("Crypto: Encryption key generated");

    return encryption_key;
}

static void dh_responder() {
    while(!status->have_peer_pub_key.load() && !status->key_exchange_stop_flag.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    if(status->have_peer_pub_key.load()) {
        generate_private_key();
        generate_public_key();
        deliver_pub_key();
    } else {
        system_push_msg("Crypto: Key exchange terminated");
    }
}

static bool dh_initiator() {
    generate_dh_key_pair();
    deliver_dh_params();
    wait_for_pub_key();
}

void key_exchange_thread(StealthcomUser *user, bool initiator) {
    user_registry->protect_users();
    state_machine->set_connection_state(KEY_EXCHANGE);

    ex_status s;
    status = &s;
    status_init(user, initiator);

    dh_params p;
    params = &p;

    status->key_exchange_stop_flag.store(false);

    if(initiator) {
        dh_initiator();
    } else {
        dh_responder();
    }

    std::vector<unsigned char> shared_secret = compute_shared_secret();

    encryption_key = derive_encryption_key(shared_secret);

    state_machine->set_connection_state(CONNECTED);
    system_push_msg("Crypto: Key exchange complete - you may now securely exchange messages");

    user_registry->unprotect_users();
}

void key_exchange_packet_handler(stealthcom_L2_extension *ext) {
    uint8_t subtype = (uint8_t)ext->type & EXT_SUBTYPE_BITMASK;

    switch(subtype) {
        case DH_PARAMS: {
            if(status->initiator) {
                system_push_msg("Crypto Error: received DH params while initiator");
                break;
            }

            if(status->have_peer_pub_key.load()) {
                break;
            }

            save_dh_params(ext);
            
            break;
        }
        case DH_PARAMS_ACK: {
            if(!status->initiator) {
                system_push_msg("Crypto Error: received DH params ACK while responder");
                break;
            }
            status->dh_params_delivered.store(true);
            break;
        }
        case PUB_KEY: {
            if(!status->initiator) {
                system_push_msg("Crypto Error: received pub key while responder");
                break;
            }

            if(status->have_peer_pub_key.load()) {
                break;
            }

            save_pub_key(ext);

            break;
        }
        case PUB_KEY_ACK: {
            if(status->initiator) {
                system_push_msg("Crypto Error: received pubkey ACK while initiator");
                break;
            }
            status->dh_params_delivered.store(true);
            break;
        }
    }
}

std::string encrypt_message(const std::string& message, const std::vector<unsigned char>& key) {

}

std::string decrypt_message(const std::string& message, const std::vector<unsigned char>& key) {
    
}

void print_encryption_key() {
    if(encryption_key.empty()) {
        main_push_msg("N/A");
        return;
    } 

    for(int x = 0; x < encryption_key.size(); x += 8) {
        main_push_msg(std::to_string(encryption_key[x]) + std::to_string(encryption_key[x + 1]) + std::to_string(encryption_key[x + 2]) + std::to_string(encryption_key[x + 3])
                        + std::to_string(encryption_key[x + 4]) + std::to_string(encryption_key[x + 5]) + std::to_string(encryption_key[x + 6]) + std::to_string(encryption_key[x + 7]));
    }
}
