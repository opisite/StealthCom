#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
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
#define GENERATOR_SIZE   1

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

struct __attribute__((packed)) dh_params_payload {
    uint16_t item_len_bits;
    uint16_t generator_size;
    unsigned char pub_key[PARAM_LEN_BYTES];
    unsigned char p[PARAM_LEN_BYTES];
    unsigned char g[GENERATOR_SIZE];
};

struct  __attribute__((packed)) pub_key_payload {
    uint16_t key_len_bits;
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

/**
 * @brief stops the key exchange process
 * 
 */
static void terminate_key_exchange() {
    state_machine->reset_connection_context();
    status->key_exchange_stop_flag.store(true);
}

/**
 * @brief Generates a private key using parameters received by the initiator (this is to be used by the DH responder)
 * 
 */
static void generate_private_key() {
    system_push_msg("Crypto: Generating private key...");

    BIGNUM* priv_key = BN_new();
    if (!priv_key) {
        system_push_msg("Crypto Error: Failed to allocate memory for BIGNUM");
        return;
    }

    BIGNUM* p = BN_bin2bn(params->p_byte_vector.data(), params->p_byte_vector.size(), nullptr);
    if (!p) {
        system_push_msg("Crypto Error: Failed to convert p to BIGNUM");
        BN_free(priv_key);
        return;
    }

    BIGNUM* p_minus_1 = BN_dup(p);
    if (!BN_sub_word(p_minus_1, 1)) {
        system_push_msg("Crypto Error: Failed to compute p-1");
        BN_free(priv_key);
        BN_free(p);
        BN_free(p_minus_1);
        return;
    }

    if (!BN_rand_range(priv_key, p_minus_1) || BN_is_zero(priv_key) || BN_is_one(priv_key)) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        std::string error_message = "Crypto Error: Failed to generate valid private key in range [1, p-1]: ";
        error_message += err_buf;
        system_push_msg(error_message.c_str());
        
        BN_free(priv_key);
        BN_free(p);
        BN_free(p_minus_1);
        return;
    }

    if (!BN_add_word(priv_key, 1)) {
        system_push_msg("Crypto Error: Failed to adjust private key to range [1, p-1]");
        BN_free(priv_key);
        BN_free(p);
        BN_free(p_minus_1);
        return;
    }

    std::vector<unsigned char> priv_key_byte_vector(BN_num_bytes(priv_key));
    BN_bn2bin(priv_key, priv_key_byte_vector.data());
    params->priv_key_byte_vector = priv_key_byte_vector;

    BN_free(priv_key);
    BN_free(p);
    BN_free(p_minus_1);
}

/**
 * @brief Generates a public key using parameters received by the initiator (this is to be used by the DH responder)
 * 
 */
static void generate_public_key() {
    system_push_msg("Crypto: Generating public key...");

    if (params->priv_key_byte_vector.empty() || 
        params->p_byte_vector.empty() || 
        params->g_byte_vector.empty()) {
        system_push_msg("Crypto Error: Missing private key or DH parameters");
        return;
    }

    if (params->priv_key_byte_vector.size() != PARAM_LEN_BYTES || 
        params->p_byte_vector.size() != PARAM_LEN_BYTES || 
        params->g_byte_vector.size() != GENERATOR_SIZE) {
        system_push_msg("Crypto Error: One or more DH parameter have incorrect length");
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
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        std::string error_message = "Crypto Error: Failed to generate public key: ";
        error_message += err_buf;
        system_push_msg(error_message.c_str());
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

    system_push_msg("Crypto: Generated public key");

    DH_free(dh);
}

/**
 * @brief send an ack in response to DH params or pub key
 * 
 * @param subtype the subtype of the ACK to be sent (PUB_KEY_ACK or DH_PARAMS_ACK)
 */
static void send_ack(int subtype) {
    stealthcom_L2_extension *ext = generate_ext(KEY_EX | subtype,
                                                status->user->getMAC());

    for(int x = 0; x < 3; x++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        send_packet(ext);
    }
    free(ext);
}

/**
 * @brief Save the incoming pubkey into memory
 * 
 * @param ext the stealthcom_L2_extenstion containing the pubkey payload
 */
static void save_pub_key(stealthcom_L2_extension *ext) {
    pub_key_payload *payload = (pub_key_payload *)ext->payload;

    if(payload->key_len_bits != PARAM_LEN_BITS) {
        system_push_msg("Crypto Error: length of incoming pubkey does not match expected: " + std::to_string(static_cast<int>(payload->key_len_bits)));
    }

    std::vector<unsigned char> peer_pub_key_byte_vector(PARAM_LEN_BYTES);
    std::copy(payload->pub_key, payload->pub_key + PARAM_LEN_BYTES, peer_pub_key_byte_vector.begin());
    params->peer_pub_key_byte_vector = peer_pub_key_byte_vector;

    status->have_peer_pub_key.store(true);

    send_ack(PUB_KEY_ACK);

    system_push_msg("Crypto: Received pubkey from peer");
}

/**
 * @brief Populate a pub_key_payload struct with the generated pubkey (as DH responder)
 * 
 * @param payload the payload to copy the pubkey into
 */
static void populate_payload(pub_key_payload *payload) {
    if (params->pub_key_byte_vector.size() != PARAM_LEN_BYTES) {
        system_push_msg("Crypto Error: Vector size does not match expected: " + std::to_string(params->pub_key_byte_vector.size()));
        return;
    }

    payload->key_len_bits = PARAM_LEN_BITS;
    std::copy(params->pub_key_byte_vector.begin(), params->pub_key_byte_vector.end(), payload->pub_key);
}

/**
 * @brief Generate an L2 extension with the pubkey payload appended to the end and deliver it to the DH initiator
 * 
 */
static void deliver_pub_key() {
    pub_key_payload payload;
    ext_payload_len_t payload_size = sizeof(payload);
    populate_payload(&payload);

    stealthcom_L2_extension *ext = generate_ext(KEY_EX | PUB_KEY,
                                                status->user->getMAC(),
                                                payload_size,
                                                (const char *)&payload);

    while(!status->dh_params_delivered.load() && !status->key_exchange_stop_flag.load()) {
        system_push_msg("Crypto: Sending pubkey...");
        send_packet(ext);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    free(ext);
}

/**
 * @brief wait to receive the DH responders pubkey
 * 
 */
static inline void wait_for_pub_key() {
    while(!status->have_peer_pub_key.load() && !status->key_exchange_stop_flag.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

static void save_dh_params(stealthcom_L2_extension *ext) {
    dh_params_payload *payload = (dh_params_payload *)ext->payload;

    if (payload->item_len_bits != PARAM_LEN_BITS) {
        system_push_msg("Crypto Error: length of incoming DH parameters do not match expected: " + std::to_string(static_cast<int>(payload->item_len_bits)));
        return;
    }
    if (payload->generator_size != GENERATOR_SIZE) {
        system_push_msg("Crypto Error: length of incoming generator does not match expected: " + std::to_string(static_cast<int>(payload->generator_size)));
        return;
    }

    std::vector<unsigned char> p_byte_vector(PARAM_LEN_BYTES);
    std::vector<unsigned char> g_byte_vector(GENERATOR_SIZE);
    std::vector<unsigned char> peer_pub_key_byte_vector(PARAM_LEN_BYTES);

    std::copy(payload->p, payload->p + PARAM_LEN_BYTES, p_byte_vector.begin());
    std::copy(payload->g, payload->g + GENERATOR_SIZE, g_byte_vector.begin());
    std::copy(payload->pub_key, payload->pub_key + PARAM_LEN_BYTES, peer_pub_key_byte_vector.begin());

    params->p_byte_vector = p_byte_vector;
    params->g_byte_vector = g_byte_vector;
    params->peer_pub_key_byte_vector = peer_pub_key_byte_vector;

    status->have_peer_pub_key.store(true);

    send_ack(DH_PARAMS_ACK);

    system_push_msg("Crypto: Received DH params from peer");
}

/**
 * @brief Save the incoming DH params into memory
 * 
 * @param ext the stealthcom_L2_extenstion containing the DH params payload
 */
static void populate_payload(dh_params_payload *payload) {
    if (params->pub_key_byte_vector.size() != PARAM_LEN_BYTES ||
        params->p_byte_vector.size() != PARAM_LEN_BYTES ||
        params->g_byte_vector.size() != GENERATOR_SIZE) {
        system_push_msg("Crypto Error: Vector sizes do not match expected: " + std::to_string(params->pub_key_byte_vector.size()) 
                            + ", " + std::to_string(params->p_byte_vector.size()) + ", " + std::to_string(params->g_byte_vector.size()));
        return;
    }

    payload->item_len_bits = PARAM_LEN_BITS;
    payload->generator_size = GENERATOR_SIZE;
    std::copy(params->pub_key_byte_vector.begin(), params->pub_key_byte_vector.end(), payload->pub_key);
    std::copy(params->p_byte_vector.begin(), params->p_byte_vector.end(), payload->p);
    std::copy(params->g_byte_vector.begin(), params->g_byte_vector.end(), payload->g);
}

/**
 * @brief Generate an L2 extension with a DH params payload appended to the end and deliver it to the DH responder
 * 
 */
static bool deliver_dh_params() {
    dh_params_payload payload;
    ext_payload_len_t payload_size = sizeof(payload);
    populate_payload(&payload);

    stealthcom_L2_extension *ext = generate_ext(KEY_EX | DH_PARAMS,
                                                status->user->getMAC(),
                                                payload_size,
                                                (const char *)&payload);

    dh_params_payload *payload_ext = (dh_params_payload *)ext->payload;

    while(!status->dh_params_delivered.load() && !status->key_exchange_stop_flag.load()) {
        system_push_msg("Crypto: Sending DH params...");
        send_packet(ext);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    free(ext);
}

/**
 * @brief generate prime modulo, generator, private key, public key as DH initiator
 * 
 */
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

    if (p == nullptr || g == nullptr) {
        system_push_msg("Crypto Error: Failed to get DH parameters p or g");
        DH_free(dh);
        terminate_key_exchange();
        return;
    }

    std::vector<unsigned char> p_byte_vector(BN_num_bytes(p));
    BN_bn2bin(p, p_byte_vector.data());
    std::vector<unsigned char> g_byte_vector(BN_num_bytes(g));
    BN_bn2bin(g, g_byte_vector.data());

    if(p_byte_vector.size() != PARAM_LEN_BYTES) {
        system_push_msg("Crypto Error: Incorrect p vector size: " + std::to_string(p_byte_vector.size()));
    }
    if(g_byte_vector.size() != GENERATOR_SIZE) {
        system_push_msg("Crypto Error: Incorrect g vector size: " + std::to_string(g_byte_vector.size()));
    }

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

    if (pub_key == nullptr || priv_key == nullptr) {
        system_push_msg("Crypto Error: Failed to get DH keys");
        DH_free(dh);
        terminate_key_exchange();
        return;
    }

    std::vector<unsigned char> public_key(BN_num_bytes(pub_key));
    BN_bn2bin(pub_key, public_key.data());
    params->pub_key_byte_vector = public_key;

    std::vector<unsigned char> private_key(BN_num_bytes(priv_key));
    BN_bn2bin(priv_key, private_key.data());
    params->priv_key_byte_vector = private_key;

    DH_free(dh);

    system_push_msg("Crypto: Generated DH params");
}

/**
 * @brief Generate a shared secret using all DH params. This should be done after initiator and responder successfully exchange pubkeys
 * 
 * @return std::vector<unsigned char> a byte vector containing the shared secret
 */
static std::vector<unsigned char> compute_shared_secret() {
    system_push_msg("Crypto: Received all DH parameters, generating shared secret");
    if (params->priv_key_byte_vector.empty() || params->peer_pub_key_byte_vector.empty() ||
        params->p_byte_vector.empty() || params->g_byte_vector.empty()) {
        system_push_msg("Crypto Error: Missing DH parameters or keys for shared secret computation: " +
                            params->priv_key_byte_vector.empty() +
                            params->peer_pub_key_byte_vector.empty() +
                            params->p_byte_vector.empty() +
                            params->g_byte_vector.empty());
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

/**
 * @brief Derive the encryption key using the shared secret
 * 
 * @param shared_secret the shared secret derived by compute_shared_secret()
 * @return std::vector<unsigned char> a byte vector containing the encryption key
 */
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

/**
 * @brief facilitate DH key exchange as the responder
 * 
 */
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

/**
 * @brief facilitate DH key exchange as the initiator
 * 
 * @return true 
 * @return false 
 */
static bool dh_initiator() {
    generate_dh_key_pair();
    deliver_dh_params();
    wait_for_pub_key();
}

/**
 * @brief (thread) facilitate the DH key exchange and generation of encryption keys for both the initiator and responder
 * 
 * @param user the user that the key exchange is being done with
 * @param initiator whether this device is the initiator or responder
 */
void key_exchange_thread(StealthcomUser *user, bool initiator) {
    user_registry->protect_users();

    system_push_msg("Crypto: Beginning key exchange with " + std::to_string(PARAM_LEN_BITS) + " bit parameters (" + std::to_string(PARAM_LEN_BYTES) + ") bytes");

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

    begin_connection(user);
    system_push_msg("Crypto: Key exchange complete - you may now securely exchange messages");

    user_registry->unprotect_users();
}

/**
 * @brief handle all packets received with type KEY_EX
 * 
 * @param ext the stealthcom_L2_extension with type KEY_EX
 */
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

            if(!status->dh_params_delivered.load()) {
                system_push_msg("Crypto: DH Params delivered");
                status->dh_params_delivered.store(true);
            }
            
            break;
        }
        case PUB_KEY: {
            if(!status->initiator) {
                system_push_msg("Crypto Error: received pubkey while responder");
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

            if(!status->dh_params_delivered.load()) {
                system_push_msg("Crypto: Pubkey delivered");
                status->dh_params_delivered.store(true);
            }
            
            break;
        }
    }
}

static const unsigned int IV_LEN = 16;
static const unsigned int TAG_LEN = 16;

/**
 * @brief Encrypt a buffer using the encryption key
 * 
 * @param buffer the buffer to be encrypted
 * @param length the length of the input buffer
 * @param out_length a reference to location where the encrypted buffer size should be stored
 * @return void* a pointer to a buffer containing the encrypted data with size out_length
 */
void* encrypt(const unsigned char* buffer, uint16_t length, uint16_t& out_length) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        system_push_msg("Crypto Error: Failed to create EVP_CIPHER_CTX");
        return nullptr;
    }

    std::vector<unsigned char> iv(IV_LEN);
    if (RAND_bytes(iv.data(), IV_LEN) != 1) {
        system_push_msg("Crypto Error: Failed to generate IV");
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        system_push_msg("Crypto Error: Failed to initialize AES-256-GCM encryption");
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, encryption_key.data(), iv.data()) != 1) {
        system_push_msg("Crypto Error: Failed to set encryption key and IV");
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    unsigned char* ciphertext = new unsigned char[length + IV_LEN + TAG_LEN];
    memcpy(ciphertext, iv.data(), IV_LEN);

    if (EVP_EncryptUpdate(ctx, ciphertext + IV_LEN, &len, buffer, length) != 1) {
        system_push_msg("Crypto Error: Failed to encrypt plaintext");
        EVP_CIPHER_CTX_free(ctx);
        delete[] ciphertext;
        return nullptr;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + IV_LEN + len, &len) != 1) {
        system_push_msg("Crypto Error: Failed to finalize encryption");
        EVP_CIPHER_CTX_free(ctx);
        delete[] ciphertext;
        return nullptr;
    }
    ciphertext_len += len;

    std::vector<unsigned char> tag(TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data()) != 1) {
        system_push_msg("Crypto Error: Failed to get GCM tag");
        EVP_CIPHER_CTX_free(ctx);
        delete[] ciphertext;
        return nullptr;
    }

    memcpy(ciphertext + IV_LEN + ciphertext_len, tag.data(), TAG_LEN);

    out_length = IV_LEN + ciphertext_len + TAG_LEN;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

/**
 * @brief Decrypt a buffer using the encryption key
 * 
 * @param buffer the buffer to be decrypted
 * @param length the length of the input buffer
 * @param out_length a reference to location where the decrypted buffer size should be stored
 * @return void* a pointer to a buffer containing the decrypted data with size out_length
 */
void* decrypt(const unsigned char* buffer, uint16_t length, uint16_t& out_length) {
    if (length < IV_LEN + TAG_LEN) {
        system_push_msg("Crypto Error: Ciphertext too short");
        return nullptr;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        system_push_msg("Crypto Error: Failed to create EVP_CIPHER_CTX");
        return nullptr;
    }

    const unsigned char* iv = buffer;
    const unsigned char* tag = buffer + length - TAG_LEN;
    const unsigned char* encrypted_message = buffer + IV_LEN;
    size_t encrypted_message_len = length - IV_LEN - TAG_LEN;

    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        system_push_msg("Crypto Error: Failed to initialize AES-256-GCM decryption");
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, encryption_key.data(), iv) != 1) {
        system_push_msg("Crypto Error: Failed to set decryption key and IV");
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    unsigned char* plaintext = new unsigned char[encrypted_message_len];

    if (EVP_DecryptUpdate(ctx, plaintext, &len, encrypted_message, encrypted_message_len) != 1) {
        system_push_msg("Crypto Error: Failed to decrypt ciphertext");
        EVP_CIPHER_CTX_free(ctx);
        delete[] plaintext;
        return nullptr;
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag) != 1) {
        system_push_msg("Crypto Error: Failed to set GCM tag");
        EVP_CIPHER_CTX_free(ctx);
        delete[] plaintext;
        return nullptr;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        system_push_msg("Crypto Error: Failed to finalize decryption");
        EVP_CIPHER_CTX_free(ctx);
        delete[] plaintext;
        return nullptr;
    }
    plaintext_len += len;

    out_length = plaintext_len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

/**
 * @brief Print the encryption key to the main window
 * 
 */
void print_encryption_key() {
    if (encryption_key.empty()) {
        main_push_msg("N/A");
        return;
    }

    std::string hex_line;
    for (size_t i = 0; i < encryption_key.size(); ++i) {
        char hex_byte[3];
        snprintf(hex_byte, sizeof(hex_byte), "%02x", encryption_key[i]);
        hex_line += hex_byte;

        if ((i + 1) % 8 == 0) {
            main_push_msg(hex_line.c_str());
            hex_line.clear();
        }
    }

    if (!hex_line.empty()) {
        main_push_msg(hex_line.c_str());
    }
}
