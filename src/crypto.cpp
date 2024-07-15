#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "crypto.h"
#include "io_handler.h"
#include "stealthcom_connection_logic.h"
#include "stealthcom_state_machine.h"
#include "user_registry.h"

std::atomic<bool> key_exchange_stop_flag;
static DH *dh;

static void terminate_key_exchange() {
    state_machine->reset_connection_context();
    key_exchange_stop_flag.store(true);
}

static void generate_dh_params() {
    dh = DH_new();
    if (dh == nullptr) {
        system_push_msg("Failed to create DH object");
        terminate_key_exchange();
        return;
    }

    if (DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, nullptr) != 1) {
        DH_free(dh);
        system_push_msg("Failed to generate DH parameters");
        terminate_key_exchange();
        return;
    }
}

void key_exchange_thread(StealthcomUser *user, bool initiatior) {
    user_registry->protect_users();
    state_machine->set_connection_state(KEY_EXCHANGE);
    key_exchange_stop_flag.store(false);

    if(initiatior) {

    }


    while(true) {
        if(key_exchange_stop_flag.load()) {
            system_push_msg("Key exchange terminated");
            break;
        }
    }

    free(dh);
    user_registry->unprotect_users();
}

std::vector<unsigned char> compute_shared_secret(const std::vector<unsigned char>& private_key, const std::vector<unsigned char>& public_key) {

}

std::string encrypt_message(const std::string& message, const std::vector<unsigned char>& key) {

}

std::string decrypt_message(const std::string& message, const std::vector<unsigned char>& key) {
    
}
