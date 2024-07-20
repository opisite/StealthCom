#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>
#include <openssl/dh.h>
#include "stealthcom_user.h"
#include "stealthcom_pkt_handler.h"

void key_exchange_thread(StealthcomUser *user, bool initiatior);
void key_exchange_packet_handler(stealthcom_L2_extension *ext);
std::string encrypt_message(const std::string& message, const std::vector<unsigned char>& key);
std::string decrypt_message(const std::string& message, const std::vector<unsigned char>& key);
void print_encryption_key();


#endif
