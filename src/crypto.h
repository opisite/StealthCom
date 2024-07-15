#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>
#include <openssl/dh.h>
#include "stealthcom_user.h"

void key_exchange_thread(StealthcomUser *user, bool initiatior);

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> generate_dh_key_pair();
std::string encrypt_message(const std::string& message, const std::vector<unsigned char>& key);
std::string decrypt_message(const std::string& message, const std::vector<unsigned char>& key);


#endif
