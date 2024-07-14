#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>
#include <openssl/dh.h>

void key_exchange_thread(bool master);

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> generate_dh_key_pair();
std::vector<unsigned char> compute_shared_secret(const std::vector<unsigned char>& private_key, const std::vector<unsigned char>& public_key);
std::string encrypt_message(const std::string& message, const std::vector<unsigned char>& key);
std::string decrypt_message(const std::string& message, const std::vector<unsigned char>& key);


#endif
