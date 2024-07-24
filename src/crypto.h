#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>
#include <openssl/dh.h>
#include "stealthcom_user.h"
#include "stealthcom_pkt_handler.h"

void key_exchange_thread(StealthcomUser *user, bool initiatior);
void key_exchange_packet_handler(stealthcom_L2_extension *ext);
void* encrypt(const unsigned char* buffer, uint16_t length, uint16_t& out_length);
void* decrypt(const unsigned char* buffer, uint16_t length, uint16_t& out_length);
void print_encryption_key();


#endif
