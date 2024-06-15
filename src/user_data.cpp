#include <string.h>
#include "user_data.h"
#include "io_handler.h"
#include "utils.h"

uint8_t this_MAC[6] = {0};
std::string this_user_ID;

void set_MAC(const uint8_t *MAC) {
    memcpy((void*)&this_MAC[0], MAC, 6);
}

void set_user_ID(const std::string& user_ID) {
    this_user_ID = user_ID;
}

const uint8_t * get_MAC() {
    return &this_MAC[0];
}


std::string& get_user_ID() {
    return this_user_ID;
}

