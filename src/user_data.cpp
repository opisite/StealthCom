#include <string.h>
#include "user_data.h"
#include "io_handler.h"
#include "utils.h"

uint8_t this_MAC[6] = {0};
std::string this_user_ID;

/**
 * @brief Set the MAC address of this user
 * 
 * @param MAC the MAC address of the network interface being used for the duration of the program
 */
void set_MAC(const uint8_t *MAC) {
    memcpy((void*)&this_MAC[0], MAC, 6);
}

/**
 * @brief Set the user ID if thi user
 * 
 * @param user_ID the user ID defined by the user at the start of the program
 */
void set_user_ID(const std::string& user_ID) {
    this_user_ID = user_ID;
}

/**
 * @brief Get the MAC address of the network interface being used for the current instance of the program
 * 
 * @return const uint8_t* a pointer to a 6 byte array containing the MAC address
 */
const uint8_t * get_MAC() {
    return &this_MAC[0];
}

/**
 * @brief Get the user ID of this user
 * 
 * @return std::string& a string containing the user ID of this user
 */
std::string& get_user_ID() {
    return this_user_ID;
}

