#include <cstring>
#include "stealthcom_user.h"

/**
 * @brief Construct a new StealthcomUser object
 * 
 * @param name the userID of the user
 * @param MAC the MAC address of the user
 */
StealthcomUser::StealthcomUser(const std::string name, const uint8_t *MAC) : name(name) {
    memcpy(&this->MAC[0], MAC, 6);
}

/**
 * @brief Get the name of a StealthcomUser
 * 
 * @return std::string a string containing the userID of user
 */
std::string StealthcomUser::getName() const {
    return name;
}

/**
 * @brief Get the MAC address of a StealthcomUser
 * 
 * @return std::array<uint8_t, 6> a 6 byte array containing the MAC address of user
 */
std::array<uint8_t, 6> StealthcomUser::getMAC() const {
    return MAC;
}
