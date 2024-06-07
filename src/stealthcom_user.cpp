#include <cstring>
#include "stealthcom_user.h"

StealthcomUser::StealthcomUser(const std::string name, const uint8_t *MAC) {
    this->name = name;
    std::memcpy(this->MAC, MAC, 6 * sizeof(uint8_t));
}


std::string StealthcomUser::getName() const {
    return name;
}

void StealthcomUser::getMAC(uint8_t *MAC) const {
    std::memcpy(MAC, this->MAC, 6 * sizeof(uint8_t));
}