#include <cstring>
#include "stealthcom_user.h"

StealthcomUser::StealthcomUser(const std::string name, const uint8_t *MAC) : name(name) {
    memcpy(&this->MAC[0], MAC, 6);
}

std::string StealthcomUser::getName() const {
    return name;
}

std::array<uint8_t, 6> StealthcomUser::getMAC() const {
    return MAC;
}
