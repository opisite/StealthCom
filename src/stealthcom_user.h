#ifndef STEALTHCOM_USER_H
#define STEALTHCOM_USER_H

#include <string>
#include <array>

class StealthcomUser {
    public:
        StealthcomUser(const std::string name, const uint8_t *MAC);
        std::string getName() const;
        std::array<uint8_t, 6> getMAC() const;

    private:
        std::string name;
        std::array<uint8_t, 6> MAC;
};

#endif
