#ifndef STEALTHCOM_USER_H
#define STEALTHCOM_USER_H

#include <string>

class StealthcomUser {
    public:
        StealthcomUser(const std::string name, const uint8_t *MAC);
        std::string getName() const;
        void getMAC(uint8_t *MAC) const;

    private:
        std::string name;
        uint8_t MAC[6];
};

#endif
