#include <iomanip>
#include "utils.h"


void print_raw_bytes(void *ptr, int n) {
    uint8_t *hex = (uint8_t *)ptr;
    for(int x = 0; x < n; x++) {
         std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*hex) << " ";
        hex++;
    }
    std::cout << std::endl;
}

std::string mac_addr_to_str(const uint8_t* macAddr) {
    std::ostringstream oss;

    for (int i = 0; i < 6; ++i) {
        if (i != 0) {
            oss << ":";
        }
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(macAddr[i]);
    }

    return oss.str();
}
