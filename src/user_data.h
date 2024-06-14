#ifndef USER_DATA_H
#define USER_DATA_H

#include <string>

void set_MAC(const uint8_t *MAC);
void set_user_ID(const std::string& user_ID);
const uint8_t * get_MAC();
std::string& get_user_ID();
bool is_self(const uint8_t *MAC);

#endif
