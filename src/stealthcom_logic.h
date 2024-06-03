#ifndef STEALTHCOM_LOGIC_H
#define STEALTHCOM_LOGIC_H

#include <string>

#define USER_ID_MAX_LEN 16

void stealthcom_init(const char *netif);
void stealthcom_main_thread();
void input_push_msg(const std::string message);
bool is_valid_user_id(const std::string user_ID);

#endif