#ifndef STEALTHCOM_LOGIC_H
#define STEALTHCOM_LOGIC_H

#include <string>
#include "stealthcom_user.h"

#define USER_ID_MAX_LEN 16

void stealthcom_init(const char *netif);
void stealthcom_main_thread();
void input_push_msg(const std::string message);
bool is_valid_user_ID(const std::string user_ID);
StealthcomUser *set_user_data(const std::string user_ID);


#endif