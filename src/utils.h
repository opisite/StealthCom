#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <memory>
#include <string>

void print_raw_bytes(void *ptr, int n);
std::string mac_addr_to_str(const uint8_t* macAddr);

#endif