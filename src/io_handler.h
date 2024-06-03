#ifndef IO_HANDLER_H
#define IO_HANDLER_H

#include <string>

void io_init();
void io_clr_output();
void io_push_msg(const std::string message);
void output_thread();
void input_thread();

#endif