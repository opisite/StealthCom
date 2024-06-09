#ifndef IO_HANDLER_H
#define IO_HANDLER_H

#include <string>

void ncurses_init();
void io_clr_output();
void output_push_msg(const std::string& message);
void ncurses_thread();

#endif
