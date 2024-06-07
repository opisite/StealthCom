#include <ncurses.h>
#include <cstring>
#include <iostream>
#include <sstream>
#include <streambuf>
#include <string>
#include <mutex>
#include <thread>

#include "message_queue.h"
#include "stealthcom_logic.h"
#include "io_handler.h"

#define INPUT_BUFFER_SIZE 256

static MessageQueue *output_queue;

static WINDOW *input_win;
static WINDOW *message_win;
static char *input;

static std::mutex mtx;

void ncurses_init() {
    initscr();
    cbreak();
    keypad(stdscr, TRUE);
    noecho();

    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    input_win = newwin(1, cols, rows - 1, 0);
    message_win = newwin(rows - 3, cols, 0, 0);

    scrollok(message_win, TRUE);

    input = new char[INPUT_BUFFER_SIZE];
    memset(input, 0, INPUT_BUFFER_SIZE);

    nodelay(input_win, TRUE);

    output_queue = new MessageQueue();
}

void io_clr_output() {
    std::lock_guard<std::mutex> lock(mtx);
    wclear(message_win);
    wrefresh(message_win);
}

void output_push_msg(const std::string& message) {
    output_queue->push(message);
}

void ncurses_thread() {
    std::stringstream buffer;
    std::streambuf* old = std::cerr.rdbuf(buffer.rdbuf());

    int input_index = 0;
    int c;

    while (true) {
        {
            std::lock_guard<std::mutex> lock(mtx);
            c = wgetch(input_win);
        }
        if (c != ERR) {
            if ((c == KEY_BACKSPACE || c == 127 || c == 8) && input_index > 0) {
                input[--input_index] = '\0';
            } else if (c == '\n') {
                input[input_index] = '\0';
                if (std::strcmp(input, "exit") == 0) {
                    break;
                }
                
                input_push_msg(input);
                input_index = 0;
                memset(input, 0, INPUT_BUFFER_SIZE);
            } else if (c >= 32 && c < 127 && input_index < INPUT_BUFFER_SIZE - 1) {
                input[input_index++] = c;
                input[input_index] = '\0';
            }

            {
                std::lock_guard<std::mutex> lock(mtx);
                wclear(input_win);
                mvwprintw(input_win, 0, 0, "> %s", input);
                wrefresh(input_win);
            }
        }

        while (!output_queue->empty()) {
            std::string msg = output_queue->pop();
            {
                std::lock_guard<std::mutex> lock(mtx);
                wprintw(message_win, "%s\n", msg.c_str());
                wrefresh(message_win);
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::cerr.rdbuf(old);

    delwin(input_win);
    delwin(message_win);
    endwin();
}
