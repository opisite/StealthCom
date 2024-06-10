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
#define INITIAL_WINDOW_LINE 2

static MessageQueue *main_queue;
static MessageQueue *system_queue;

static WINDOW *input_win;
static WINDOW *system_win;
static WINDOW *main_win;
static char *input;

static std::mutex mtx;

static int main_win_line = INITIAL_WINDOW_LINE;
static int system_win_line = INITIAL_WINDOW_LINE;

static void draw_sys_window() {
    box(system_win, 0, 0);
    wprintw(system_win, "SYSTEM");
    wrefresh(system_win);
}

static void draw_main_window() {
    box(main_win, 0, 0);
    wprintw(main_win, "MAIN");
    wrefresh(main_win);
}

void ncurses_init() {
    initscr();
    cbreak();
    keypad(stdscr, TRUE);
    noecho();

    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    input_win = newwin(1, cols, --rows, 0);
    main_win = newwin(rows / 2, cols, 0, 0);
    system_win = newwin(rows / 2, cols, rows / 2, 0);

    draw_main_window();
    draw_sys_window();

    scrollok(main_win, TRUE);

    input = new char[INPUT_BUFFER_SIZE];
    memset(input, 0, INPUT_BUFFER_SIZE);

    nodelay(input_win, TRUE);

    main_queue = new MessageQueue();
    system_queue = new MessageQueue();
}

void io_clr_output() {
    std::lock_guard<std::mutex> lock(mtx);
    main_win_line = INITIAL_WINDOW_LINE;
    wclear(main_win);
    draw_main_window();
    wrefresh(main_win);
}

void main_push_msg(const std::string& message) {
    main_queue->push(message);
}

void system_push_msg(const std::string& message) {
    system_queue->push(message);
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

        while (!main_queue->empty()) {  // Empty main_queue into main window
            std::string msg = main_queue->pop();
            {
                std::lock_guard<std::mutex> lock(mtx);
                mvwprintw(main_win, main_win_line++, 2,  "%s\n", msg.c_str());
                wrefresh(main_win);
            }
        }

        while (!system_queue->empty()) {    // Empty system_queue into system window
            std::string msg = system_queue->pop();
            {
                std::lock_guard<std::mutex> lock(mtx);
                mvwprintw(system_win, system_win_line++, 2,  "%s\n", msg.c_str());
                wrefresh(system_win);
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::cerr.rdbuf(old);

    delwin(input_win);
    delwin(main_win);
    delwin(system_win);
    endwin();
}
