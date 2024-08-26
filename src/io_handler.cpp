#include <ncurses.h>
#include <cstring>
#include <iostream>
#include <sstream>
#include <streambuf>
#include <string>
#include <mutex>
#include <thread>

#include "stealthcom_logic.h"
#include "io_handler.h"

#define INPUT_BUFFER_SIZE 256
#define INITIAL_WINDOW_LINE 1

static InputQueue *main_queue;
static InputQueue *system_queue;

static WINDOW *input_win;
static WINDOW *system_win;
static WINDOW *main_win;
static WINDOW *system_win_buffer;
static WINDOW *main_win_buffer;
static WINDOW *main_win_sub;
static WINDOW *system_win_sub;
static char *input;

static std::mutex mtx;

static int main_win_line = INITIAL_WINDOW_LINE;
static int system_win_line = INITIAL_WINDOW_LINE;

/**
 * @brief Draw the system window box on the screen
 * 
 */
static void draw_sys_window() {
    werase(system_win_buffer);
    box(system_win_buffer, 0, 0);
    mvwprintw(system_win_buffer, 0, 2, "SYSTEM");
    wrefresh(system_win_buffer);
}

/**
 * @brief Draw the main window box on the screen
 * 
 */
static void draw_main_window() {
    werase(main_win_buffer);
    box(main_win_buffer, 0, 0);
    mvwprintw(main_win_buffer, 0, 2, "MAIN");
    wrefresh(main_win_buffer);
}

/**
 * @brief Initialize ncurses and all boxes
 * 
 */
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

    main_win_buffer = newwin(rows / 2, cols, 0, 0);
    system_win_buffer = newwin(rows / 2, cols, rows / 2, 0);

    // Create sub-windows inside the buffer windows for content
    main_win_sub = derwin(main_win_buffer, rows / 2 - 2, cols - 2, 1, 1);
    system_win_sub = derwin(system_win_buffer, rows / 2 - 2, cols - 2, 1, 1);

    draw_main_window();
    draw_sys_window();

    // Enable scrolling for sub-windows
    scrollok(main_win_sub, TRUE);
    scrollok(system_win_sub, TRUE);

    input = new char[INPUT_BUFFER_SIZE];
    memset(input, 0, INPUT_BUFFER_SIZE);

    nodelay(input_win, TRUE);

    main_queue = new InputQueue();
    system_queue = new InputQueue();
}

/**
 * @brief Clear the output on the main window
 * 
 */
void io_clr_output() {
    std::lock_guard<std::mutex> lock(mtx);
    main_queue->clear();
    main_win_line = INITIAL_WINDOW_LINE;
    werase(main_win_sub);
    draw_main_window();
}

/**
 * @brief Print a message to the main window
 * 
 * @param message the string to print
 */
void main_push_msg(const std::string& message) {
    main_queue->push(message);
}

/**
 * @brief Print a message to the system window
 * 
 * @param message the string to print
 */
void system_push_msg(const std::string& message) {
    system_queue->push(message);
}

/**
 * @brief (thread) handle all IO operations through ncurses
 * 
 */
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
                werase(input_win);
                mvwprintw(input_win, 0, 0, "> %s", input);
                wrefresh(input_win);
            }
        }

        while (!main_queue->empty()) {  // Empty main_queue into main window buffer
            std::string msg = main_queue->pop();
            {
                std::lock_guard<std::mutex> lock(mtx);
                if (main_win_line >= getmaxy(main_win_sub)) {
                    wscrl(main_win_sub, 1);
                    main_win_line = getmaxy(main_win_sub) - 1;
                }
                mvwprintw(main_win_sub, main_win_line++, 0, "%s", msg.c_str());
                wrefresh(main_win_sub);
                wrefresh(main_win_buffer);
            }
        }

        while (!system_queue->empty()) {  // Empty system_queue into system window buffer
            std::string msg = system_queue->pop();
            {
                std::lock_guard<std::mutex> lock(mtx);
                if (system_win_line >= getmaxy(system_win_sub)) {
                    wscrl(system_win_sub, 1);
                    system_win_line = getmaxy(system_win_sub) - 1;
                }
                mvwprintw(system_win_sub, system_win_line++, 0, "%s", msg.c_str());
                wrefresh(system_win_sub);
                wrefresh(system_win_buffer);
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::cerr.rdbuf(old);

    delwin(input_win);
    delwin(main_win);
    delwin(system_win);
    delwin(main_win_buffer);
    delwin(system_win_buffer);
    delwin(main_win_sub);
    delwin(system_win_sub);
    endwin();
}
