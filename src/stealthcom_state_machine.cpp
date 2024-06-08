#include <stdexcept>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <chrono>

#include "stealthcom_state_machine.h"
#include "io_handler.h"
#include "stealthcom_logic.h"
#include "user_data.h"
#include "stealthcom_pkt_handler.h"
#include "user_registry.h"
#include "utils.h"

std::atomic<bool> stop_flag;
std::mutex running_mtx;

static const struct {
    std::string key;
    State state;
} menu_items[] = {
    { "Show users", SHOW_USERS },
    { "Settings", SETTINGS },
    { "Details", DETAILS },
};

static const int menu_items_size = sizeof(menu_items) / sizeof(menu_items[0]);

static void print_menu_items() {
    output_push_msg("MENU");
    for(int x = 0; x < menu_items_size; x++) {
        output_push_msg(std::to_string(x + 1) + ": " + menu_items[x].key);
    }
}

static void print_user_details() {
    output_push_msg("User ID: " + get_user_ID());
    output_push_msg("User MAC: " + mac_addr_to_str(get_MAC()));
}

static void print_users_thread() {
    stop_flag.store(true);
    std::lock_guard<std::mutex> lock(running_mtx);
    stop_flag.store(false);

    while(!stop_flag.load()) {
        std::vector<StealthcomUser*> users = user_registry->get_users();
        io_clr_output();
        for(int x = 0; x < users.size(); x++) {
            output_push_msg(std::to_string(x + 1));
            output_push_msg("MAC Address: " + mac_addr_to_str(users[x]->getMAC().data()));
            output_push_msg("User ID: " + users[x]->getName());
            output_push_msg("\n");
        }
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
}

StealthcomStateMachine::StealthcomStateMachine() {
    stop_flag.store(false);
    set_state(ENTER_USER_ID);
}

void StealthcomStateMachine::set_state(State state) {
    this->state = state;
    print_state_msg(state);
}

void StealthcomStateMachine::print_state_msg(State state) {
    io_clr_output();
    switch (state) {
        case ENTER_USER_ID: {
            output_push_msg("Enter your user ID (" + std::to_string(USER_ID_MAX_LEN) + " CHARACTERS MAX)");
            break;
        }
        case MENU: {
            print_menu_items();
            break;
        }
        case DETAILS: {
            print_user_details();
            break;
        }
        case SHOW_USERS: {
            std::thread showUsersThread(print_users_thread);
            showUsersThread.detach();
            break;
        }
    }
}

void StealthcomStateMachine::handle_input(const std::string& input) {
    switch(state) {
        case ENTER_USER_ID: {
            if(is_valid_user_ID(input)) {
                set_user_ID(input);
                std::thread advertiseThread(user_advertise_thread);
                advertiseThread.detach();
                set_state(MENU);
            } else {
                set_state(ENTER_USER_ID);
            }
            break;
        }
        case MENU: {
            int index = get_menu_item(input);
            if(index != -1) {
                set_state(menu_items[index - 1].state);
            }
            break;
        }
        case CHAT: {
            if(input == "..") {
                set_state(MENU);
            }
            break;
        }
        case SHOW_USERS: {
            if(input == "..") {
                stop_flag.store(true);
                set_state(MENU);
            }
            break;
        }
        case SETTINGS: {
            if(input == "..") {
                set_state(MENU);
            }
            break;
        }
        case DETAILS: {
            if(input == "..") {
                set_state(MENU);
            }
            break;
        }
    }
}

int StealthcomStateMachine::get_menu_item(const std::string& input) {
    int index;
    try {
        index = std::stoi(input);
        return (index < 1 || index > menu_items_size) ? -1 : index;
    } catch (const std::invalid_argument&) {
        return -1;
    } catch (const std::out_of_range&) {
        return -1;
    }
}
