#include <stdexcept>
#include "stealthcom_state_machine.h"
#include "io_handler.h"
#include "stealthcom_logic.h"
#include "user_data.h"

static const struct {
    std::string key;
    State state;
} menu_items[] = {
    { "Show users", SHOW_USERS },
    { "Settings", SETTINGS },
    { "Details", DETAILS },
};

static const int menu_items_size = sizeof(menu_items) / sizeof(menu_items[0]);

StealthcomStateMachine::StealthcomStateMachine() {
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
    }
}

void StealthcomStateMachine::print_menu_items() {
    output_push_msg("MENU");
    for(int x = 0; x < menu_items_size; x++) {
        output_push_msg(std::to_string(x + 1) + ": " + menu_items[x].key);
    }
}

void StealthcomStateMachine::handle_input(const std::string& input) {
    switch(state) {
        case ENTER_USER_ID: {
            if(is_valid_user_ID(input)) {
                set_user_ID(input);
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
