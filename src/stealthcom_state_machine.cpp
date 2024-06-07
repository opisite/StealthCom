#include "stealthcom_state_machine.h"
#include "io_handler.h"
#include "stealthcom_logic.h"

static const struct {
    std::string key;
    State state;
} menu_items[] = {
    { "Show users", SHOW_USERS },
    { "Settings", SETTINGS },
    { "Details", DETAILS },
};

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
            size_t menu_items_size = sizeof(menu_items) / sizeof(menu_items[0]);
            output_push_msg("MENU");
            for(int x = 0; x < menu_items_size; x++) {
                output_push_msg(std::to_string(x) + ": " + menu_items[x].key);
            }
        }
    }
}

void StealthcomStateMachine::handle_input(const std::string input) {
    switch(state) {
        case ENTER_USER_ID: {
            if(is_valid_user_id(input)) {
                set_state(MENU);
            } else {
                set_state(ENTER_USER_ID);
            }
            break;
        }
        case CHAT: {
            break;
        }
        case MENU: {
            break;
        }
    }
}