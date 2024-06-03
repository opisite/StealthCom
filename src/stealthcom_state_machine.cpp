#include "stealthcom_state_machine.h"
#include "io_handler.h"
#include "stealthcom_logic.h"

StealthcomStateMachine::StealthcomStateMachine() {
    state = ENTER_USER_ID;
}

void StealthcomStateMachine::handle_input(const std::string input) {
    switch(state) {
        case ENTER_USER_ID: {
            if(is_valid_user_id(input)) {
                output_push_msg("VALID ID");
                state = CHAT;
            } else {
                output_push_msg("INVALID ID");
            }
            break;
        }
        case CHAT: {
            break;
        }
    }
}