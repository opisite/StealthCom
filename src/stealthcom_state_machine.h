#ifndef STEALTHCOM_STATE_MACHINE_H
#define STEALTHCOM_STATE_MACHINE_H

#include <string>

enum State {
    ENTER_USER_ID,
    MENU,
    SHOW_USERS,
    SETTINGS,
    DETAILS,
    CHAT,
};

class StealthcomStateMachine {
    public:
        StealthcomStateMachine();
        void handle_input(const std::string input);
        

    private:
        void set_state(State state);
        void print_state_msg(State state);
        State state;
};

#endif