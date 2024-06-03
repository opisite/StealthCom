#ifndef STEALTHCOM_STATE_MACHINE_H
#define STEALTHCOM_STATE_MACHINE_H

#include <string>

enum State {
    ENTER_USER_ID,
    CHAT
};

class StealthcomStateMachine {
    public:
        StealthcomStateMachine();
        void handle_input(const std::string input);
        

    private:
        State state;
};

#endif