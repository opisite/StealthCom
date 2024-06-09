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

enum InteractionType {
    ENTER_INDEX,
    ENTER_VAL,
};

struct SubStateContext {
    InteractionType interaction_type;
    int selected_index;
};

class StealthcomStateMachine {
    public:
        StealthcomStateMachine();
        void handle_input(const std::string& input);
        

    private:
        void set_state(State state);
        void perform_state_action(State state);
        void perform_substate_action(State state);
        void reset_context();
        State state;
        SubStateContext context;
};

#endif
