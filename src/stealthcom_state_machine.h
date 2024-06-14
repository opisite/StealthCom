#ifndef STEALTHCOM_STATE_MACHINE_H
#define STEALTHCOM_STATE_MACHINE_H

#include <string>
#include "stealthcom_user.h"

enum State {
    ENTER_USER_ID,
    MENU,
    SHOW_USERS,
    SETTINGS,
    DETAILS,
    CONNECTION_REQUESTS,
    CHAT,
};

enum InteractionType {
    ENTER_INDEX,
    ENTER_VAL,
};

enum ConnectionState {
    UNASSOCIATED,
    AWAITING_CONNECTION_RESPONSE,
    KEY_EXCHANGE,
    CONNECTED,
};

struct SubStateContext {
    InteractionType interaction_type;
    int selected_index;
};

struct ConnectionContext {
    ConnectionState connection_state;
    StealthcomUser *user;
};

class StealthcomStateMachine {
    public:
        StealthcomStateMachine();
        void handle_input(const std::string& input);
        

    private:
        void set_state(State state);
        void perform_state_action(State state);
        void perform_substate_action(State state);
        void reset_substate_context();
        ConnectionContext get_connection_context();
        State state;
        SubStateContext substate_context;
        ConnectionContext connection_context;

};

#endif
