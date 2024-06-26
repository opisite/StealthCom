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
        ConnectionContext get_connection_context();
        void set_connection_state(ConnectionState state);
        void set_connection_state_and_user(ConnectionState state, StealthcomUser *user);
        void reset_connection_context();
        State get_state();
        
    private:
        void set_state(State state);
        void perform_state_action(State state);
        void perform_substate_action(State state);
        void reset_substate_context();
        void handle_input_enter_user_ID(const std::string& input);
        void handle_input_menu(const std::string& input);
        void handle_input_msg(const std::string& input);
        void handle_input_show_users(const std::string& input);
        void handle_input_settings(const std::string& input);
        void handle_input_details(const std::string& input);
        void handle_input_connection_requests(const std::string& input);
        State state;
        SubStateContext substate_context;
        ConnectionContext connection_context;

};

extern StealthcomStateMachine *state_machine;

#endif
