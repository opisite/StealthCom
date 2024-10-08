#include <stdexcept>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <chrono>

#include "stealthcom_state_machine.h"
#include "io_handler.h"
#include "user_data.h"
#include "stealthcom_pkt_handler.h"
#include "stealthcom_connection_logic.h"
#include "stealthcom_data_logic.h"
#include "user_registry.h"
#include "request_registry.h"
#include "data_registry.h"
#include "utils.h"
#include "crypto.h"

#define Y 1
#define N 0
#define INVALID -1

std::atomic<bool> stop_flag;
std::mutex running_mtx;

typedef void (*SettingFunction)(int);

static const struct {
    std::string key;
    State state;
} menu_items[] = {
    { "Show users", SHOW_USERS },
    { "Settings", SETTINGS },
    { "Details", DETAILS },
    { "Connection Requests", CONNECTION_REQUESTS },
    { "Chat", CHAT },
};

struct {
    const std::string key;
    int value;
    int temp_value;
    const std::pair<int, int> range; // Inclusive
    const SettingFunction func;
} settings_items[] = {
    { "Advertise", 0, 0, {0, 1}, &set_advertise },
};

static const int menu_items_size = ARRAY_LEN(menu_items);
static const int settings_items_size = ARRAY_LEN(settings_items);

std::vector<StealthcomUser*> users;
std::vector<StealthcomUser*> requests;

/**
 * @brief Convert a user input into an index corresponding to an item in an array
 * 
 * @param input the input string passed by the user
 * @param size the size of the item array the user wants to select from
 * @return INVALID if the input is not a valid index. Index value if the input is valid
 */
static int get_item(const std::string& input, int size) {
    int index;
    try {
        index = std::stoi(input);
        return (index < 1 || index > size) ? INVALID : index - 1;
    } catch (const std::invalid_argument&) {
        return INVALID;
    } catch (const std::out_of_range&) {
        return INVALID;
    }
}

/**
 * @brief Convert a user input into a value to be assigned to a setting
 * 
 * @param input the input string passed by the user
 * @param range the range of possible values of the setting being modified
 * @return INVALID if the input is not a valid value. Value if the input is valid
 */
static int get_value(const std::string& input, const std::pair<int, int> range) {
    int value;
    try {
        value = std::stoi(input);
        return (value >= range.first && value <= range.second) ? value : INVALID;
    } catch (const std::invalid_argument&) {
        return INVALID;
    } catch (const std::out_of_range&) {
        return INVALID;
    }
}

/**
 * @brief Get a yes/no value from a user input string
 * 
 * @param input the input string passed by the user
 * @return INVALID if the user input is not a valid Y/N value. Y or N if user input is valid
 */
static int get_value(const std::string& input) {
    if(input == "Y" || input == "y")
        return Y;
    if(input == "N" || input == "n")
        return N;
    return INVALID;
}

/**
 * @brief Print all menu items to MAIN window
 * 
 */
static void print_menu_items() {
    main_push_msg("MENU\n");
    for(int x = 0; x < menu_items_size; x++) {
        main_push_msg(std::to_string(x + 1) + ": " + menu_items[x].key);
    }
}

/**
 * @brief Print user details to MAIN window
 * 
 */
static void print_user_details() {
    main_push_msg("User ID: " + get_user_ID());
    main_push_msg("User MAC: " + mac_addr_to_str(get_MAC()));
    main_push_msg("");
    main_push_msg("SESSION KEY");
    print_encryption_key();
}

/**
 * @brief Print settings to MAIN window
 * 
 */
static void print_settings() {
    main_push_msg("SETTINGS (Exit to apply)\n");
    for(int x = 0; x < settings_items_size; x++) {
        main_push_msg(std::to_string(x + 1) + ": " + settings_items[x].key + " = " + std::to_string(settings_items[x].temp_value));
    }
}

/**
 * @brief (thread) print all known users (in user_registry) to the MAIN window, updating once per second
 * 
 */
static void show_users_thread() {
    std::lock_guard<std::mutex> lock(running_mtx);
    stop_flag.store(false);
    while(!stop_flag.load()) {
        if(!user_registry->registry_update()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        users = user_registry->get_users();
        io_clr_output();
        main_push_msg("VISIBLE USERS");
        main_push_msg("");
        for(int x = 0; x < users.size(); x++) {
            main_push_msg(std::to_string(x + 1));
            main_push_msg("MAC Address: " + mac_addr_to_str(users[x]->getMAC().data()));
            main_push_msg("User ID: " + users[x]->getName());
            main_push_msg("\n");
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    user_registry->raise_update_flag();
    stop_flag.store(false);
}

/**
 * @brief (thread) Show all connection requests (in request_registry) tp the MAIN window, updating once per second
 * 
 */
static void show_connection_requests_thread() {
    std::lock_guard<std::mutex> lock(running_mtx);
    stop_flag.store(false);
    while(!stop_flag.load()) {
        if(!request_registry->registry_update()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        requests = request_registry->get_requests();
        io_clr_output();
        main_push_msg("CONNECTION REQUESTS");
        main_push_msg("");
        for(int x = 0; x < requests.size(); x++) {
            main_push_msg(std::to_string(x + 1));
            main_push_msg("MAC Address: " + mac_addr_to_str(requests[x]->getMAC().data()));
            main_push_msg("User ID: " + requests[x]->getName());
            main_push_msg("\n");
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    request_registry->raise_update_flag();
    stop_flag.store(false);
}

/**
 * @brief Save and apply all modified settings
 * 
 */
static void apply_settings() {
    for(int x = 0; x < settings_items_size; x++) {
        if(settings_items[x].value != settings_items[x].temp_value) {
            settings_items[x].value = settings_items[x].temp_value;
            settings_items[x].func(settings_items[x].value);
        }
    }
}

/**
 * @brief Check if a user ID string is valid
 * 
 * @param user_ID the user ID string passed by the user
 * @return true if the user ID is valid (string length <= USER_ID_MAX_LEN)
 * @return false if the user ID is invalid (string length > USER_ID_MAX_LEN)
 */
static inline bool is_valid_user_ID(const std::string user_ID) {
    if(user_ID.length() > USER_ID_MAX_LEN) {
        return false;
    }
    return true;
}

/**
 * @brief Construct a new Stealthcom State Machine object
 * 
 */
StealthcomStateMachine::StealthcomStateMachine() {
    substate_context = {
        ENTER_INDEX,
        INVALID,
    };
    stop_flag.store(false);
    connection_context.connection_state = UNASSOCIATED;
    connection_context.user = nullptr;
    set_state(ENTER_USER_ID);
}

/**
 * @brief Reset the substate context to default values
 * 
 */
inline void StealthcomStateMachine::reset_substate_context() {
    substate_context.interaction_type = ENTER_INDEX;
    substate_context.selected_index = INVALID;
}

/**
 * @brief Set the state of the state machine
 * 
 * @param state the state to be transitioned to
 */
void StealthcomStateMachine::set_state(State state) {
    stop_flag.store(true);
    this->state = state;
    reset_substate_context();
    user_registry->unprotect_users();
    perform_state_action(state);
}

/**
 * @brief Perform the inital action that needs to be done upon state transition
 * 
 * @param state the state that the state machine is transitioning into
 */
void StealthcomStateMachine::perform_state_action(State state) {
    io_clr_output();
    switch (state) {
        case ENTER_USER_ID: {
            main_push_msg("Enter your user ID (" + std::to_string(USER_ID_MAX_LEN) + " CHARACTERS MAX)");
            break;
        }
        case MENU: {
            print_menu_items();
            break;
        }
        case CHAT: {
            display_messages();
            break;
        }
        case DETAILS: {
            print_user_details();
            break;
        }
        case SHOW_USERS: {
            std::thread showUsersThread(show_users_thread);
            showUsersThread.detach();
            break;
        }
        case SETTINGS: {
            print_settings();
            break;
        }
        case CONNECTION_REQUESTS: {
            std::thread showConnectionRequestsThread(show_connection_requests_thread);
            showConnectionRequestsThread.detach();
            break;
        }
    }
}

/**
 * @brief Perform the substate action that needs to be done within a certain state.
 *          The particular action that is to be done depends on the substate context
 * 
 * @param state the current state of the state machine
 */
void StealthcomStateMachine::perform_substate_action(State state) {
    stop_flag.store(true);
    switch (state) {
        case SHOW_USERS: {
            user_registry->protect_users();
            io_clr_output();
            main_push_msg("Send connection request to [" + users[substate_context.selected_index]->getName() + "]? (Y/N)");
            break;
        }
        case SETTINGS: {
            io_clr_output();
            main_push_msg("Set: " + settings_items[substate_context.selected_index].key);
            break;
        }
        case CONNECTION_REQUESTS: {
            user_registry->protect_users();
            io_clr_output();
            main_push_msg("Accept connection request from [" + requests[substate_context.selected_index]->getName() + "]? (Y/N)");
            break;
        }
    }
}

/**
 * @brief Handle the user input if the state is ENTER_USER_ID
 * 
 * @param input the user input string
 */
void StealthcomStateMachine::handle_input_enter_user_ID(const std::string& input) {
    if(is_valid_user_ID(input)) {
            set_user_ID(input);
            set_state(MENU);
        } else {
            set_state(ENTER_USER_ID);
        }
}

/**
 * @brief Handle the user input if the state is MENU
 * 
 * @param input the user input string
 */
void StealthcomStateMachine::handle_input_menu(const std::string& input) {
    int index = get_item(input, menu_items_size);
    if(index != INVALID) {
        set_state(menu_items[index].state);
    }
}

/**
 * @brief Handle the user input if the state is CHAT
 * 
 * @param input the user input string
 */
void StealthcomStateMachine::handle_input_msg(const std::string& input) {
    if(input == "..") {
        set_state(MENU);
        return;
    } else if(input == "/disconnect") {
        if(connection_context.connection_state != CONNECTED) {
            return;
        }
        system_push_msg("Disconnecting from user: " + connection_context.user->getName());
        send_disconnect();
        reset_connection_context();
        return;
    }
    
    if(connection_context.connection_state != CONNECTED) {
        system_push_msg("Message send failed - not connected");
        return;
    }

    create_message(input);
}

/**
 * @brief Handle the user input if the state is SHOW_USERS
 * 
 * @param input the user input string
 */
void StealthcomStateMachine::handle_input_show_users(const std::string& input) {
    if(input == "..") {
        set_state(MENU);
        return;
    }

    if(substate_context.interaction_type == ENTER_INDEX) {
        int index = get_item(input, users.size());
        if(index != INVALID) {
            substate_context.selected_index = index;
            substate_context.interaction_type = ENTER_VAL;
            perform_substate_action(SHOW_USERS);
        }
    } else if(substate_context.interaction_type == ENTER_VAL) {
        int value = get_value(input);
        if(value == Y) {
            StealthcomUser *target_user = users[substate_context.selected_index];
            send_conn_request(target_user);
            set_state(SHOW_USERS);
        } else if(value == N) {
            set_state(SHOW_USERS);
        }
    }
}

/**
 * @brief Handle the user input if the state is SETTINGS
 * 
 * @param input the user input string
 */
void StealthcomStateMachine::handle_input_settings(const std::string& input) {
    if(input == "..") {
        apply_settings();
        set_state(MENU);
        return;
    }

    if(substate_context.interaction_type == ENTER_INDEX) {
        int index = get_item(input, settings_items_size);
        if(index != INVALID) {
            substate_context.selected_index = index;
            substate_context.interaction_type = ENTER_VAL;
            perform_substate_action(SETTINGS);
        }
    } else if(substate_context.interaction_type == ENTER_VAL) {
        int index  = substate_context.selected_index;
        int value = get_value(input, settings_items[index].range);
        if(value != INVALID) {
            settings_items[substate_context.selected_index].temp_value = std::stoi(input);
            set_state(SETTINGS);
        }
    }
}

/**
 * @brief Handle the user input if the state is DETAILS
 * 
 * @param input the user input string
 */
void StealthcomStateMachine::handle_input_details(const std::string& input) {
    if(input == "..") {
        set_state(MENU);
    }
}

/**
 * @brief Handle the user input if the state is CONNECTION_REQUESTS
 * 
 * @param input the user input string
 */
void StealthcomStateMachine::handle_input_connection_requests(const std::string& input) {
    if(input == "..") {
        set_state(MENU);
        return;
    }

    if(substate_context.interaction_type == ENTER_INDEX) {
        int index = get_item(input, requests.size());
        if(index != INVALID) {
            substate_context.selected_index = index;
            substate_context.interaction_type = ENTER_VAL;
            perform_substate_action(CONNECTION_REQUESTS);
        }
    } else if(substate_context.interaction_type == ENTER_VAL) {
        int value = get_value(input);
        StealthcomUser *target_user = requests[substate_context.selected_index];
        if(value == Y) {
            send_conn_request_response(target_user, true);
            set_state(CONNECTION_REQUESTS);
        } else if(value == N) {
            send_conn_request_response(target_user, false);
            set_state(CONNECTION_REQUESTS);
        }
    }
}

/**
 * @brief Pass the user input to the appropriate handler
 * 
 * @param input the user input string
 */
void StealthcomStateMachine::handle_input(const std::string& input) {
    switch(state) {
        case ENTER_USER_ID: {
            handle_input_enter_user_ID(input);
            break;
        }
        case MENU: {
            handle_input_menu(input);
            break;
        }
        case CHAT: {
            handle_input_msg(input);
            break;
        }
        case SHOW_USERS: {
            handle_input_show_users(input);
            break;
        }
        case SETTINGS: {
            handle_input_settings(input);
            break;
        }
        case DETAILS: {
            handle_input_details(input);
            break;
        }
        case CONNECTION_REQUESTS: {
            handle_input_connection_requests(input);
            break;
        }

    }
}

/**
 * @brief Get the current state of the state machine
 * 
 * @return State state
 */
State StealthcomStateMachine::get_state() {
    return state;
}

/**
 * @brief Get the connection context of the state machine
 * 
 * @return ConnectionContext connection_context
 */
ConnectionContext StealthcomStateMachine::get_connection_context() {
    return connection_context;
}

/**
 * @brief Set the connection state of the state machine
 * 
 * @param state the ConnectionState to set for connection_context
 */
void StealthcomStateMachine::set_connection_state(ConnectionState state) {
    connection_context.connection_state = state;
}

/**
 * @brief Set the connection state and user of the state machine
 * 
 * @param state the ConnectionState to set for connection_context
 * @param user the StealthcomUser* to set for connection_context
 */
void StealthcomStateMachine::set_connection_state_and_user(ConnectionState state, StealthcomUser *user) {
    connection_context.connection_state = state;
    connection_context.user = user;
}

/**
 * @brief Reset connection_context to its default values
 * 
 */
void StealthcomStateMachine::reset_connection_context() {
    StealthcomUser *user = connection_context.user;
    if(connection_context.connection_state == AWAITING_CONNECTION_RESPONSE) {
        system_push_msg("Request to user [" + user->getName() + "] timed out");
    }

    connection_context.connection_state = UNASSOCIATED;
    connection_context.user = nullptr;
}
