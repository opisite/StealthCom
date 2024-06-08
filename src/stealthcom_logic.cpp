#include <stdlib.h>
#include <stdio.h>
#include <iomanip>
#include <cstring>
#include <thread>
#include <chrono>
#include <pcap.h>
#include <iostream>

#include "packet_rx_tx.h"
#include "io_handler.h"
#include "utils.h"
#include "stealthcom_pkt_handler.h"
#include "stealthcom_logic.h"
#include "message_queue.h"
#include "stealthcom_state_machine.h"
#include "user_registry.h"

static MessageQueue *input_queue;
static StealthcomStateMachine *state_machine;

std::shared_ptr<UserRegistry> user_registry;

void stealthcom_init(const char *netif) {

    std::shared_ptr<PacketQueue> rx_queue = std::make_shared<PacketQueue>();
    std::shared_ptr<PacketQueue> tx_queue = std::make_shared<PacketQueue>();
    user_registry = std::make_shared<UserRegistry>();

    ncurses_init();
    packet_rx_tx_init(netif, rx_queue, tx_queue);
    stealthcom_pkt_handler_init(rx_queue, tx_queue);

    std::thread ncursesThread(ncurses_thread);
    std::thread packetTxThread(packet_tx);
    std::thread packetRxThread(packet_capture_wrapper);
    std::thread packetHandlerThread(packet_handler_thread);

    ncursesThread.detach();
    packetTxThread.detach();
    packetRxThread.detach();
    packetHandlerThread.detach();

    input_queue = new MessageQueue();
    state_machine = new StealthcomStateMachine();


    stealthcom_main_thread();
}

void stealthcom_main_thread() {
    while(true) {
        std::string msg = input_queue->pop();

        state_machine->handle_input(msg);
    }

}

void input_push_msg(const std::string message) {
    input_queue->push(message);
}

bool is_valid_user_ID(const std::string user_ID) {
    if(user_ID.length() > USER_ID_MAX_LEN) {
        return false;
    }
    return true;
}
