#include <stdlib.h>
#include <stdio.h>
#include <iomanip>
#include <cstring>
#include <thread>
#include <chrono>
#include <pcap.h>
#include <iostream>

#include "io_handler.h"
#include "utils.h"
#include "packet_rx_tx.h"
#include "stealthcom_pkt_handler.h"
#include "stealthcom_logic.h"
#include "thread_safe_queue.h"
#include "stealthcom_state_machine.h"
#include "user_registry.h"
#include "request_registry.h"
#include "data_registry.h"
#include "stealthcom_data_logic.h"

static InputQueue *input_queue;
StealthcomStateMachine *state_machine;

std::shared_ptr<UserRegistry> user_registry;
std::shared_ptr<RequestRegistry> request_registry;
std::shared_ptr<DataRegistry> data_registry;

/**
 * @brief Initialize shared resources and threads at the start of the program
 * 
 * @param netif the network interface to use
 */
void stealthcom_init(const char *netif) {
    ncurses_init();

    std::shared_ptr<PacketQueue> rx_queue = std::make_shared<PacketQueue>();
    std::shared_ptr<PacketQueue> tx_queue = std::make_shared<PacketQueue>();
    user_registry = std::make_shared<UserRegistry>();
    request_registry = std::make_shared<RequestRegistry>();
    data_registry = std::make_shared<DataRegistry>();

    packet_rx_tx_init(netif, rx_queue, tx_queue);
    stealthcom_pkt_handler_init(rx_queue, tx_queue);

    std::thread ncursesThread(ncurses_thread);
    ncursesThread.detach();

    std::thread packetTxThread(packet_tx);
    packetTxThread.detach();

    std::thread packetRxThread(packet_capture_wrapper);
    packetRxThread.detach();

    std::thread packetHandlerThread(packet_handler_thread);
    packetHandlerThread.detach();

    input_queue = new InputQueue();
    state_machine = new StealthcomStateMachine();


    stealthcom_main_thread();
}

/**
 * @brief (thread) sequentially handle user inputs
 * 
 */
void stealthcom_main_thread() {
    while(true) {
        std::string msg = input_queue->pop();
        state_machine->handle_input(msg);
    }

}

/**
 * @brief API called by io_handler to push messages to a queue to be popped by stealthcom_main_thread()
 * 
 * @param message 
 */
void input_push_msg(const std::string message) {
    input_queue->push(message);
}
