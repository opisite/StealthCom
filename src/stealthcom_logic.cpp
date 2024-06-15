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
#include "request_registry.h"

static MessageQueue *input_queue;
static StealthcomStateMachine *state_machine;

std::shared_ptr<UserRegistry> user_registry;
std::shared_ptr<RequestRegistry> request_registry;

void stealthcom_init(const char *netif) {
    ncurses_init();

    std::shared_ptr<PacketQueue> rx_queue = std::make_shared<PacketQueue>();
    std::shared_ptr<PacketQueue> tx_queue = std::make_shared<PacketQueue>();
    user_registry = std::make_shared<UserRegistry>();
    request_registry = std::make_shared<RequestRegistry>();

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
