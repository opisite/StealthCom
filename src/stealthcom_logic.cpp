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

void stealthcom_init(const char *netif) {

    std::shared_ptr<PacketQueue> rx_queue = std::make_shared<PacketQueue>();
    std::shared_ptr<PacketQueue> tx_queue = std::make_shared<PacketQueue>();

    io_init();
    packet_rx_tx_init(netif, rx_queue, tx_queue);
    stealthcom_pkt_handler_init(rx_queue, tx_queue);

    

    std::thread inputThread(input_thread);
    std::thread outputThread(output_thread);
    std::thread packetTxThread(packet_tx);
    std::thread packetRxThread(packet_capture_wrapper);
    std::thread advertiseThread(user_advertise_thread);

    while(1);
}