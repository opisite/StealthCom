#include <stdlib.h>
#include <stdio.h>
#include <iomanip>
#include <cstring>
#include <thread>
#include <chrono>
#include <pcap.h>

#include "packet_rx_tx.h"
#include "io_handler.h"
#include "utils.h"
#include "stealthcom_pkt_handler.h"
#include "stealthcom_logic.h"

int main(int argc, char* argv[]) {
    const char *device = argv[1];

    std::thread stealthcom(stealthcom_init, device);

    if(stealthcom.joinable()) {
        stealthcom.join();
    }

    return 0;
}
