#include <stdlib.h>
#include <stdio.h>
#include <iomanip>
#include <cstring>
#include <thread>
#include <chrono>
#include <pcap.h>

#include "packet_rx_tx.h"
#include "input_handler.h"
#include "utils.h"
#include "stealthcom_pkt_handler.h"

int main(int argc, char* argv[]) {
    const char *device = "wlan1";

    system("clear");

    set_sys_info(device);

    std::thread packetTxThread(packet_tx);
    std::thread captureThread(packet_capture_wrapper);
    std::thread advertiseThread(user_advertise_thread);

    while(1) {
        std::cout << "online" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    return 0;
}
