#ifndef STEALTHCOM_CONNECTION_LOGIC_H
#define STEALTHCOM_CONNECTION_LOGIC_H

#include <memory>
#include "packet_rx_tx.h"
#include "stealthcom_user.h"

void begin_connection(StealthcomUser *user);
void connection_worker_init(std::shared_ptr<PacketQueue> queue);
void connection_worker_thread();
void send_conn_request(StealthcomUser *user);
void send_conn_request_response(StealthcomUser *user, bool accept);
void send_disconnect();

#endif
