#pragma once

hal_error_t hal_rpc_client_transport_init(void);
hal_error_t hal_rpc_client_transport_init_ip(const char *hostip, const char *hostname);
hal_error_t hal_rpc_client_transport_close(void);
hal_error_t hal_serial_send_char(const uint8_t c);
hal_error_t hal_serial_recv_char(uint8_t * const c);