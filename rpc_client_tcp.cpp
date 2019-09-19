#include "stdafx.h"

extern "C"
{
	static struct tls *tls = NULL;
	static struct tls_config *config = NULL;
}

hal_error_t hal_rpc_client_transport_init(void)
{
	// get the IP address from the DKS_HSM_HOST_IP environment variable
	const char *hostip = "10.1.10.9";  // getenv("DKS_HSM_HOST_IP");
	const char *hostname = "dks-hsm";  // getenv("DKS_HSM_HOST_NAME");

	if (hostip == NULL) {
		return HAL_ERROR_BAD_ARGUMENTS;
	}

	if (hostname == NULL) {
		return HAL_ERROR_BAD_ARGUMENTS;
	}

	return hal_rpc_client_transport_init_ip(hostip, hostname);
}

hal_error_t hal_rpc_client_transport_init_ip(const char *hostip, const char *hostname)
{
	struct sockaddr_in server;
	int sock;

	if (hostip == NULL) {
		return HAL_ERROR_BAD_ARGUMENTS;
	}

	if (hostname == NULL) {
		return HAL_ERROR_BAD_ARGUMENTS;
	}

	// make sure any previous attemps to open a connection have closed
	hal_rpc_client_transport_close();

	// start the tls connection
	tls_init();

	tls = tls_client();

	config = tls_config_new();

	tls_config_insecure_noverifycert(config);

	tls_config_insecure_noverifyname(config);

	tls_configure(tls, config);

	sock = socket(AF_INET, SOCK_STREAM, 0);

	server.sin_port = htons(8080);
	server.sin_addr.s_addr = inet_addr(hostip);
	server.sin_family = AF_INET;

	if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
		return HAL_ERROR_RPC_TRANSPORT;
	}

	if (tls_connect_socket(tls, sock, hostname) < 0) {
		return HAL_ERROR_RPC_TRANSPORT;
	}

	return HAL_OK;
}

hal_error_t hal_rpc_client_transport_close(void)
{
	if (tls != NULL)
	{
		tls_close(tls);
		tls_free(tls);

		tls = NULL;
	}

	if (config != NULL)
	{
		tls_config_free(config);
		config = NULL;
	}

	return HAL_OK;
}


hal_error_t hal_rpc_send(const uint8_t * const buf, const size_t len)
{
	return hal_slip_send(buf, len);
}

hal_error_t hal_rpc_recv(uint8_t * const buf, size_t * const len)
{
	size_t maxlen = *len;
	*len = 0;
	hal_error_t err = hal_slip_recv(buf, len, maxlen);
	return err;
}

/*
* These two are sort of mis-named, fix eventually, but this is what
* the code in slip.c expects.
*/

hal_error_t hal_serial_send_char(const uint8_t c)
{
	if (tls_write(tls, &c, 1) == 1)
		return HAL_OK;
	else
		return HAL_ERROR_RPC_TRANSPORT;
}

hal_error_t hal_serial_recv_char(uint8_t * const c)
{
	if (tls_read(tls, c, 1) == 1)
		return HAL_OK;
	else
		return HAL_ERROR_RPC_TRANSPORT;
}
