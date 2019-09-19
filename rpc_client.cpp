#include "stdafx.h"

#ifndef HAL_RPC_CLIENT_DEBUG
#define HAL_RPC_CLIENT_DEBUG 1
#endif

#if HAL_RPC_CLIENT_DEBUG
#include <stdio.h>
#define check(op) do { const hal_error_t _err_ = (op); if (_err_ != HAL_OK) { hal_log(HAL_LOG_DEBUG, "%s returned %d (%s)", #op, _err_, hal_error_string(_err_)); return _err_; } } while (0)
#else
#define check(op) do { const hal_error_t _err_ = (op); if (_err_ != HAL_OK) { return _err_; } } while (0)
#endif


#define pad(n) (((n) + 3) & ~3)

#define nargs(n) ((n) * 4)

/*
* Consolidate a bit of the repetitive code from the packet receive loop.
* We're looking for a packet which is a response to the packet we sent,
* so if the opcode is wrong, we discard and wait for another packet.
*/

static hal_error_t read_matching_packet(const rpc_func_num_t expected_func,
	uint8_t *inbuf,
	const size_t inbuf_max,
	const uint8_t **iptr,
	const uint8_t **ilimit)
{
	hal_client_handle_t dummy_client;
	uint32_t received_func;
	size_t ilen = inbuf_max;
	hal_error_t err;

	hal_assert(inbuf != NULL && iptr != NULL && ilimit != NULL);

	do {

		if ((err = hal_rpc_recv(inbuf, &ilen)) != HAL_OK)
			return err;

		hal_assert(ilen <= inbuf_max);
		*iptr = inbuf;
		*ilimit = inbuf + ilen;

		if ((err = hal_xdr_decode_int(iptr, *ilimit, &received_func)) == HAL_ERROR_XDR_BUFFER_OVERFLOW)
			continue;
		if (err != HAL_OK)
			return err;

		if ((err = hal_xdr_decode_int(iptr, *ilimit, &dummy_client.handle)) == HAL_ERROR_XDR_BUFFER_OVERFLOW)
			continue;
		if (err != HAL_OK)
			return err;

	} while (received_func != expected_func);

	return HAL_OK;
}


hal_error_t hal_rpc_get_version(uint32_t *version)
{
	uint8_t outbuf[nargs(2)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
	uint8_t inbuf[nargs(4)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_GET_VERSION));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_GET_VERSION, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK) {
		check(hal_xdr_decode_int(&iptr, ilimit, version));
	}

	return (hal_error_t)rpc_ret;
}

/*hal_error_t get_random(void *buffer, const size_t length)
{
	uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
	uint8_t inbuf[nargs(4) + pad(length)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	size_t rcvlen;
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_GET_RANDOM));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, (uint32_t)length));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_GET_RANDOM, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK) {
		check(hal_xdr_decode_variable_opaque(&iptr, ilimit, buffer, &rcvlen, length));
		// XXX check rcvlen vs length
	}
	return (hal_error_t)rpc_ret;
}*/
