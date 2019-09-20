/*
* hal_internal.h
* --------------
* Internal API declarations for libhal.
*
* Authors: Rob Austein, Paul Selkirk
* Copyright (c) 2015, NORDUnet A/S All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
* - Redistributions of source code must retain the above copyright notice,
*   this list of conditions and the following disclaimer.
*
* - Redistributions in binary form must reproduce the above copyright
*   notice, this list of conditions and the following disclaimer in the
*   documentation and/or other materials provided with the distribution.
*
* - Neither the name of the NORDUnet nor the names of its contributors may
*   be used to endorse or promote products derived from this software
*   without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
* IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
// Modifications
// Copyright 2019, Diamond Key Security
#include "stdafx.h"

const hal_hash_handle_t hal_hash_handle_none = { HAL_HANDLE_NONE };

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


hal_error_t hal_rpc_get_version(uint32_t *version) // TESTED
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

hal_error_t hal_rpc_get_random(void *buffer, const size_t length) // TESTED
{
	uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);

	// VS doesn't allow arrays of variable size
	uint32_t ibuf_len = nargs(4) + pad(length);
	uint8_t *inbuf = new uint8_t[ibuf_len];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + ibuf_len;

	// use a unique_ptr to handle destruction of the data we just created
	// because VS only allows arrays created with const values
	std::unique_ptr<uint8_t> temp(inbuf);

	size_t rcvlen;
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_GET_RANDOM));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, (uint32_t)length));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_GET_RANDOM, inbuf, ibuf_len, &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK) {
		check(hal_xdr_decode_variable_opaque(&iptr, ilimit, (uint8_t *)buffer, &rcvlen, length));
		// XXX check rcvlen vs length
	}
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_set_pin(const hal_client_handle_t client,
	const hal_user_t user,
	const char * const pin, const size_t pin_len)
{
	size_t sizeof_outbuf = nargs(4) + pad(pin_len);
	uint8_t *outbuf =  new uint8_t[sizeof_outbuf], *optr = outbuf, *olimit = outbuf + sizeof_outbuf;

	// use a unique_ptr to handle destruction of the data we just created
	// because VS only allows arrays created with const values
	std::unique_ptr<uint8_t> free_outbuf(outbuf);

	uint8_t inbuf[nargs(3)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_SET_PIN));
	check(hal_xdr_encode_int(&optr, olimit, client.handle));
	check(hal_xdr_encode_int(&optr, olimit, user));
	check(hal_xdr_encode_variable_opaque(&optr, olimit, (const uint8_t *)pin, pin_len));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_SET_PIN, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	return (hal_error_t)rpc_ret;
}

/*
* We may end up wanting to wrap a client-side cache around the
* login()/logout()/logout_all() calls and reimplement is_logged_in()
* on the client side using that cache, so that access checks don't
* need to cross the RPC boundary.  Then again, we might not, if the
* RPC call is fast enough, so implementing all before the RPC would
* qualify as premature optimization.  There aren't all that many
* things on the client side that would use this anyway, so the whole
* question may be moot.
*
* For now, we leave all of these as plain RPC calls, but we may want
* to revisit this if the is_logged_in() call turns into a bottleneck.
*/

hal_error_t hal_rpc_login(const hal_client_handle_t client,
	const hal_user_t user,
	const char * const pin, const size_t pin_len)
{
	size_t sizeof_outbuf = nargs(4) + pad(pin_len);
	uint8_t *outbuf = new uint8_t[sizeof_outbuf], *optr = outbuf, *olimit = outbuf + sizeof_outbuf;

	// use a unique_ptr to handle destruction of the data we just created
	// because VS only allows arrays created with const values
	std::unique_ptr<uint8_t> free_outbuf(outbuf);

	uint8_t inbuf[nargs(3)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_LOGIN));
	check(hal_xdr_encode_int(&optr, olimit, client.handle));
	check(hal_xdr_encode_int(&optr, olimit, user));
	check(hal_xdr_encode_variable_opaque(&optr, olimit, (const uint8_t *)pin, pin_len));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_LOGIN, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_logout(const hal_client_handle_t client)
{
	uint8_t outbuf[nargs(2)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
	uint8_t inbuf[nargs(3)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_LOGOUT));
	check(hal_xdr_encode_int(&optr, olimit, client.handle));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_LOGOUT, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_logout_all(void)
{
	uint8_t outbuf[nargs(2)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
	uint8_t inbuf[nargs(3)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_LOGOUT_ALL));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_LOGOUT_ALL, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_is_logged_in(const hal_client_handle_t client,
	const hal_user_t user)
{
	uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
	uint8_t inbuf[nargs(3)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_IS_LOGGED_IN));
	check(hal_xdr_encode_int(&optr, olimit, client.handle));
	check(hal_xdr_encode_int(&optr, olimit, user));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_IS_LOGGED_IN, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_hash_get_digest_len(const hal_digest_algorithm_t alg, size_t *length)
{
	uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
	uint8_t inbuf[nargs(4)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	uint32_t len32;
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_GET_DIGEST_LEN));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, alg));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_HASH_GET_DIGEST_LEN, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK) {
		check(hal_xdr_decode_int(&iptr, ilimit, &len32));
		*length = (size_t)len32;
	}
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_hash_get_digest_algorithm_id(const hal_digest_algorithm_t alg,
	uint8_t *id, size_t *len, const size_t len_max)
{
	uint8_t outbuf[nargs(4)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);

	size_t sizeof_inbuf = nargs(4) + pad(len_max);
	uint8_t *inbuf = new uint8_t[sizeof_inbuf];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof_inbuf;
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	// use a unique_ptr to handle destruction of the data we just created
	// because VS only allows arrays created with const values
	std::unique_ptr<uint8_t> free_inbuf(inbuf);

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_GET_DIGEST_ALGORITHM_ID));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, alg));
	check(hal_xdr_encode_int(&optr, olimit, len_max));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_HASH_GET_DIGEST_ALGORITHM_ID,
		inbuf, sizeof_inbuf, &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK) {
		uint32_t len32;
		check(hal_xdr_decode_int(&iptr, ilimit, &len32));
		if (len != NULL)
			*len = len32;
		if (id != NULL)
			check(hal_xdr_decode_fixed_opaque(&iptr, ilimit, id, len32));
	}
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_hash_get_algorithm(const hal_hash_handle_t hash, hal_digest_algorithm_t *alg)
{
	uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
	uint8_t inbuf[nargs(4)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	uint32_t alg32;
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_GET_ALGORITHM));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, hash.handle));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_HASH_GET_ALGORITHM, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK) {
		check(hal_xdr_decode_int(&iptr, ilimit, &alg32));
		*alg = (hal_digest_algorithm_t)alg32;
	}
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_hash_initialize(const hal_client_handle_t client,
	const hal_session_handle_t session,
	hal_hash_handle_t *hash,
	const hal_digest_algorithm_t alg,
	const uint8_t * const key, const size_t key_len)
{
	size_t sizeof_outbuf = nargs(5) + pad(key_len);
	uint8_t *outbuf = new uint8_t[sizeof_outbuf], *optr = outbuf, *olimit = outbuf + sizeof_outbuf;
	uint8_t inbuf[nargs(4)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	uint32_t rpc_ret;

	// use a unique_ptr to handle destruction of the data we just created
	// because VS only allows arrays created with const values
	std::unique_ptr<uint8_t> free_outbuf(outbuf);

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_INITIALIZE));
	check(hal_xdr_encode_int(&optr, olimit, client.handle));
	check(hal_xdr_encode_int(&optr, olimit, session.handle));
	check(hal_xdr_encode_int(&optr, olimit, alg));
	check(hal_xdr_encode_variable_opaque(&optr, olimit, key, key_len));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_HASH_INITIALIZE, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK) {
		check(hal_xdr_decode_int(&iptr, ilimit, &hash->handle));
	}
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_hash_update(const hal_hash_handle_t hash,
	const uint8_t * data, const size_t length)
{
	size_t sizeof_outbuf = nargs(4) + pad(length);
	uint8_t *outbuf = new uint8_t[sizeof_outbuf], *optr = outbuf, *olimit = outbuf + sizeof_outbuf;
	uint8_t inbuf[nargs(3)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	// use a unique_ptr to handle destruction of the data we just created
	// because VS only allows arrays created with const values
	std::unique_ptr<uint8_t> free_outbuf(outbuf);

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_UPDATE));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, hash.handle));
	check(hal_xdr_encode_variable_opaque(&optr, olimit, data, length));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_HASH_UPDATE, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_hash_finalize(const hal_hash_handle_t hash,
	uint8_t *digest, const size_t length)
{
	size_t sizeof_inbuf = nargs(4) + pad(length);
	uint8_t outbuf[nargs(4)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
	uint8_t *inbuf = new uint8_t[sizeof_inbuf];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof_inbuf;
	size_t digest_len;
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	// use a unique_ptr to handle destruction of the data we just created
	// because VS only allows arrays created with const values
	std::unique_ptr<uint8_t> free_inbuf(inbuf);

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_FINALIZE));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, hash.handle));
	check(hal_xdr_encode_int(&optr, olimit, length));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_HASH_FINALIZE, inbuf, sizeof_inbuf, &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK) {
		check(hal_xdr_decode_variable_opaque(&iptr, ilimit, digest, &digest_len, length));
		/* XXX check digest_len vs length */
	}
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_pkey_load(const hal_client_handle_t client,
	const hal_session_handle_t session,
	hal_pkey_handle_t *pkey,
	hal_uuid_t *name,
	const uint8_t * const der, const size_t der_len,
	const hal_key_flags_t flags)
{
	size_t sizeof_outbuf = nargs(5) + pad(der_len);
	uint8_t *outbuf = new uint8_t[sizeof_outbuf], *optr = outbuf, *olimit = outbuf + sizeof_outbuf;
	uint8_t inbuf[nargs(5) + pad(sizeof(name->uuid))];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	size_t name_len;
	uint32_t rpc_ret;

	// use a unique_ptr to handle destruction of the data we just created
	// because VS only allows arrays created with const values
	std::unique_ptr<uint8_t> free_outbuf(outbuf);

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_LOAD));
	check(hal_xdr_encode_int(&optr, olimit, client.handle));
	check(hal_xdr_encode_int(&optr, olimit, session.handle));
	check(hal_xdr_encode_variable_opaque(&optr, olimit, der, der_len));
	check(hal_xdr_encode_int(&optr, olimit, flags));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_LOAD, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK) {
		check(hal_xdr_decode_int(&iptr, ilimit, &pkey->handle));
		check(hal_xdr_decode_variable_opaque(&iptr, ilimit, name->uuid, &name_len, sizeof(name->uuid)));
		if (name_len != sizeof(name->uuid))
			return HAL_ERROR_KEY_NAME_TOO_LONG;
	}
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_pkey_open(const hal_client_handle_t client,
	const hal_session_handle_t session,
	hal_pkey_handle_t *pkey,
	const hal_uuid_t * const name)
{
	uint8_t outbuf[nargs(4) + pad(sizeof(name->uuid))], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
	uint8_t inbuf[nargs(4)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_OPEN));
	check(hal_xdr_encode_int(&optr, olimit, client.handle));
	check(hal_xdr_encode_int(&optr, olimit, session.handle));
	check(hal_xdr_encode_variable_opaque(&optr, olimit, name->uuid, sizeof(name->uuid)));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_OPEN, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));

	if (rpc_ret == HAL_OK)
		check(hal_xdr_decode_int(&iptr, ilimit, &pkey->handle));

	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_pkey_generate_rsa(const hal_client_handle_t client,
	const hal_session_handle_t session,
	hal_pkey_handle_t *pkey,
	hal_uuid_t *name,
	const unsigned key_len,
	const uint8_t * const exp, const size_t exp_len,
	const hal_key_flags_t flags)
{
	size_t sizeof_outbuf = nargs(6) + pad(exp_len);
	uint8_t *outbuf = new uint8_t[sizeof_outbuf], *optr = outbuf, *olimit = outbuf + sizeof_outbuf;
	uint8_t inbuf[nargs(5) + pad(sizeof(name->uuid))];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	size_t name_len;
	uint32_t rpc_ret;

	// use a unique_ptr to handle destruction of the data we just created
	// because VS only allows arrays created with const values
	std::unique_ptr<uint8_t> free_outbuf(outbuf);

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GENERATE_RSA));
	check(hal_xdr_encode_int(&optr, olimit, client.handle));
	check(hal_xdr_encode_int(&optr, olimit, session.handle));
	check(hal_xdr_encode_int(&optr, olimit, key_len));
	check(hal_xdr_encode_variable_opaque(&optr, olimit, exp, exp_len));
	check(hal_xdr_encode_int(&optr, olimit, flags));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_GENERATE_RSA, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));

	if (rpc_ret == HAL_OK) {
		check(hal_xdr_decode_int(&iptr, ilimit, &pkey->handle));
		check(hal_xdr_decode_variable_opaque(&iptr, ilimit, name->uuid, &name_len, sizeof(name->uuid)));
		if (name_len != sizeof(name->uuid))
			return HAL_ERROR_KEY_NAME_TOO_LONG;
	}

	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_pkey_generate_ec(const hal_client_handle_t client,
	const hal_session_handle_t session,
	hal_pkey_handle_t *pkey,
	hal_uuid_t *name,
	const hal_curve_name_t curve,
	const hal_key_flags_t flags)
{
	uint8_t outbuf[nargs(5)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
	uint8_t inbuf[nargs(5) + pad(sizeof(name->uuid))];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	size_t name_len;
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GENERATE_EC));
	check(hal_xdr_encode_int(&optr, olimit, client.handle));
	check(hal_xdr_encode_int(&optr, olimit, session.handle));
	check(hal_xdr_encode_int(&optr, olimit, curve));
	check(hal_xdr_encode_int(&optr, olimit, flags));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_GENERATE_EC, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));

	if (rpc_ret == HAL_OK) {
		check(hal_xdr_decode_int(&iptr, ilimit, &pkey->handle));
		check(hal_xdr_decode_variable_opaque(&iptr, ilimit, name->uuid, &name_len, sizeof(name->uuid)));
		if (name_len != sizeof(name->uuid))
			return HAL_ERROR_KEY_NAME_TOO_LONG;
	}

	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_pkey_generate_hashsig(const hal_client_handle_t client,
	const hal_session_handle_t session,
	hal_pkey_handle_t *pkey,
	hal_uuid_t *name,
	const size_t hss_levels,
	const hal_lms_algorithm_t lms_type,
	const hal_lmots_algorithm_t lmots_type,
	const hal_key_flags_t flags)
{
	uint8_t outbuf[nargs(7)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
	uint8_t inbuf[nargs(5) + pad(sizeof(name->uuid))];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	size_t name_len;
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GENERATE_HASHSIG));
	check(hal_xdr_encode_int(&optr, olimit, client.handle));
	check(hal_xdr_encode_int(&optr, olimit, session.handle));
	check(hal_xdr_encode_int(&optr, olimit, (uint32_t)hss_levels));
	check(hal_xdr_encode_int(&optr, olimit, (uint32_t)lms_type));
	check(hal_xdr_encode_int(&optr, olimit, (uint32_t)lmots_type));
	check(hal_xdr_encode_int(&optr, olimit, flags));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_GENERATE_HASHSIG, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));

	if (rpc_ret == HAL_OK) {
		check(hal_xdr_decode_int(&iptr, ilimit, &pkey->handle));
		check(hal_xdr_decode_variable_opaque(&iptr, ilimit, name->uuid, &name_len, sizeof(name->uuid)));
		if (name_len != sizeof(name->uuid))
			return HAL_ERROR_KEY_NAME_TOO_LONG;
	}

	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_pkey_close(const hal_pkey_handle_t pkey)
{
	uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
	uint8_t inbuf[nargs(3)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_CLOSE));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_CLOSE, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_pkey_delete(const hal_pkey_handle_t pkey)
{
	uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
	uint8_t inbuf[nargs(3)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_DELETE));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_DELETE, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_pkey_get_key_type(const hal_pkey_handle_t pkey,
	hal_key_type_t *type)
{
	uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
	uint8_t inbuf[nargs(4)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	uint32_t type32;
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GET_KEY_TYPE));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_GET_KEY_TYPE, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK) {
		check(hal_xdr_decode_int(&iptr, ilimit, &type32));
		*type = (hal_key_type_t)type32;
	}
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_pkey_get_key_curve(const hal_pkey_handle_t pkey,
	hal_curve_name_t *curve)
{
	uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
	uint8_t inbuf[nargs(4)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	uint32_t curve32;
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GET_KEY_CURVE));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_GET_KEY_CURVE, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK) {
		check(hal_xdr_decode_int(&iptr, ilimit, &curve32));
		*curve = (hal_curve_name_t)curve32;
	}
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_pkey_get_key_flags(const hal_pkey_handle_t pkey,
	hal_key_flags_t *flags)
{
	uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
	uint8_t inbuf[nargs(4)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	uint32_t flags32;
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GET_KEY_FLAGS));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_GET_KEY_FLAGS, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK) {
		check(hal_xdr_decode_int(&iptr, ilimit, &flags32));
		*flags = (hal_key_flags_t)flags32;
	}
	return (hal_error_t)rpc_ret;
}

size_t hal_rpc_pkey_get_public_key_len(const hal_pkey_handle_t pkey)
{
	uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
	uint8_t inbuf[nargs(4)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	uint32_t len32;
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GET_PUBLIC_KEY_LEN));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_GET_PUBLIC_KEY_LEN, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK &&
		hal_xdr_decode_int(&iptr, ilimit, &len32) == HAL_OK)
		return (size_t)len32;

	return 0;
}

hal_error_t hal_rpc_pkey_get_public_key(const hal_pkey_handle_t pkey,
	uint8_t *der, size_t *der_len, const size_t der_max)
{
	uint8_t outbuf[nargs(4)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);

	size_t sizeof_inbuf = nargs(4) + pad(der_max);
	uint8_t *inbuf = new uint8_t[sizeof_inbuf];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof_inbuf;
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	// use a unique_ptr to handle destruction of the data we just created
	// because VS only allows arrays created with const values
	std::unique_ptr<uint8_t> free_inbuf(inbuf);

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GET_PUBLIC_KEY));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
	check(hal_xdr_encode_int(&optr, olimit, der_max));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_GET_PUBLIC_KEY, inbuf, sizeof_inbuf, &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK) {
		uint32_t len32;
		check(hal_xdr_decode_int(&iptr, ilimit, &len32));
		if (der_len != NULL)
			*der_len = len32;
		if (der != NULL)
			check(hal_xdr_decode_fixed_opaque(&iptr, ilimit, der, len32));
	}
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_pkey_sign(const hal_pkey_handle_t pkey,
	const hal_hash_handle_t hash,
	const uint8_t * const input, const size_t input_len,
	uint8_t * signature, size_t *signature_len, const size_t signature_max)
{
	size_t sizeof_outbuf = nargs(6) + pad(input_len);
	uint8_t *outbuf = new uint8_t[sizeof_outbuf], *optr = outbuf, *olimit = outbuf + sizeof_outbuf;

	size_t sizeof_inbuf = nargs(4) + pad(signature_max);
	uint8_t *inbuf = new uint8_t[sizeof_inbuf];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof_inbuf;
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	// use a unique_ptr to handle destruction of the data we just created
	// because VS only allows arrays created with const values
	std::unique_ptr<uint8_t> free_outbuf(outbuf);
	std::unique_ptr<uint8_t> free_inbuf(inbuf);

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_SIGN));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
	check(hal_xdr_encode_int(&optr, olimit, hash.handle));
	check(hal_xdr_encode_variable_opaque(&optr, olimit, input, input_len));
	check(hal_xdr_encode_int(&optr, olimit, signature_max));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_SIGN, inbuf, sizeof_inbuf, &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK)
		check(hal_xdr_decode_variable_opaque(&iptr, ilimit, signature, signature_len, signature_max));
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_pkey_verify(const hal_pkey_handle_t pkey,
	const hal_hash_handle_t hash,
	const uint8_t * const input, const size_t input_len,
	const uint8_t * const signature, const size_t signature_len)
{
	size_t sizeof_outbuf = nargs(6) + pad(input_len) + pad(signature_len);
	uint8_t *outbuf = new uint8_t[sizeof_outbuf], *optr = outbuf, *olimit = outbuf + sizeof_outbuf;
	uint8_t inbuf[nargs(3)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	// use a unique_ptr to handle destruction of the data we just created
	// because VS only allows arrays created with const values
	std::unique_ptr<uint8_t> free_outbuf(outbuf);

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_VERIFY));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
	check(hal_xdr_encode_int(&optr, olimit, hash.handle));
	check(hal_xdr_encode_variable_opaque(&optr, olimit, input, input_len));
	check(hal_xdr_encode_variable_opaque(&optr, olimit, signature, signature_len));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_VERIFY, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_pkey_match(const hal_client_handle_t client,
	const hal_session_handle_t session,
	const hal_key_type_t type,
	const hal_curve_name_t curve,
	const hal_key_flags_t mask,
	const hal_key_flags_t flags,
	const hal_pkey_attribute_t *attributes,
	const unsigned attributes_len,
	unsigned *state,
	hal_uuid_t *result,
	unsigned *result_len,
	const unsigned result_max,
	const hal_uuid_t * const previous_uuid)
{
	size_t attributes_buffer_len = 0;
	if (attributes != NULL)
		for (int i = 0; i < attributes_len; i++)
			attributes_buffer_len += pad(attributes[i].length);

	size_t sizeof_outbuf = nargs(11 + attributes_len * 2) + attributes_buffer_len + pad(sizeof(hal_uuid_t));
	uint8_t *outbuf = new uint8_t[sizeof_outbuf];
	uint8_t *optr = outbuf, *olimit = outbuf + sizeof_outbuf;

	size_t sizeof_inbuf = nargs(5 + result_max) + pad(result_max * sizeof(hal_uuid_t));
	uint8_t *inbuf = new uint8_t[sizeof_inbuf];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof_inbuf;
	uint32_t rpc_ret;

	// use a unique_ptr to handle destruction of the data we just created
	// because VS only allows arrays created with const values
	std::unique_ptr<uint8_t> free_outbuf(outbuf);
	std::unique_ptr<uint8_t> free_inbuf(inbuf);

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_MATCH));
	check(hal_xdr_encode_int(&optr, olimit, client.handle));
	check(hal_xdr_encode_int(&optr, olimit, session.handle));
	check(hal_xdr_encode_int(&optr, olimit, type));
	check(hal_xdr_encode_int(&optr, olimit, curve));
	check(hal_xdr_encode_int(&optr, olimit, mask));
	check(hal_xdr_encode_int(&optr, olimit, flags));
	check(hal_xdr_encode_int(&optr, olimit, attributes_len));
	if (attributes != NULL) {
		for (int i = 0; i < attributes_len; i++) {
			check(hal_xdr_encode_int(&optr, olimit, attributes[i].type));
			check(hal_xdr_encode_variable_opaque(&optr, olimit, (uint8_t *)attributes[i].value, attributes[i].length));
		}
	}
	check(hal_xdr_encode_int(&optr, olimit, *state));
	check(hal_xdr_encode_int(&optr, olimit, result_max));
	check(hal_xdr_encode_variable_opaque(&optr, olimit, previous_uuid->uuid, sizeof(previous_uuid->uuid)));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_MATCH, inbuf, sizeof_inbuf, &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK) {
		uint32_t array_len, ustate;
		*result_len = 0;
		check(hal_xdr_decode_int(&iptr, ilimit, &ustate));
		*state = ustate;
		check(hal_xdr_decode_int(&iptr, ilimit, &array_len));
		for (int i = 0; i < array_len; ++i) {
			size_t uuid_len;
			check(hal_xdr_decode_variable_opaque(&iptr, ilimit, result[i].uuid, &uuid_len, sizeof(result[i].uuid)));
			if (uuid_len != sizeof(result[i].uuid))
				return HAL_ERROR_KEY_NAME_TOO_LONG;
		}
		*result_len = array_len;
	}
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_pkey_set_attributes(const hal_pkey_handle_t pkey,
	const hal_pkey_attribute_t *attributes,
	const unsigned attributes_len)
{
	size_t outbuf_len = nargs(4 + 2 * attributes_len);
	for (int i = 0; i < attributes_len; i++)
		outbuf_len += pad(attributes[i].length);

	uint8_t *outbuf = new uint8_t[outbuf_len], *optr = outbuf, *olimit = outbuf + outbuf_len;
	uint8_t inbuf[nargs(3)];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	// use a unique_ptr to handle destruction of the data we just created
	// because VS only allows arrays created with const values
	std::unique_ptr<uint8_t> free_outbuf(outbuf);

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_SET_ATTRIBUTES));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
	check(hal_xdr_encode_int(&optr, olimit, attributes_len));
	for (int i = 0; i < attributes_len; i++) {
		check(hal_xdr_encode_int(&optr, olimit, attributes[i].type));
		if (attributes[i].length == HAL_PKEY_ATTRIBUTE_NIL)
			check(hal_xdr_encode_int(&optr, olimit, HAL_PKEY_ATTRIBUTE_NIL));
		else
			check(hal_xdr_encode_variable_opaque(&optr, olimit, (uint8_t *)attributes[i].value, attributes[i].length));
	}
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_SET_ATTRIBUTES, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_pkey_get_attributes(const hal_pkey_handle_t pkey,
	hal_pkey_attribute_t *attributes,
	const unsigned attributes_len,
	uint8_t *attributes_buffer,
	const size_t attributes_buffer_len)
{
	/* inbuf[] here includes one extra word per attribute for padding */
	size_t sizeof_outbuf = nargs(5 + attributes_len);
	uint8_t *outbuf = new uint8_t[sizeof_outbuf], *optr = outbuf, *olimit = outbuf + sizeof_outbuf;

	size_t sizeof_inbuf = nargs(4 + 3 * attributes_len) + attributes_buffer_len;
	uint8_t *inbuf = new uint8_t[sizeof_inbuf];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof_inbuf;
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	// use a unique_ptr to handle destruction of the data we just created
	// because VS only allows arrays created with const values
	std::unique_ptr<uint8_t> free_outbuf(outbuf);
	std::unique_ptr<uint8_t> free_inbuf(inbuf);

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GET_ATTRIBUTES));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
	check(hal_xdr_encode_int(&optr, olimit, attributes_len));
	for (int i = 0; i < attributes_len; i++)
		check(hal_xdr_encode_int(&optr, olimit, attributes[i].type));
	check(hal_xdr_encode_int(&optr, olimit, attributes_buffer_len));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_GET_ATTRIBUTES, inbuf, sizeof_inbuf, &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK) {
		uint8_t *abuf = attributes_buffer;
		uint32_t u32;
		check(hal_xdr_decode_int(&iptr, ilimit, &u32));
		if (u32 != attributes_len)
			return HAL_ERROR_RPC_PROTOCOL_ERROR;
		for (int i = 0; i < attributes_len; i++) {
			check(hal_xdr_decode_int(&iptr, ilimit, &u32));
			if (u32 != attributes[i].type)
				return HAL_ERROR_RPC_PROTOCOL_ERROR;
			if (attributes_buffer_len == 0) {
				check(hal_xdr_decode_int(&iptr, ilimit, &u32));
				attributes[i].value = NULL;
				attributes[i].length = u32;
			}
			else {
				size_t len;
				check(hal_xdr_decode_variable_opaque(&iptr, ilimit, abuf, &len, attributes_buffer + attributes_buffer_len - abuf));
				attributes[i].value = abuf;
				attributes[i].length = len;
				abuf += len;
			}
		}
	}
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_pkey_export(const hal_pkey_handle_t pkey,
	const hal_pkey_handle_t kekek,
	uint8_t *pkcs8, size_t *pkcs8_len, const size_t pkcs8_max,
	uint8_t *kek, size_t *kek_len, const size_t kek_max)
{
	uint8_t outbuf[nargs(6)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);

	size_t sizeof_inbuf = nargs(5) + pad(pkcs8_max) + pad(kek_max);
	uint8_t *inbuf = new uint8_t[sizeof_inbuf];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof_inbuf;
	hal_client_handle_t dummy_client = { 0 };
	uint32_t rpc_ret;

	// use a unique_ptr to handle destruction of the data we just created
	// because VS only allows arrays created with const values
	std::unique_ptr<uint8_t> free_inbuf(inbuf);

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_EXPORT));
	check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
	check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
	check(hal_xdr_encode_int(&optr, olimit, kekek.handle));
	check(hal_xdr_encode_int(&optr, olimit, pkcs8_max));
	check(hal_xdr_encode_int(&optr, olimit, kek_max));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_EXPORT, inbuf, sizeof_inbuf, &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
	if (rpc_ret == HAL_OK) {
		check(hal_xdr_decode_variable_opaque(&iptr, ilimit, pkcs8, pkcs8_len, pkcs8_max));
		check(hal_xdr_decode_variable_opaque(&iptr, ilimit, kek, kek_len, kek_max));
	}
	return (hal_error_t)rpc_ret;
}

hal_error_t hal_rpc_pkey_import(const hal_client_handle_t client,
	const hal_session_handle_t session,
	hal_pkey_handle_t *pkey,
	hal_uuid_t *name,
	const hal_pkey_handle_t kekek,
	const uint8_t * const pkcs8, const size_t pkcs8_len,
	const uint8_t * const kek, const size_t kek_len,
	const hal_key_flags_t flags)
{
	size_t sizeof_outbuf = nargs(7) + pad(pkcs8_len) + pad(kek_len);
	uint8_t *outbuf = new uint8_t[sizeof_outbuf], *optr = outbuf, *olimit = outbuf + sizeof_outbuf;
	uint8_t inbuf[nargs(5) + pad(sizeof(name->uuid))];
	const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
	size_t name_len;
	uint32_t rpc_ret;

	// use a unique_ptr to handle destruction of the data we just created
	// because VS only allows arrays created with const values
	std::unique_ptr<uint8_t> free_inbuf(inbuf);

	check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_IMPORT));
	check(hal_xdr_encode_int(&optr, olimit, client.handle));
	check(hal_xdr_encode_int(&optr, olimit, session.handle));
	check(hal_xdr_encode_int(&optr, olimit, kekek.handle));
	check(hal_xdr_encode_variable_opaque(&optr, olimit, pkcs8, pkcs8_len));
	check(hal_xdr_encode_variable_opaque(&optr, olimit, kek, kek_len));
	check(hal_xdr_encode_int(&optr, olimit, flags));
	check(hal_rpc_send(outbuf, optr - outbuf));

	check(read_matching_packet(RPC_FUNC_PKEY_IMPORT, inbuf, sizeof(inbuf), &iptr, &ilimit));

	check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));

	if (rpc_ret == HAL_OK) {
		check(hal_xdr_decode_int(&iptr, ilimit, &pkey->handle));
		check(hal_xdr_decode_variable_opaque(&iptr, ilimit, name->uuid, &name_len, sizeof(name->uuid)));
		if (name_len != sizeof(name->uuid))
			return HAL_ERROR_KEY_NAME_TOO_LONG;
	}

	return (hal_error_t)rpc_ret;
}

