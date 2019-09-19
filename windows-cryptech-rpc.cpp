// windows-cryptech-rpc.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

/*
* Error checking for libhal calls.
*/

#define hal_whine(_expr_)            (_hal_whine((_expr_), #_expr_, __FILE__, __LINE__, HAL_OK))
#define hal_whine_allow(_expr_, ...) (_hal_whine((_expr_), #_expr_, __FILE__, __LINE__, __VA_ARGS__, HAL_OK))
#define hal_check(_expr_)            (_expr_ == HAL_OK)

#include <iostream>

int main()
{
	if (!hal_check(hal_rpc_client_transport_init_ip("10.1.10.9", "dks-hsm")))
	{
		printf("\n'%s' at '%s'\n", "10.1.10.9", "dks-hsm");
		std::cin.ignore();
		return 0;
	}

	uint32_t version;
	if (!hal_check(hal_rpc_get_version(&version)))
	{
		printf("\nError getting the version\n");
		std::cin.ignore();
		return 0;
	}

	printf("version == %i", (int)version);

	hal_rpc_client_transport_close();

	std::cin.ignore();

    return 1;
}

