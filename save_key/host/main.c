/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* TA API: UUID and command IDs */
#include <save_key_ta.h>

#define MQTTZ_CLI_ID_SIZE 12

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_SAVE_KEY_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

TEEC_Result write_secure_key(struct test_ctx *ctx, char *id, char *data,
        int mode)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
                     TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
                     TEEC_NONE,
                     TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = strlen(id);

	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = strlen(data);

	//op.params[2].value.a = 0;

	res = TEEC_InvokeCommand(&ctx->sess, TA_SECURE_STORAGE_CMD_WRITE_RAW,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);

	switch (res) {
	case TEEC_SUCCESS:
		break;
	default:
		printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

int parse_arguments(int argc, char *argv[], char *cli_id, int *mode,
        char *cli_key)
{
    if (argc != 4)
    {
        printf("MQTTZ-ERROR: Too few parameters supplied!\n");
        return 1;
    }
    strcpy(cli_id, argv[1]);
    *mode = atoi(argv[2]);
    if (strlen(cli_id) != MQTTZ_CLI_ID_SIZE)
    {
        printf("MQTTZ-ERROR: Bad Cli ID introduced!\n");
        return 1;
    }
    strcpy(cli_key, argv[3]);
    return 0;
}

int main(int argc, char *argv[])
{
	struct test_ctx ctx;
    char *cli_id;
    cli_id = malloc(sizeof *cli_id * (strlen(argv[1]) + 1));
    memset(cli_id, '\0', (strlen(argv[1]) + 1));
    char *cli_key;
    cli_key = malloc(sizeof *cli_key * (strlen(argv[3]) + 1));
    memset(cli_key, '\0', (strlen(argv[3]) + 1));
    int mode;
	TEEC_Result res;

	prepare_tee_session(&ctx);
    if (parse_arguments(argc, argv, cli_id, &mode, cli_key) != 0)
    {
        printf("MQTTZ-ERROR: Error parsing command line arguments!\n");
        return 1;
    }


	printf("Loading key for client with id: %s\n", cli_id);

	res = write_secure_key(&ctx, cli_id, cli_key, mode);
	if (res != TEEC_SUCCESS)
		errx(1, "Failed to load the key in secure storage");

	terminate_tee_session(&ctx);
	return 0;
}
