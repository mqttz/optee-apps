#include <arpa/inet.h>
#include <err.h>
#include <math.h>
#include <netinet/in.h> 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h> 
#include <sys/time.h>
#include <regex.h>
#include <unistd.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* TA API: UUID and command IDs */
#include <hot_cache_ta.h>

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

typedef struct mqttz_client {
    char *cli_id;
    char *iv;
    char *data;
} mqttz_client;

#define MQTTZ_MAX_MSG_SIZE              4096
#define AES_IV_SIZE                     16
#define AES_KEY_SIZE                    32

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_HOT_CACHE_UUID;
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


TEEC_Result read_secure_object(struct test_ctx *ctx, char *id,
			char *data, size_t data_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = data_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_STORAGE_CMD_READ_RAW,
				 &op, &origin);
	switch (res) {
	case TEEC_SUCCESS:
	case TEEC_ERROR_SHORT_BUFFER:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command READ_RAW failed: 0x%x / %u\n", res, origin);
	}

	return res;
}


TEEC_Result write_secure_object(struct test_ctx *ctx, char *id,
			char *data, size_t data_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = data_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_STORAGE_CMD_WRITE_RAW,
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

TEEC_Result payload_reencryption(struct test_ctx *ctx, mqttz_client *origin,
        mqttz_client *dest)
{
    TEEC_Operation op;
    uint32_t ori;
    TEEC_Result res;

    memset(&op, 0, sizeof op);
    op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_INOUT,
            TEEC_NONE,
            TEEC_NONE);
    
    // We need to deconstruct the struct the internal structure is lost
    // in the REE -> TEE communication.
    size_t ori_size = strlen(origin->cli_id) + strlen(origin->iv)
            + strlen(origin->data);
    char *tmp_ori = malloc(ori_size + 1);
    memset(tmp_ori, '\0', ori_size + 1);
    strcpy(tmp_ori, origin->cli_id);
    strcat(tmp_ori, origin->iv);
    strcat(tmp_ori, origin->data);
    tmp_ori[ori_size] = '\0';
    //printf("1st: %s\n", tmp_ori);
    size_t dest_size = strlen(dest->cli_id) + AES_IV_SIZE + MQTTZ_MAX_MSG_SIZE;
    char *tmp_dest = malloc(dest_size + 1);
    memset(tmp_dest, '\0', dest_size + 1);
    strcpy(tmp_dest, dest->cli_id);
    op.params[0].tmpref.buffer = tmp_ori;
    op.params[0].tmpref.size = ori_size;
    op.params[1].tmpref.buffer = tmp_dest;
    op.params[1].tmpref.size = dest_size;
    //printf("Destination before sending: %s\n", tmp_dest);
    res = TEEC_InvokeCommand(&ctx->sess, TA_REENCRYPT, &op, &ori);
    printf("%s\n", tmp_dest);

    /*
    switch(res)
    {
        case TEEC_SUCCESS:
            printf("Reencryption finished succesfully!\n");
            break;
        default:
            printf("Failed!\n");
    }*/

    free(tmp_ori);
    free(tmp_dest);
    return res;
}

int parse_arguments(int argc, char *argv[], mqttz_client *origin,
        mqttz_client *dest)
{
    if (argc != 5)
    {
        printf("MQTTZ Usage ERROR! Not right amount of parameters supplied.\n");
        return 1;
    }
    else
    {
        // Origin Client ID
        origin->cli_id = malloc(sizeof *(origin->cli_id) 
                * (strlen(argv[1]) + 1));
        memset(origin->cli_id, '\0', (strlen(argv[1]) +1));
        strcpy(origin->cli_id, argv[1]);
        // Origin Client IV
        origin->iv = malloc(sizeof *(origin->iv) * (strlen(argv[2]) + 1));
        memset(origin->iv, '\0', (strlen(argv[2]) + 1));
        strcpy(origin->iv, argv[2]);
        // Origin Client Data
        origin->data = malloc(sizeof *(origin->data) * (strlen(argv[3]) + 1));
        memset(origin->data, '\0', (strlen(argv[3]) + 1));
        strcpy(origin->data, argv[3]);
        // Destination Client ID
        dest->cli_id = malloc(sizeof *(dest->cli_id) * (strlen(argv[4]) + 1));
        memset(dest->cli_id, '\0', (strlen(argv[4]) + 1));
        strcpy(dest->cli_id, argv[4]);
        // Destination Client IV
        dest->iv = malloc(sizeof *(dest->iv) * (AES_IV_SIZE + 1));
        memset(dest->iv, '\0', (AES_IV_SIZE + 1));
        // strcpy(dest->iv, argv[5]);
        // Origin Client Data
        dest->data = malloc(sizeof *(dest->data) * MQTTZ_MAX_MSG_SIZE);
        memset(dest->data, '\0', MQTTZ_MAX_MSG_SIZE);
        // strcpy(dest->data, argv[6]);
    }
    return 0;
}

int free_client(mqttz_client *cli)
{
    free(cli->cli_id);
    free(cli->iv);
    free(cli->data);
    free(cli);
    return 0;
}

int main(int argc, char *argv[])
{
	struct test_ctx ctx;
    //struct timeval t1, t2;
    mqttz_client *origin;
    origin = malloc(sizeof *origin);
    mqttz_client *dest;
    dest = malloc(sizeof *dest);

    // Dummy TEE Context to check if all files are OK
	prepare_tee_session(&ctx);

    parse_arguments(argc, argv, origin, dest);
    payload_reencryption(&ctx, origin, dest);

    // Terminate Dummy TEE Context
	terminate_tee_session(&ctx);
    free_client(origin);
    free_client(dest);
	return 0;
}

//./optee_hot_cache 123123123123 1111111111111111 holaholaholahoholahola 123123123123
//./optee_save_key 123123123123 0 11111111111111111111111111111111
