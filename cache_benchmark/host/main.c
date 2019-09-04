#include <arpa/inet.h>
#include <err.h>
#include <math.h>
#include <netinet/in.h> 
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
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
#include <cache_benchmarking_ta.h>

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

int non_secure_payload_reencryption(mqttz_client *origin, mqttz_client *dest,
        mqttz_times *times)
{
    struct timeval t_ini, t_end;
    int dec_len, enc_len;
    char fake_key[AES_KEY_SIZE + 1];
    char fake_iv[AES_IV_SIZE + 1];
    memset(fake_iv, '1', AES_IV_SIZE);
    fake_iv[AES_IV_SIZE] = '\0';
    char buff_data[MQTTZ_MAX_MSG_SIZE];
    char buff_data_2[MQTTZ_MAX_MSG_SIZE];
    switch (times->key_mode)
    {
        case KEY_IN_MEM:
            gettimeofday(&t_ini, NULL);
            memset(fake_key, '1', AES_KEY_SIZE);
            fake_key[AES_KEY_SIZE] = '\0';
            gettimeofday(&t_end, NULL);
            timersub(&t_end, &t_ini, &times->t_ret_dec_key);
            gettimeofday(&t_ini, NULL);
            enc_len = encrypt((unsigned char *) origin->data,
                    strlen(origin->data), (unsigned char *) fake_key,
                    (unsigned char *) fake_iv, (unsigned char *) buff_data_2,
                    AES_KEY_SIZE);
            gettimeofday(&t_end, NULL);
            timersub(&t_end, &t_ini, &times->t_enc);
            gettimeofday(&t_ini, NULL);
            // Load second fake key from memory
            memset(fake_key, '1', AES_KEY_SIZE);
            fake_key[AES_KEY_SIZE] = '\0';
            gettimeofday(&t_end, NULL);
            timersub(&t_end, &t_ini, &times->t_ret_enc_key);
            gettimeofday(&t_ini, NULL);
            dec_len = decrypt((unsigned char *) buff_data_2, enc_len,
                    (unsigned char *) fake_key, (unsigned char *) fake_iv,
                    (unsigned char *) buff_data, AES_KEY_SIZE);
            //printf("Decrypted text: %s\n", buff_data);
            gettimeofday(&t_end, NULL);
            timersub(&t_end, &t_ini, &times->t_dec);
            break;
        case KEY_IN_SS: ;
            gettimeofday(&t_ini, NULL);
            FILE *fp;
            fp = fopen(FAKE_KEY_FILE, "r");
            if (fp == NULL)
            {
                printf("MQT-TZ: ERROR! Can't open file!\n");
                return 1;
            }
            else
            {
                fgets(fake_key, AES_KEY_SIZE + 1, fp);
                //printf("Read key from file: %s\n", fake_key);
            }
            gettimeofday(&t_end, NULL);
            timersub(&t_end, &t_ini, &times->t_ret_dec_key);
            gettimeofday(&t_ini, NULL);
            enc_len = encrypt((unsigned char *) origin->data,
                    strlen(origin->data), (unsigned char *) fake_key,
                    (unsigned char *) fake_iv, (unsigned char *) buff_data_2,
                    AES_KEY_SIZE);
            gettimeofday(&t_end, NULL);
            timersub(&t_end, &t_ini, &times->t_enc);
            gettimeofday(&t_ini, NULL);
            fp = fopen(FAKE_KEY_FILE, "r");
            if (fp == NULL)
            {
                printf("MQT-TZ: ERROR! Can't open file!\n");
                return 1;
            }
            else
            {
                fgets(fake_key, AES_KEY_SIZE + 1, fp);
                //printf("Read key from file: %s\n", fake_key);
            }
            gettimeofday(&t_end, NULL);
            timersub(&t_end, &t_ini, &times->t_ret_enc_key);
            gettimeofday(&t_ini, NULL);
            dec_len = decrypt((unsigned char *) buff_data_2, enc_len,
                    (unsigned char *) fake_key, (unsigned char *) fake_iv,
                    (unsigned char *) buff_data, AES_KEY_SIZE);
            //printf("Decrypted text: %s\n", buff_data);
            gettimeofday(&t_end, NULL);
            timersub(&t_end, &t_ini, &times->t_dec);
            break;
    }
    return 0;
}

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_HOT_CACHE_UUID;
	uint32_t origin;
	TEEC_Result res;
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
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


TEEC_Result cache_benchmarking(struct test_ctx *ctx)
{
    // Dummy
    TEEC_Operation op;
    uint32_t ori;
    TEEC_Result res;
    memset(&op, 0, sizeof op);
    op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE);
    res = TEEC_InvokeCommand(&ctx->sess, TA_CACHE_BENCHMARK, &op, &ori);
    return res;
}

int main(int argc, char *argv[])
{
    printf("Starting Cache Benchmarking!\n");
	struct test_ctx ctx;
    parse_arguments(argc, argv, origin, dest);
    prepare_tee_session(&ctx);
    times->key_mode = KEY_IN_SS;
    cache_benchmarking(&ctx);
    terminate_tee_session(&ctx);
    printf("Finished Cache Benchmarking!\n");
	return 0;
}
