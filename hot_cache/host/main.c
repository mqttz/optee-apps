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
// Benchmark Parameters
#define NUMBER_TESTS                    2 //100
#define NUMBER_WORLDS                   2
#define KEY_MODES                       2
#define KEY_IN_MEM                      0
#define KEY_IN_SS                       1
#define NW                              0
#define SW                              1

// Times are in miliseconds
typedef struct mqttz_times {
    struct timeval t_ret_dec_key;
    struct timeval t_dec;
    struct timeval t_ret_enc_key;
    struct timeval t_enc;
    double ret_dec_key[NUMBER_WORLDS][KEY_MODES * NUMBER_TESTS];
    double dec_times[NUMBER_WORLDS][KEY_MODES * NUMBER_TESTS];
    double ret_enc_key[NUMBER_WORLDS][KEY_MODES * NUMBER_TESTS];
    double enc_times[NUMBER_WORLDS][KEY_MODES * NUMBER_TESTS];
    int key_mode;
    int world;
    bool benchmark;
} mqttz_times;


double avg(double* arr, int num_elements)
{
    double ret = 0.0;
    for (int i = 0; i < num_elements; i++)
        ret += *(arr + i);
    return ret / num_elements; 
}


double stdev(double* arr, int num_elements)
{
    double sq_sum = 0.0;
    for (int i = 0; i < num_elements; i++)
        sq_sum += pow(*(arr + i), 2);
    return sqrt(sq_sum / num_elements - pow(avg(arr, num_elements), 2));
}


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


TEEC_Result payload_reencryption(struct test_ctx *ctx, mqttz_client *origin,
        mqttz_client *dest, mqttz_times *times)
{
    // Dummy
    gettimeofday(&(times->t_ret_dec_key), NULL); 
    gettimeofday(&(times->t_dec), NULL); 
    gettimeofday(&(times->t_ret_enc_key), NULL); 
    gettimeofday(&(times->t_enc), NULL); 

    TEEC_Operation op;
    uint32_t ori;
    TEEC_Result res;

    memset(&op, 0, sizeof op);
    if (times->benchmark)
    {
        op.paramTypes = TEEC_PARAM_TYPES(
                TEEC_MEMREF_TEMP_INPUT,
                TEEC_MEMREF_TEMP_INOUT,
                TEEC_NONE,
                TEEC_NONE);
    }
    else
    {
        op.paramTypes = TEEC_PARAM_TYPES(
                TEEC_MEMREF_TEMP_INPUT,
                TEEC_MEMREF_TEMP_INOUT,
                TEEC_NONE,
                TEEC_NONE);
    }
    
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

int benchmark(struct test_ctx *ctx, mqttz_client *origin, mqttz_client *dest,
        mqttz_times *times)
{
    FILE *fp;

    // Launch Tests
    printf("MQT-TZ: Starting Benchmarking!\n");
    int test, world, key;
    for (test = 0; test < NUMBER_TESTS; test++)
    {
        for (world = 0; world < NUMBER_WORLDS; world++)
        {
            times->world = world;
            for (key = 0; key < KEY_MODES; key++)
            {
                times->key_mode = key;
	            prepare_tee_session(ctx);
                payload_reencryption(ctx, origin, dest, times);
	            terminate_tee_session(ctx);
                int pos = key * NUMBER_TESTS + test;
                printf("%i %i\n", world, pos);
                times->ret_dec_key[world][pos] = (times->t_ret_dec_key).tv_sec
                    * 1000.0 + (times->t_ret_dec_key).tv_usec / 1000.0;
                times->dec_times[world][pos] = (times->t_dec).tv_sec
                    * 1000.0 + (times->t_dec).tv_usec / 1000.0;
                times->ret_enc_key[world][pos] = (times->t_ret_enc_key).tv_sec
                    * 1000.0 + (times->t_ret_enc_key).tv_usec / 1000.0;
                times->enc_times[world][pos] = (times->t_enc).tv_sec
                    * 1000.0 + (times->t_enc).tv_usec / 1000.0;
            }
        }
    }
    printf("MQT-TZ: Finished benchmarking, printing to file!\n");

    // Print Results
    fp = fopen("results/ub1_s_mem.dat", "w");
    printf("Not even here?\n");
    int i = 0;
    printf("%f\n", times->ret_dec_key[0][0]);
    printf("%f\n", times->ret_dec_key[0][i]);
    printf("%f\n", times->ret_dec_key[0][2]);
    printf("%f\n", times->ret_dec_key[0][3]);
    double *tt = &times->ret_dec_key[0][0];
    for (i = 0; i < 2; i++)
        printf("%f\n", times->ret_dec_key[0][i]);
        //printf("%f ", *(tt + i));
    fprintf(fp, "%f %f ",
            avg(&(times->ret_dec_key[SW][KEY_IN_MEM * NUMBER_TESTS]),
            NUMBER_TESTS),
            stdev(&(times->ret_dec_key[SW][KEY_IN_MEM * NUMBER_TESTS]),
            NUMBER_TESTS));
    printf("Not even here?\n");
    fprintf(fp, "%f %f ",
            avg(&(times->dec_times[SW][KEY_IN_MEM * NUMBER_TESTS]),
            NUMBER_TESTS),
            stdev(&(times->dec_times[SW][KEY_IN_MEM * NUMBER_TESTS]),
            NUMBER_TESTS));
    fprintf(fp, "%f %f ",
            avg(&(times->ret_enc_key[SW][KEY_IN_MEM * NUMBER_TESTS]),
            NUMBER_TESTS),
            stdev(&(times->ret_enc_key[SW][KEY_IN_MEM * NUMBER_TESTS]),
            NUMBER_TESTS));
    fprintf(fp, "%f %f\n",
            avg(&(times->enc_times[SW][KEY_IN_MEM * NUMBER_TESTS]),
            NUMBER_TESTS),
            stdev(&(times->enc_times[SW][KEY_IN_MEM * NUMBER_TESTS]),
            NUMBER_TESTS));
    fclose(fp);
    printf("First done?\n");
    fp = fopen("results/ub1_ns_mem.dat", "w");
    fprintf(fp, "%f %f ",
            avg(&(times->ret_dec_key[NW][KEY_IN_MEM * NUMBER_TESTS]),
            NUMBER_TESTS),
            stdev(&(times->ret_dec_key[NW][KEY_IN_MEM * NUMBER_TESTS]),
            NUMBER_TESTS));
    fprintf(fp, "%f %f ", 
            avg(&(times->dec_times[NW][KEY_IN_MEM * NUMBER_TESTS]),
            NUMBER_TESTS),
            stdev(&(times->dec_times[NW][KEY_IN_MEM * NUMBER_TESTS]),
            NUMBER_TESTS));
    fprintf(fp, "%f %f ",
            avg(&(times->ret_enc_key[NW][KEY_IN_MEM * NUMBER_TESTS]),
            NUMBER_TESTS),
            stdev(&(times->ret_enc_key[NW][KEY_IN_MEM * NUMBER_TESTS]),
            NUMBER_TESTS));
    fprintf(fp, "%f %f\n",
            avg(&(times->enc_times[NW][KEY_IN_MEM * NUMBER_TESTS]),
            NUMBER_TESTS),
            stdev(&(times->enc_times[NW][KEY_IN_MEM * NUMBER_TESTS]),
            NUMBER_TESTS));
    fclose(fp);
    printf("Second done?\n");
    fp = fopen("results/ub1_s_ss.dat", "w");
    fprintf(fp, "%f %f ",
            avg(&(times->ret_dec_key[SW][KEY_IN_SS * NUMBER_TESTS]),
            NUMBER_TESTS),
            stdev(&(times->ret_dec_key[SW][KEY_IN_SS * NUMBER_TESTS]),
            NUMBER_TESTS));
    fprintf(fp, "%f %f ",
            avg(&(times->dec_times[SW][KEY_IN_SS * NUMBER_TESTS]),
            NUMBER_TESTS),
            stdev(&(times->dec_times[SW][KEY_IN_SS * NUMBER_TESTS]),
            NUMBER_TESTS));
    fprintf(fp, "%f %f ",
            avg(&(times->ret_enc_key[SW][KEY_IN_SS * NUMBER_TESTS]),
            NUMBER_TESTS),
            stdev(&(times->ret_enc_key[SW][KEY_IN_SS * NUMBER_TESTS]),
            NUMBER_TESTS));
    fprintf(fp, "%f %f\n",
            avg(&(times->enc_times[SW][KEY_IN_SS * NUMBER_TESTS]),
            NUMBER_TESTS),
            stdev(&(times->enc_times[SW][KEY_IN_SS * NUMBER_TESTS]),
            NUMBER_TESTS));
    fclose(fp);
    printf("Third done?\n");
    fp = fopen("results/ub1_ns_ss.dat", "w");
    fprintf(fp, "%f %f ",
            avg(&(times->ret_dec_key[NW][KEY_IN_SS * NUMBER_TESTS]),
            NUMBER_TESTS),
            stdev(&(times->ret_dec_key[NW][KEY_IN_SS * NUMBER_TESTS]),
            NUMBER_TESTS));
    fprintf(fp, "%f %f ",
            avg(&(times->dec_times[NW][KEY_IN_SS * NUMBER_TESTS]),
            NUMBER_TESTS),
            stdev(&(times->dec_times[NW][KEY_IN_SS * NUMBER_TESTS]),
            NUMBER_TESTS));
    fprintf(fp, "%f %f ",
            avg(&(times->ret_enc_key[NW][KEY_IN_SS * NUMBER_TESTS]),
            NUMBER_TESTS),
            stdev(&(times->ret_enc_key[NW][KEY_IN_SS * NUMBER_TESTS]),
            NUMBER_TESTS));
    fprintf(fp, "%f %f\n",
            avg(&(times->enc_times[NW][KEY_IN_SS * NUMBER_TESTS]),
            NUMBER_TESTS),
            stdev(&(times->enc_times[NW][KEY_IN_SS * NUMBER_TESTS]),
            NUMBER_TESTS));
    fclose(fp);
    printf("MQT-TZ: Finished printing to file!\n");
}

int main(int argc, char *argv[])
{
	struct test_ctx ctx;
    mqttz_client *origin;
    origin = malloc(sizeof *origin);
    mqttz_client *dest;
    dest = malloc(sizeof *dest);
    mqttz_times *times;
    times = malloc(sizeof *times);
    times->benchmark = 1;

    // Dummy TEE Context to check if all files are OK
	//prepare_tee_session(&ctx);

    parse_arguments(argc, argv, origin, dest);
    if (times->benchmark)
    {
	    //prepare_tee_session(&ctx);
        benchmark(&ctx, origin, dest, times);
	    //terminate_tee_session(&ctx);
    }
    else
        payload_reencryption(&ctx, origin, dest, times);

    // Terminate Dummy TEE Context
	//terminate_tee_session(&ctx);
    free_client(origin);
    free_client(dest);
	return 0;
}

//./optee_hot_cache 123123123123 1111111111111111 holaholaholahoholahola 123123123123
//./optee_save_key 123123123123 0 11111111111111111111111111111111
