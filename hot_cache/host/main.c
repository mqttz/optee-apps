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
#define NUMBER_TESTS                    20 //100
#define NUMBER_WORLDS                   2
#define KEY_MODES                       2
#define KEY_IN_MEM                      0
#define KEY_IN_SS                       1
#define NW                              0
#define SW                              1
#define FAKE_KEY_FILE                   "fake_key.key"

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
    int i = 0;
    double ret = 0.0;
    for (i = 0; i < num_elements; i++)
    {
        ret += *(arr + i);
    }
    return ret / num_elements; 
}


double stdev(double* arr, int num_elements)
{
    double sq_sum = 0.0;
    for (int i = 0; i < num_elements; i++)
        sq_sum += pow(*(arr + i), 2);
    return sqrt(sq_sum / num_elements - pow(avg(arr, num_elements), 2));
}

// Error handling for encryption and decryption in the NS world usign OpenSSl
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

// Encryption in the NS world using OpenSSL
int encrypt(unsigned char *plain_text, int plain_text_len, unsigned char *key,
        unsigned char *iv, unsigned char *cipher_text, int key_size)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int cipher_text_len;
    // Create and initialise the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    // Initialise the encryption operation
    switch (key_size) 
    {
        case 16:
            if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
                handleErrors();
            break;
        case 32:
            if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
                handleErrors();
            break;
        default:
            return -1;
    }
    // Encrypt the input text
    if (1 != EVP_EncryptUpdate(ctx, cipher_text, &len, plain_text,
                plain_text_len))
        handleErrors();
    cipher_text_len = len;
    // Finalise the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, cipher_text + len, &len))
        handleErrors();
    cipher_text_len += len;
    // Clean Context
    EVP_CIPHER_CTX_free(ctx);
    return cipher_text_len;
}

// Decryption in the NS World using OpenSSL
int decrypt(unsigned char *cipher_text, int cipher_text_len, unsigned char *key,
        unsigned char *iv, unsigned char *decrypted_text, int key_size)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int decrypted_text_len;
    // Initialise context
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    // Initialise cipher suite
    switch (key_size)
    {
        case 16:
            if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) 
                handleErrors();
            break;
        case 32:
            if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) 
                handleErrors();
            break;
        default:
            return -1;
    }
    // Start decryption
    if(1 != EVP_DecryptUpdate(ctx, decrypted_text, &len, cipher_text,
                cipher_text_len)) 
        handleErrors();
    decrypted_text_len = len;
    // Finalise decryption
    if(1 != EVP_DecryptFinal_ex(ctx, decrypted_text + len, &len))
        handleErrors();
    decrypted_text_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return decrypted_text_len;
}

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
    TEEC_Operation op;
    uint32_t ori;
    TEEC_Result res;

    memset(&op, 0, sizeof op);
    //if (times->benchmark)
    //{
    op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_INOUT,
            TEEC_MEMREF_TEMP_INOUT,
            TEEC_VALUE_INPUT);
    //}
    //else
    //{
        /*
        op.paramTypes = TEEC_PARAM_TYPES(
                TEEC_MEMREF_TEMP_INPUT,
                TEEC_MEMREF_TEMP_INOUT,
                TEEC_NONE,
                TEEC_NONE);
    }*/
    
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
    size_t dest_size = strlen(dest->cli_id) + AES_IV_SIZE + MQTTZ_MAX_MSG_SIZE;
    char *tmp_dest = malloc(dest_size + 1);
    memset(tmp_dest, '\0', dest_size + 1);
    strcpy(tmp_dest, dest->cli_id);
    op.params[0].tmpref.buffer = tmp_ori;
    op.params[0].tmpref.size = ori_size;
    op.params[1].tmpref.buffer = tmp_dest;
    op.params[1].tmpref.size = dest_size;
    op.params[2].tmpref.buffer = malloc(sizeof(char) * 100);
    op.params[2].tmpref.size = 100;
    op.params[3].value.a = times->key_mode;
    printf("Invokation with this params: \n%s\n%s\n%s\n%i\n",
            op.params[0].tmpref.buffer, op.params[1].tmpref.buffer,
            op.params[2].tmpref.buffer, op.params[3].value.a);
    res = TEEC_InvokeCommand(&ctx->sess, TA_REENCRYPT, &op, &ori);
    // Results are stored in tmp_dest
    const char deli[] = ",";
    char *token;
    token = strtok(op.params[2].tmpref.buffer, deli);
    times->t_ret_dec_key = (struct timeval){0, atoi(token) * 1000};
    token = strtok(NULL, deli);
    times->t_enc = (struct timeval){0, atoi(token) * 1000};
    token = strtok(NULL, deli);
    times->t_ret_enc_key = (struct timeval){0, atoi(token) * 1000};
    token = strtok(NULL, deli);
    times->t_dec = (struct timeval){0, atoi(token) * 1000};
    printf("Results: %s\n", tmp_dest);
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
    if (argc == 3)
    {
        // FIXME This is only a workaround for MW article!!
        // Origin Client ID
        origin->cli_id = malloc(sizeof *(origin->cli_id) 
                * (strlen(argv[1]) + 1));
        memset(origin->cli_id, '\0', (strlen(argv[1]) +1));
        strcpy(origin->cli_id, argv[1]);
        // Fake origin IV
        origin->iv = malloc(sizeof *(origin->iv) * (AES_IV_SIZE + 1));
        memset(origin->iv, '1', AES_IV_SIZE);
        origin->iv[AES_IV_SIZE] = '\0';
        // Fake origin data
        origin->data = malloc(sizeof *(origin->data) * (4000 + 1));
        memset(origin->data, 'h', 4000 + 1);
        origin->data[4000] = '\0';
        // Destination Client ID
        dest->cli_id = malloc(sizeof *(dest->cli_id) * (strlen(argv[2]) + 1));
        memset(dest->cli_id, '\0', (strlen(argv[2]) + 1));
        strcpy(dest->cli_id, argv[2]);
        // Destination Client IV
        dest->iv = malloc(sizeof *(dest->iv) * (AES_IV_SIZE + 1));
        memset(dest->iv, '\0', (AES_IV_SIZE + 1));
        // Origin Client Data
        dest->data = malloc(sizeof *(dest->data) * MQTTZ_MAX_MSG_SIZE);
        memset(dest->data, '\0', MQTTZ_MAX_MSG_SIZE);
    }
    else if (argc == 5)
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
        // FIXME FIXME FIXME
        // origin->data = malloc(sizeof *(origin->data) * (strlen(argv[3]) + 1));
        // memset(origin->data, '\0', (strlen(argv[3]) + 1));
        // strcpy(origin->data, argv[3]);
        origin->data = malloc(sizeof *(origin->data) * (4000 + 1));
        memset(origin->data, 'h', 4000 + 1);
        origin->data[4000] = '\0';
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
    else
    {
        printf("MQTTZ Usage ERROR! Not right amount of parameters supplied.\n");
        return 1;
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
    // Launch Tests
    printf("MQT-TZ: Starting Benchmarking!\n");
    int test, world, key;
    FILE *fp;
    fp = fopen(FAKE_KEY_FILE, "w");
    if (fp == NULL)
    {
        printf("MQT-TZ: ERROR! Can't wirte to file!\n");
        return 1;
    }
    char fake_key[AES_KEY_SIZE + 1];
    memset(fake_key, '1', AES_KEY_SIZE);
    fake_key[AES_KEY_SIZE] = '\0';
    fputs(fake_key, fp);
    fclose(fp);
    for (test = 0; test < NUMBER_TESTS; test++)
    {
        for (world = 0; world < NUMBER_WORLDS; world++)
        {
            times->world = world;
            for (key = 0; key < KEY_MODES; key++)
            {
                times->key_mode = key;
                switch (world)
                {
                    case NW:
                        if (non_secure_payload_reencryption(origin, dest,
                                    times) != 0)
                            return 1;
                        break;
                    case SW:
	                    prepare_tee_session(ctx);
                        payload_reencryption(ctx, origin, dest, times);
	                    terminate_tee_session(ctx);
                        break;
                    default:
                        return 1;
                }
                int pos = key * NUMBER_TESTS + test;
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
    printf("MQT-TZ: Finished benchmarking, printing results!\n");
    printf("Retrieve Decrypt Key, Decrypt, Retrieve Encrypt Key, Encrypt\n");
    printf("NW - MEM\n");
    printf("%f %f\n",
            avg(&times->ret_dec_key[NW][KEY_IN_MEM * NUMBER_TESTS], 
                NUMBER_TESTS),
            stdev(&times->ret_dec_key[NW][KEY_IN_MEM * NUMBER_TESTS],
                NUMBER_TESTS));
    printf("%f %f\n",
            avg(&times->dec_times[NW][KEY_IN_MEM * NUMBER_TESTS],
            NUMBER_TESTS),
            stdev(&times->dec_times[NW][KEY_IN_MEM * NUMBER_TESTS],
            NUMBER_TESTS));
    printf("%f %f\n",
            avg(&times->ret_enc_key[NW][KEY_IN_MEM * NUMBER_TESTS],
            NUMBER_TESTS),
            stdev(&times->ret_enc_key[NW][KEY_IN_MEM * NUMBER_TESTS],
            NUMBER_TESTS));
    printf("%f %f\n",
            avg(&times->enc_times[NW][KEY_IN_MEM * NUMBER_TESTS],
            NUMBER_TESTS),
            stdev(&times->enc_times[NW][KEY_IN_MEM * NUMBER_TESTS],
            NUMBER_TESTS));
    printf("SW - MEM\n");
    printf("%f %f\n",
            avg(&times->ret_dec_key[SW][KEY_IN_MEM * NUMBER_TESTS],
            NUMBER_TESTS),
            stdev(&times->ret_dec_key[SW][KEY_IN_MEM * NUMBER_TESTS],
            NUMBER_TESTS));
    printf("%f %f\n", 
            avg(&times->dec_times[SW][KEY_IN_MEM * NUMBER_TESTS],
            NUMBER_TESTS),
            stdev(&times->dec_times[SW][KEY_IN_MEM * NUMBER_TESTS],
            NUMBER_TESTS));
    printf("%f %f\n",
            avg(&times->ret_enc_key[SW][KEY_IN_MEM * NUMBER_TESTS],
            NUMBER_TESTS),
            stdev(&times->ret_enc_key[SW][KEY_IN_MEM * NUMBER_TESTS],
            NUMBER_TESTS));
    printf("%f %f\n",
            avg(&times->enc_times[SW][KEY_IN_MEM * NUMBER_TESTS],
            NUMBER_TESTS),
            stdev(&times->enc_times[SW][KEY_IN_MEM * NUMBER_TESTS],
            NUMBER_TESTS));
    printf("NW - S\n");
    printf("%f %f\n",
            avg(&times->ret_dec_key[NW][KEY_IN_SS * NUMBER_TESTS],
            NUMBER_TESTS),
            stdev(&times->ret_dec_key[NW][KEY_IN_SS * NUMBER_TESTS],
            NUMBER_TESTS));
    printf("%f %f\n",
            avg(&times->dec_times[NW][KEY_IN_SS * NUMBER_TESTS],
            NUMBER_TESTS),
            stdev(&times->dec_times[NW][KEY_IN_SS * NUMBER_TESTS],
            NUMBER_TESTS));
    printf("%f %f\n",
            avg(&times->ret_enc_key[NW][KEY_IN_SS * NUMBER_TESTS],
            NUMBER_TESTS),
            stdev(&times->ret_enc_key[NW][KEY_IN_SS * NUMBER_TESTS],
            NUMBER_TESTS));
    printf("%f %f\n",
            avg(&times->enc_times[NW][KEY_IN_SS * NUMBER_TESTS],
            NUMBER_TESTS),
            stdev(&times->enc_times[NW][KEY_IN_SS * NUMBER_TESTS],
            NUMBER_TESTS));
    printf("SW - SS\n");
    printf("%f %f\n",
            avg(&times->ret_dec_key[SW][KEY_IN_SS * NUMBER_TESTS],
            NUMBER_TESTS),
            stdev(&times->ret_dec_key[SW][KEY_IN_SS * NUMBER_TESTS],
            NUMBER_TESTS));
    printf("%f %f\n",
            avg(&times->dec_times[SW][KEY_IN_SS * NUMBER_TESTS],
            NUMBER_TESTS),
            stdev(&times->dec_times[SW][KEY_IN_SS * NUMBER_TESTS],
            NUMBER_TESTS));
    printf("%f %f\n",
            avg(&times->ret_enc_key[SW][KEY_IN_SS * NUMBER_TESTS],
            NUMBER_TESTS),
            stdev(&times->ret_enc_key[SW][KEY_IN_SS * NUMBER_TESTS],
            NUMBER_TESTS));
    printf("%f %f\n",
            avg(&times->enc_times[SW][KEY_IN_SS * NUMBER_TESTS],
            NUMBER_TESTS),
            stdev(&times->enc_times[SW][KEY_IN_SS * NUMBER_TESTS],
            NUMBER_TESTS));
    printf("MQT-TZ: Finished printing results!\n");
}

int main(int argc, char *argv[])
{
    printf("Starting!!\n");
	struct test_ctx ctx;
    mqttz_client *origin;
    origin = malloc(sizeof *origin);
    mqttz_client *dest;
    dest = malloc(sizeof *dest);
    mqttz_times *times;
    times = malloc(sizeof *times);
    times->benchmark = 0;

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
    {
	    prepare_tee_session(&ctx);
        times->key_mode = KEY_IN_SS;
        payload_reencryption(&ctx, origin, dest, times);
	    terminate_tee_session(&ctx);
    }

    // Terminate Dummy TEE Context
	//terminate_tee_session(&ctx);
    free_client(origin);
    free_client(dest);
	return 0;
}

//./optee_hot_cache 123123123123 1111111111111111 holaholaholahoholahola 123123123123
//./optee_hot_cache 123123123123 111111111111
//./optee_save_key 123123123123 0 11111111111111111111111111111111
//./optee_read_key 123123123123
