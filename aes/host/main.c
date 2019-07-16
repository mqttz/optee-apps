#include <err.h>
#include <math.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <aes_ta.h>

#define DECODE			0
#define ENCODE			1

#define CLEAR_TEXT_PATH         "clear.txt"
#define NUM_TESTS               100

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

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

char* load_file(char *file_name, size_t *newLen)
{
    FILE *fp;
    char *dest = NULL;
    fp = fopen(file_name, "r");
    if (fp != NULL) {
        if (fseek(fp, 0L, SEEK_END) == 0) {
            long bufsize = ftell(fp);
            if (bufsize == -1) {
                fputs("Error reading file!", stderr);
                return '\0';
            }
            dest = malloc(sizeof(char) * (bufsize + 1));
            if (fseek(fp, 0L, SEEK_SET) != 0) {
                fputs("Error reading file!", stderr);
                return '\0';
            }
            *newLen = fread(dest, sizeof(char), bufsize, fp);
            if (ferror(fp) != 0) {
                fputs("Error reading file!", stderr);
                return '\0';
            } else {
                dest[*newLen++] = '\0';
            }
        }
        fclose(fp);
        return dest;
    }
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

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
    switch (key_size) {
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
    if (1 != EVP_EncryptUpdate(ctx, cipher_text, &len, plain_text, plain_text_len))
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
    switch (key_size) {
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
    if(1 != EVP_DecryptUpdate(ctx, decrypted_text, &len, cipher_text, cipher_text_len)) 
        handleErrors();
    decrypted_text_len = len;

    // Finalise decryption
    if(1 != EVP_DecryptFinal_ex(ctx, decrypted_text + len, &len))
        handleErrors();
    decrypted_text_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return decrypted_text_len;
}

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_AES_UUID;
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

double prepare_aes(struct test_ctx *ctx, int encode, int key_size)
{
    struct timeval t1, t2;
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_NONE);

	op.params[0].value.a = TA_AES_ALGO_CTR;
	//op.params[1].value.a = TA_AES_SIZE_128BIT;
	op.params[1].value.a = key_size;
	op.params[2].value.a = encode ? TA_AES_MODE_ENCODE :
					TA_AES_MODE_DECODE;

    gettimeofday(&t1, NULL);
	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_PREPARE,
				 &op, &origin);
    gettimeofday(&t2, NULL);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(PREPARE) failed 0x%x origin 0x%x",
			res, origin);
    return (t2.tv_sec - t1.tv_sec) * 1000.0 + (t2.tv_usec - t1.tv_usec)/1000.0;
}

double set_key(struct test_ctx *ctx, char *key, size_t key_sz)
{
    struct timeval t1, t2;
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = key;
	op.params[0].tmpref.size = key_sz;

    gettimeofday(&t1, NULL);
	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_KEY,
				 &op, &origin);
    gettimeofday(&t2, NULL);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x",
			res, origin);
    return (t2.tv_sec - t1.tv_sec) * 1000.0 + (t2.tv_usec - t1.tv_usec)/1000.0;
}

double set_iv(struct test_ctx *ctx, char *iv, size_t iv_sz)
{
    struct timeval t1, t2;
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					  TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = iv;
	op.params[0].tmpref.size = iv_sz;

    gettimeofday(&t1, NULL);
	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_IV,
				 &op, &origin);
    gettimeofday(&t2, NULL);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_IV) failed 0x%x origin 0x%x",
			res, origin);
    return (t2.tv_sec - t1.tv_sec) * 1000.0 + (t2.tv_usec - t1.tv_usec)/1000.0;
}

double cipher_buffer(struct test_ctx *ctx, char *in, char *out, size_t sz)
{
    struct timeval t1, t2;
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = in;
	op.params[0].tmpref.size = sz;
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = sz;

    gettimeofday(&t1, NULL);
	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_CIPHER,
				 &op, &origin);
    gettimeofday(&t2, NULL);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x",
			res, origin);
    return (t2.tv_sec - t1.tv_sec) * 1000.0 + (t2.tv_usec - t1.tv_usec)/1000.0;
}

int main(void)
{
    // Initialise variables
    struct timeval t1, t2, t3, t4, t5;
	struct test_ctx ctx;
    int key_sizes[] = {16, 32}; // Different AES key Sizes (in Bytes)
    //int key_sizes[] = {16}; // Different AES key Sizes (in Bytes)
    double enc_times_ns[2 * NUM_TESTS]; // Array to store encryption times
    double dec_times_ns[2 * NUM_TESTS]; // Array to store decryption times
    double enc_times_s[2 * NUM_TESTS]; // Array to store sec encryption times
    double dec_times_s[2 * NUM_TESTS]; // Array to store sec decryption times
    double prepare_times[4][2 * NUM_TESTS]; // Prepare times (full and InvkCMD)
    double set_iv_times[4][2 * NUM_TESTS]; // Set IV times (full and InvkCMD)
    double set_key_times[4][2 * NUM_TESTS]; // Set key times (full and invk)
    double cipher_times[4][2 * NUM_TESTS]; // Cipher buffer times (full n inv)
    size_t clear_text_len; // Clear text size, to estimate cipher text size

    // Load text in clear TODO: include files with build
    //char *clear_text = load_file(CLEAR_TEXT_PATH, &clear_text_len);
    char clear_text[] = "Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor. Aenean massa. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Donec quam felis, ultricies nec, pellentesque eu, pretium quis, sem. Nulla consequat massa quis enim. Donec pede justo, fringilla vel, aliquet nec, vulputate eget, arcu. In enim justo, rhoncus ut, imperdiet a, venenatis vitae, justo. Nullam dictum felis eu pede mollis pretium. Integer tincidunt. Cras dapibus. Vivamus elementum semper nisi. Aenean vulputate eleifend tellus. Aenean leo ligula, porttitor eu, consequat vitae, eleifend ac, enim. Aliquam lorem ante, dapibus in, viverra quis, feugiat a, tellus. Phasellus viverra nulla ut metus varius laoreet. Quisque rutrum. Aenean imperdiet. Etiam ultricies nisi vel augue. Curabitur ullamcorper ultricies nisi. Nam eget dui. Etiam rhoncus. Maecenas tempus, tellus eget condimentum rhoncus, sem quam semper libero, sit amet adipiscing sem neque sed ipsum. Nam quam nunc, blandit vel, luctus pulvinar, hendrerit id, lorem. Maecenas nec odio et ante tincidunt tempus. Donec vitae sapien ut libero venenatis faucibus. Nullam quis ante. Etiam sit amet orci eget eros faucibus tincidunt. Duis leo. Sed fringilla mauris sit amet nibh. Donec sodales sagittis magna. Sed consequat, leo eget bibendum sodales, augue velit cursus nunc, quis gravida magna mi a libero. Fusce vulputate eleifend sapien. Vestibulum purus quam, scelerisque ut, mollis sed, nonummy id, metus. Nullam accumsan lorem in dui. Cras ultricies mi eu turpis hendrerit fringilla. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; In ac dui quis mi consectetuer lacinia. Nam pretium turpis et arcu. Duis arcu tortor, suscipit eget, imperdiet nec, imperdiet iaculis, ipsum. Sed aliquam ultrices mauris. Integer ante arcu, accumsan a, consectetuer eget, posuere ut, mauris. Praesent adipiscing. Phasellus ullamcorper ipsum rutrum nunc. Nunc nonummy metus. Vestibulum volutpat pretium libero. Cras id dui. Aenean ut eros et nisl sagittis vestibulum. Nullam nulla eros, ultricies sit amet, nonummy id, imperdiet feugiat, pede. Sed lectus. Donec mollis hendrerit risus. Phasellus nec sem in justo pellentesque facilisis. Etiam imperdiet imperdiet orci. Nunc nec neque. Phasellus leo dolor, tempus non, auctor et, hendrerit quis, nisi. Curabitur ligula sapien, tincidunt non, euismod vitae, posuere imperdiet, leo. Maecenas malesuada. Praesent congue erat at massa. Sed cursus turpis vitae tortor. Donec posuere vulputate arcu. Phasellus accumsan cursus velit. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Sed aliquam, nisi quis porttitor congue, elit erat euismod orci, ac placerat dolor lectus quis orci. Phasellus consectetuer vestibulum elit. Aenean tellus metus, bibendum sed, posuere ac, mattis non, nunc. Vestibulum fringilla pede sit amet augue. In turpis. Pellentesque posuere. Praesent turpis. Aenean posuere, tortor sed cursus feugiat, nunc augue blandit nunc, eu sollicitudin urna dolor sagittis lacus. Donec elit libero, sodales nec, volutpat a, suscipit non, turpis. Nullam sagittis. Suspendisse pulvinar, augue ac venenatis condimentum, sem libero volutpat nibh, nec pellentesque velit pede quis nunc. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Fusce id purus. Ut varius tincidunt libero. Phasellus dolor. Maecenas vestibulum mollis diam. Pellentesque ut neque. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. In dui magna, posuere eget, vestibulum et, tempor auctor, justo. In ac felis quis tortor malesuada pretium. Pellentesque auctor neque nec urna. Proin sapien ipsum, porta a, auctor quis, euismod ut, mi. Aenean viverra rhoncus pede. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Ut non enim eleifend felis pretium feugiat. Vivamus quis mi. Phasellus a est. Phasellus magna. In hac habitasse platea dictumst. Curabitur at lacus ac velit ornare lobortis. Cura";
 
    
    // Prepare TEE Session
	prepare_tee_session(&ctx);

    // Start tests
    for (int i = 0; i < 2; i++) {
        printf("Starting Test Suite for Key Size of: %i\n", key_sizes[i]);

        // Estimate cipher text length
        size_t cph_len = clear_text_len + (key_sizes[i] * 8 - (clear_text_len %
                    (key_sizes[i] * 8)));
        // Define variables for encrypt/decrypt
        unsigned char cipher_text[cph_len]; // Buffer for the cipher text
        unsigned char decrypted_text[cph_len]; // Buffer for the decrypted text
        int cipher_text_len, decrypted_text_len; // Placeholders for the length
        

        for (int j = 0; j < NUM_TESTS; j++) {

            // Key and Initial Vector Random Generation
            unsigned char key[key_sizes[i]], iv[key_sizes[0]];
            /*
             * TODO: generate randomness within TZ
            if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
                printf("Error generating the key!");
                return 1;
            }
            */
            memset(key, 0xa5, sizeof(key));
            memset(iv, 0xa1, sizeof(iv));
            
            // Non-Secure Encryption
            gettimeofday(&t1, NULL);
            cipher_text_len = encrypt(clear_text, clear_text_len, key, iv,
                    cipher_text, key_sizes[i]);
            gettimeofday(&t2, NULL);
            enc_times_ns[NUM_TESTS * i + j] = (t2.tv_sec - t1.tv_sec) * 1000.0;
            enc_times_ns[NUM_TESTS * i + j] += (t2.tv_usec - t1.tv_usec)/1000.0;

            // Non-Secure Decryption
            gettimeofday(&t1, NULL);
            decrypted_text_len = decrypt(cipher_text, cipher_text_len, key,
                    iv, decrypted_text, key_sizes[i]);
            decrypted_text[decrypted_text_len++] = '\0';
            gettimeofday(&t2, NULL);
            dec_times_ns[NUM_TESTS * i + j] = (t2.tv_sec - t1.tv_sec) * 1000.0;
            dec_times_ns[NUM_TESTS * i + j] += (t2.tv_usec - t1.tv_usec)/1000.0;

            // Secure Encryption
            gettimeofday(&t1, NULL);
	        prepare_times[1][NUM_TESTS * i + j] = prepare_aes(&ctx, ENCODE,
                    key_sizes[i]);
            gettimeofday(&t3, NULL);
	        set_key_times[1][NUM_TESTS * i + j] = set_key(&ctx, (char *) key,
                    (size_t) key_sizes[i]);
            gettimeofday(&t4, NULL);
	        set_iv_times[1][NUM_TESTS * i + j] = set_iv(&ctx, (char *) iv,
                    (size_t) key_sizes[0]);
            gettimeofday(&t5, NULL);
	        cipher_times[1][NUM_TESTS * i + j] = cipher_buffer(&ctx,
                    clear_text, cipher_text, cph_len);
            gettimeofday(&t2, NULL);
            // Update Times
            prepare_times[0][NUM_TESTS * i + j] = (t3.tv_sec - t1.tv_sec) 
                * 1000.0;
            prepare_times[0][NUM_TESTS * i + j] += (t3.tv_usec - t1.tv_usec)
                / 1000.0;
            set_key_times[0][NUM_TESTS * i + j] = (t4.tv_sec - t3.tv_sec) 
                * 1000.0;
            set_key_times[0][NUM_TESTS * i + j] += (t4.tv_usec - t3.tv_usec)
                / 1000.0;
            set_iv_times[0][NUM_TESTS * i + j] = (t5.tv_sec - t4.tv_sec) 
                * 1000.0;
            set_iv_times[0][NUM_TESTS * i + j] += (t5.tv_usec - t4.tv_usec)
                / 1000.0;
            cipher_times[0][NUM_TESTS * i + j] = (t2.tv_sec - t5.tv_sec) 
                * 1000.0;
            cipher_times[0][NUM_TESTS * i + j] += (t2.tv_usec - t5.tv_usec)
                / 1000.0;
            enc_times_s[NUM_TESTS * i + j] = (t2.tv_sec - t1.tv_sec) 
                * 1000.0;
            enc_times_s[NUM_TESTS * i + j] += (t2.tv_usec - t1.tv_usec)
                / 1000.0;

            // Secure Decryption
            gettimeofday(&t1, NULL);
	        prepare_times[4][NUM_TESTS * i + j] = prepare_aes(&ctx, DECODE,
                    key_sizes[i]);
            gettimeofday(&t3, NULL);
	        set_key_times[4][NUM_TESTS * i + j] = set_key(&ctx, (char *) key,
                    (size_t) key_sizes[i]);
            gettimeofday(&t4, NULL);
	        set_iv_times[4][NUM_TESTS * i + j] = set_iv(&ctx, (char *) iv,
                    (size_t) key_sizes[0]);
            gettimeofday(&t5, NULL);
	        cipher_times[4][NUM_TESTS * i + j] = cipher_buffer(&ctx,
                    cipher_text, decrypted_text, cph_len);
            gettimeofday(&t2, NULL);
            prepare_times[3][NUM_TESTS * i + j] = (t3.tv_sec - t1.tv_sec) 
                * 1000.0;
            prepare_times[3][NUM_TESTS * i + j] += (t3.tv_usec - t1.tv_usec)
                / 1000.0;
            set_key_times[3][NUM_TESTS * i + j] = (t4.tv_sec - t3.tv_sec) 
                * 1000.0;
            set_key_times[3][NUM_TESTS * i + j] += (t4.tv_usec - t3.tv_usec)
                / 1000.0;
            set_iv_times[3][NUM_TESTS * i + j] = (t5.tv_sec - t4.tv_sec) 
                * 1000.0;
            set_iv_times[3][NUM_TESTS * i + j] += (t5.tv_usec - t4.tv_usec)
                / 1000.0;
            cipher_times[3][NUM_TESTS * i + j] = (t2.tv_sec - t5.tv_sec) 
                * 1000.0;
            cipher_times[3][NUM_TESTS * i + j] += (t2.tv_usec - t5.tv_usec)
                / 1000.0;
            dec_times_s[NUM_TESTS * i + j] = (t2.tv_sec - t1.tv_sec) * 1000.0;
            dec_times_s[NUM_TESTS * i + j] += (t2.tv_usec - t1.tv_usec)/1000.0;

        }
    }

    // Print times
    printf("--------------------------------------------------------------\n");
    printf("AES 128/256 CBC ENCRYPT/DECRYPT BENCHMARK (16B vs 32B Key): %i RUNS\n"
            , NUM_TESTS);
    printf("Encrypt S: \t%f %f\t%f %f\n", avg(enc_times_s, NUM_TESTS),
            stdev(enc_times_s, NUM_TESTS), avg(&enc_times_s[100], NUM_TESTS),
            stdev(&enc_times_s[100], NUM_TESTS));
    printf("Encrypt NS: \t%f %f\t%f %f\n", avg(enc_times_ns, NUM_TESTS),
            stdev(enc_times_ns, NUM_TESTS), avg(&enc_times_ns[100], NUM_TESTS),
            stdev(&enc_times_ns[100], NUM_TESTS));
    printf("Decrypt S: \t%f %f\t%f %f\n", avg(dec_times_s, NUM_TESTS),
            stdev(dec_times_s, NUM_TESTS), avg(&dec_times_s[100], NUM_TESTS),
            stdev(&dec_times_s[100], NUM_TESTS));
    printf("Decrypt NS: \t%f %f\t%f %f\n", avg(dec_times_ns, NUM_TESTS),
            stdev(dec_times_ns, NUM_TESTS), avg(&dec_times_ns[100], NUM_TESTS),
            stdev(&dec_times_ns[100], NUM_TESTS));
    printf("--------------------------------------------------------------\n");
    printf("\t\tSECURE ENCRYPT/DECRYPT TIME BREAKDOWN\n");
    printf("\t\t\tENCRYPT (16B / 32B)\n");
    printf("prepare_aes (All) \t%f %f\t%f %f\n", avg(prepare_times, NUM_TESTS),
            stdev(prepare_times, NUM_TESTS), avg(&prepare_times[0][100],
            NUM_TESTS), stdev(&prepare_times[0][100], NUM_TESTS));
    printf("prepare_aes (Inv) \t%f %f\t%f %f\n", avg(&prepare_times[1],
            NUM_TESTS), stdev(&prepare_times[1], NUM_TESTS), 
            avg(&prepare_times[1][100], NUM_TESTS), 
            stdev(&prepare_times[1][100], NUM_TESTS));
    printf("set_iv (All) \t\t%f %f\t%f %f\n", avg(set_iv_times, NUM_TESTS),
            stdev(set_iv_times, NUM_TESTS), avg(&set_iv_times[0][100],
            NUM_TESTS), stdev(&set_iv_times[0][100], NUM_TESTS));
    printf("set_iv (Inv) \t\t%f %f\t%f %f\n", avg(&set_iv_times[1],
            NUM_TESTS), stdev(&set_iv_times[1], NUM_TESTS), 
            avg(&set_iv_times[1][100], NUM_TESTS), 
            stdev(&set_iv_times[1][100], NUM_TESTS));
    printf("set_key (All) \t\t%f %f\t%f %f\n", avg(set_key_times, NUM_TESTS),
            stdev(set_key_times, NUM_TESTS), avg(&set_key_times[0][100],
            NUM_TESTS), stdev(&set_key_times[0][100], NUM_TESTS));
    printf("set_key (Inv) \t\t%f %f\t%f %f\n", avg(&set_key_times[1],
            NUM_TESTS), stdev(&set_key_times[1], NUM_TESTS), 
            avg(&set_key_times[1][100], NUM_TESTS), 
            stdev(&set_key_times[1][100], NUM_TESTS));
    printf("cipher_buffer (All) \t%f %f\t%f %f\n", avg(cipher_times, NUM_TESTS),
            stdev(cipher_times, NUM_TESTS), avg(&cipher_times[0][100],
            NUM_TESTS), stdev(&cipher_times[0][100], NUM_TESTS));
    printf("cipher_buffer (Inv) \t%f %f\t%f %f\n", avg(&cipher_times[1],
            NUM_TESTS), stdev(&cipher_times[1], NUM_TESTS), 
            avg(&cipher_times[1][100], NUM_TESTS), 
            stdev(&cipher_times[1][100], NUM_TESTS));
    printf("\t\t\tDECRYPT (16B / 32B)\n");
    printf("prepare_aes (All) \t%f %f\t%f %f\n", avg(&prepare_times[3], NUM_TESTS),
            stdev(&prepare_times[3], NUM_TESTS), avg(&prepare_times[3][100],
            NUM_TESTS), stdev(&prepare_times[3][100], NUM_TESTS));
    printf("prepare_aes (Inv) \t%f %f\t%f %f\n", avg(&prepare_times[4],
            NUM_TESTS), stdev(&prepare_times[4], NUM_TESTS), 
            avg(&prepare_times[4][100], NUM_TESTS), 
            stdev(&prepare_times[4][100], NUM_TESTS));
    printf("set_iv (All) \t\t%f %f\t%f %f\n", avg(&set_iv_times[3], NUM_TESTS),
            stdev(&set_iv_times[3], NUM_TESTS), avg(&set_iv_times[3][100],
            NUM_TESTS), stdev(&set_iv_times[3][100], NUM_TESTS));
    printf("set_iv (Inv) \t\t%f %f\t%f %f\n", avg(&set_iv_times[4],
            NUM_TESTS), stdev(&set_iv_times[4], NUM_TESTS), 
            avg(&set_iv_times[4][100], NUM_TESTS), 
            stdev(&set_iv_times[4][100], NUM_TESTS));
    printf("set_key (All) \t\t%f %f\t%f %f\n", avg(&set_key_times[3], NUM_TESTS),
            stdev(&set_key_times[3], NUM_TESTS), avg(&set_key_times[3][100],
            NUM_TESTS), stdev(&set_key_times[3][100], NUM_TESTS));
    printf("set_key (Inv) \t\t%f %f\t%f %f\n", avg(&set_key_times[4],
            NUM_TESTS), stdev(&set_key_times[4], NUM_TESTS), 
            avg(&set_key_times[4][100], NUM_TESTS), 
            stdev(&set_key_times[4][100], NUM_TESTS));
    printf("cipher_buffer (All) \t%f %f\t%f %f\n", avg(&cipher_times[3], NUM_TESTS),
            stdev(&cipher_times[3], NUM_TESTS), avg(&cipher_times[3][100],
            NUM_TESTS), stdev(&cipher_times[3][100], NUM_TESTS));
    printf("cipher_buffer (Inv) \t%f %f\t%f %f\n", avg(&cipher_times[4],
            NUM_TESTS), stdev(&cipher_times[4], NUM_TESTS), 
            avg(&cipher_times[4][100], NUM_TESTS), 
            stdev(&cipher_times[4][100], NUM_TESTS));
    printf("--------------------------------------------------------------\n");

	terminate_tee_session(&ctx);
	return 0;
}
