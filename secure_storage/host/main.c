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
#include <math.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* TA API: UUID and command IDs */
#include <secure_storage_ta.h>

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
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

TEEC_Result delete_secure_object(struct test_ctx *ctx, char *id)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_STORAGE_CMD_DELETE,
				 &op, &origin);

	switch (res) {
	case TEEC_SUCCESS:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command DELETE failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

#define TEST_OBJECT_SIZE	7000
#define NUM_TESTS           100

double avg(double* arr, size_t total_size)
{
    double ret = 0.0;
    double num_elements = total_size / sizeof(*arr);
    for (int i = 0; i < num_elements; i++)
        ret += *(arr + i);
    return ret / num_elements; 
}

double stdev(double* arr, size_t total_size)
{
    double sq_sum = 0.0;
    double num_elements = total_size / sizeof(*arr);
    for (int i = 0; i < num_elements; i++)
        sq_sum += pow(*(arr + i), 2);
    return sqrt(sq_sum / num_elements - pow(avg(arr, total_size), 2));
}

int main(void)
{
	struct test_ctx ctx;
    struct timeval t1, t2;
	char obj1_id[] = "object#1";		
	char obj2_id[] = "object#2";		
	char obj1_data[TEST_OBJECT_SIZE];
	char read_data[TEST_OBJECT_SIZE];
    double t_create[NUM_TESTS], t_read[NUM_TESTS], t_delete[NUM_TESTS];
    double t_create_ns[NUM_TESTS], t_read_ns[NUM_TESTS];
    double t_delete_ns[NUM_TESTS];
	TEEC_Result res;

	printf("CSG-CSEM: Prepare session with the TA\n");
	prepare_tee_session(&ctx);

    // Secure Storage Benchmarking
	printf("\nCSG-CSEM: Secure Storage Benchmarking \"%s\"\n", obj1_id);

    for (u_int32_t i = 0; i < NUM_TESTS; ++i) {
        gettimeofday(&t1, NULL);
        memset(obj1_data, 0xA1, sizeof(obj1_data));
        res = write_secure_object(&ctx, obj1_id,
                      obj1_data, sizeof(obj1_data));
        gettimeofday(&t2, NULL);
        if (res != TEEC_SUCCESS)
            errx(1, "Failed to create an object in the secure storage");
        t_create[i] = (t2.tv_sec - t1.tv_sec) * 1000.0;
        t_create[i] += (t2.tv_usec - t1.tv_usec) / 1000.0;

        // Read
        gettimeofday(&t1, NULL);
        res = read_secure_object(&ctx, obj1_id,
                     read_data, sizeof(read_data));
        gettimeofday(&t2, NULL);
        t_read[i] = (t2.tv_sec - t1.tv_sec) * 1000.0;
        t_read[i] += (t2.tv_usec - t1.tv_usec) / 1000.0;
        if (res != TEEC_SUCCESS)
            errx(1, "Failed to read an object from the secure storage");
        if (memcmp(obj1_data, read_data, sizeof(obj1_data)))
            errx(1, "Unexpected content found in secure storage");

        // Delete
        gettimeofday(&t1, NULL);
        res = delete_secure_object(&ctx, obj1_id);
        gettimeofday(&t2, NULL);
        t_delete[i] = (t2.tv_sec - t1.tv_sec) * 1000.0;
        t_delete[i] += (t2.tv_usec - t1.tv_usec) / 1000.0;
        if (res != TEEC_SUCCESS)
            errx(1, "Failed to delete the object: 0x%x", res);
    }

    // Non-Secure Storage Benchmarking
	printf("\nCSG-CSEM: Non-Secure Storage Benchmarking \n");

    for (u_int32_t i = 0; i < NUM_TESTS; ++i) {
        // Create Object in Non-Secure Storage
        gettimeofday(&t1, NULL);
        char* obj_ns = malloc(TEST_OBJECT_SIZE * sizeof(*obj_ns));
        memset(obj_ns, 0xA1, sizeof(obj_ns));
        gettimeofday(&t2, NULL);
        t_create_ns[i] = (t2.tv_sec - t1.tv_sec) * 1000.0;
        t_create_ns[i] += (t2.tv_usec - t1.tv_usec) / 1000.0;

        // Read Object from Non-Secure Storage
        gettimeofday(&t1, NULL);
        char* new_obj_ns = malloc(TEST_OBJECT_SIZE * sizeof(*new_obj_ns));
        strncpy(new_obj_ns, obj_ns, sizeof(obj_ns));
        gettimeofday(&t2, NULL);
        t_read_ns[i] = (t2.tv_sec - t1.tv_sec) * 1000.0;
        t_read_ns[i] += (t2.tv_usec - t1.tv_usec) / 1000.0;


        // Delete Object from Non-Secure Storage
        gettimeofday(&t1, NULL);
        memset(obj_ns, '\0', sizeof(obj_ns));
        free(obj_ns);
        gettimeofday(&t2, NULL);
        t_delete_ns[i] = (t2.tv_sec - t1.tv_sec) * 1000.0;
        t_delete_ns[i] += (t2.tv_usec - t1.tv_usec) / 1000.0;
    }

    // Print Times
    printf("\nSTORAGE BENCHMARKING (avg (ms), stdev): SECURE / NSECURE\n");
    printf("Create: \t %f, %f \t %f, %f \n",
            avg(t_create, sizeof(t_create)),
            stdev(t_create, sizeof(t_create)),
            avg(t_create_ns, sizeof(t_create_ns)),
            stdev(t_create_ns, sizeof(t_create_ns)));
    printf("Read: \t\t %f, %f \t %f, %f \n",
            avg(t_read, sizeof(t_read)),
            stdev(t_read, sizeof(t_read)),
            avg(t_read_ns, sizeof(t_read_ns)),
            stdev(t_read_ns, sizeof(t_read_ns)));
    printf("Delete: \t %f, %f \t %f, %f \n",
            avg(t_delete, sizeof(t_delete)),
            stdev(t_delete, sizeof(t_delete)),
            avg(t_delete_ns, sizeof(t_delete_ns)),
            stdev(t_delete_ns, sizeof(t_delete_ns)));
    printf("---------------------------------------------------------\n");

	printf("\nWe're done, close and release TEE resources\n");
	terminate_tee_session(&ctx);
	return 0;
}
