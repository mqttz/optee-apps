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

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include <cache_benchmarking_ta.h>

#define NUM_TESTS               100
#define TA_AES_KEY_SIZE         32
#define TA_MQTTZ_CLI_ID_SZ      12
#define TOTAL_ELEMENTS          12//128 
// To change every experiment
#define CACHE_SIZE              6 // 12 64 128

typedef struct Node {
    char *id;
    char *data;
    struct Node *next;
    struct Node *prev;
} Node;

typedef struct Queue {
    Node *first;
    Node *last;
    int size;
    int max_size;
} Queue;

typedef struct Hash {
    int capacity;
    Node **array;
} Hash;

static Node* init_node(char *id, char *data)
{
    Node *tmp = (Node *) TEE_Malloc(sizeof(Node), 0);
    tmp->id = (char *) TEE_Malloc(sizeof(char) * (TA_MQTTZ_CLI_ID_SZ + 1), 0);
    strncpy(tmp->id, id, TA_MQTTZ_CLI_ID_SZ);
    tmp->id[TA_MQTTZ_CLI_ID_SZ] = '\0';
    tmp->data = (char *) TEE_Malloc(sizeof(char) * (TA_AES_KEY_SIZE + 1), 0);
    strncpy(tmp->data, data, TA_AES_KEY_SIZE);
    tmp->data[TA_AES_KEY_SIZE] = '\0';
    tmp->prev = tmp->next = NULL;
    return tmp;
}

static TEE_Result read_raw_object(char *cli_id, size_t cli_id_size, char *data,
        size_t data_sz)
{
	TEE_ObjectHandle object;
	TEE_ObjectInfo object_info;
	TEE_Result res;
	uint32_t read_bytes;
    // Check if object is in memory
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					cli_id, cli_id_size,
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_SHARE_READ,
					&object);
	if (res != TEE_SUCCESS) {
		printf("Failed to open persistent object, res=0x%08x", res);
		return res;
	}
	res = TEE_GetObjectInfo1(object, &object_info);
	if (res != TEE_SUCCESS) {
		printf("Failed to create persistent object, res=0x%08x", res);
		goto exit;
	}
	if (object_info.dataSize > data_sz) {
		/*
		 * Provided buffer is too short.
		 * Return the expected size together with status "short buffer"
		 */
        printf("here\n");
		data_sz = object_info.dataSize;
		res = TEE_ERROR_SHORT_BUFFER;
		goto exit;
	}
	res = TEE_ReadObjectData(object, data, object_info.dataSize,
				 &read_bytes);
	if (res != TEE_SUCCESS || read_bytes != object_info.dataSize) {
		printf("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
				res, read_bytes, object_info.dataSize);
		goto exit;
	}
	data_sz = read_bytes;
exit:
	TEE_CloseObject(object);
	return res;
}

static int get_key(char *cli_id, char *cli_key)
{
    size_t read_bytes = TA_AES_KEY_SIZE + 1;
    //if ((read_raw_object(cli_id, strlen(cli_id), cli_key, read_bytes) 
    if ((read_raw_object(cli_id, strlen(cli_id), cli_key, read_bytes) 
            != TEE_SUCCESS))// || (read_bytes != TA_AES_KEY_SIZE))
    {
        printf("Key not found in storage!\n");
        return 0;
    }
    //printf("Key read from storage!\n");
    return 0;
}

static int free_node(Node *node)
{
    TEE_Free((void *) node->id);
    TEE_Free((void *) node->data);
    TEE_Free((void *) node); 
    return 0;
}

static Queue* init_queue(int max_size)
{
    Queue *queue = (Queue *) TEE_Malloc(sizeof(Queue), 0);
    queue->first = NULL;
    queue->last = NULL;
    queue->size = 0;
    queue->max_size = max_size;
    return queue;
}

static int free_queue(Queue *queue)
{
    TEE_Free((void *) queue->first);
    TEE_Free((void *) queue->last);
    TEE_Free((void *) queue);
    return 0;
}

static Hash* init_hash(int capacity)
{
    Hash *hash = (Hash *) TEE_Malloc(sizeof(Hash), 0);
    hash->capacity = capacity;
    hash->array = (Node **) TEE_Malloc(sizeof(Node*) * hash->capacity, 0);
    unsigned int i;
    for (i = 0; i < hash->capacity; i++)
        hash->array[i] = NULL;
    return hash;
}

int free_hash(Hash *hash)
{
    TEE_Free((void *) hash->array);
    TEE_Free((void *) hash);
    return 0;
}

Node* queue_pop(Queue *queue)
{
    // FIFO policy for the time being
    if (queue->size == 0)
        return NULL;
    Node *old_last = queue->last;
    queue->last = queue->last->prev;
    queue->last->next = NULL;
    queue->size -= 1;
    return old_last;
}

int queue_push(Queue *queue, Node *node)
{
    // FIFO policy for the time being
    if (queue->size == CACHE_SIZE)
        queue_pop(queue);
    if (queue->first != NULL)
    {
        queue->first->prev = node;
        node->next = queue->first;
    }
    else
    {
        queue->last = node;
    }
    queue->first = node;
    queue->size += 1;
    return 0;
}

int queue_to_front(Queue *queue, Node *node)
{
    if (queue->first == node)
        return 0;
    if (queue->last == node)
        queue->last = node->prev;
    else
        node->next->prev = node->prev;
    node->prev->next = node->next;
    node->prev = NULL;
    node->next = queue->first;
    queue->first->prev = node;
    queue->first = node;
    return 0;
}

Node* cache_query(Hash *hash, Queue *queue, char *obj_id)
{
    int page = atoi(obj_id) % hash->capacity;
    Node *reqPage = hash->array[page];
    if (reqPage == NULL)
    {
        // Cache Miss
        // Load from Secure Storage FIXME FIXME TODO
        // We do this instead for testing!
        char obj[TA_AES_KEY_SIZE + 1];
        get_key(obj_id, obj);
        reqPage = init_node(obj_id, obj);
        if (queue->size == CACHE_SIZE)
        {
            Node *tmp = queue_pop(queue);
            int tmp_index = atoi(tmp->id) % hash->capacity;
            hash->array[tmp_index] = NULL;
            free_node(tmp);
        }
        queue_push(queue, reqPage);
        hash->array[page] = reqPage;
        return reqPage;
    }
    queue_to_front(queue, reqPage);
    return reqPage;
}


void print_queue_status(Queue *queue)
{
    printf("-----------------------\n");
    printf("Current Queue Status:\n\t- Queue Size: %i\n\t- Elements:\n",
            queue->size);
    int i;
    Node *current = queue->first;
    for (i = 0; i < queue->size; i++)
    {
        printf("\t\t%i -> %s\n", i, current->data);
        current = current->next;
    }
    printf("-----------------------\n");
}

void print_cache_status(Hash *hash)
{
    printf("-----------------------\n");
    printf("Current Hash Status:\n\t- Table Size: %i\n", hash->capacity);
    printf("\t- Cache Size: %i\n\t- Elements:\n", CACHE_SIZE);
    unsigned int i;
    for (i = 0; i < hash->capacity; i++)
    {
        if (hash->array[i] != NULL)
            printf("\t\t%i -> %s\n", i, hash->array[i]->data);
        else
            printf("\t\t%i -> \n", i);
    }
    printf("-----------------------\n");
}

static int save_key(char *cli_id, char *cli_key)
{
    uint32_t obj_data_flag;
    TEE_Result res;
    TEE_ObjectHandle object;
    obj_data_flag = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE
        | TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, cli_id,
            strlen(cli_id), obj_data_flag, TEE_HANDLE_NULL, NULL, 0, &object);
    if (res != TEE_SUCCESS)
        return 1;
    res = TEE_WriteObjectData(object, cli_key, strlen(cli_key));
    if (res != TEE_SUCCESS)
    {
        TEE_CloseAndDeletePersistentObject1(object);
        return 1;
    }
    TEE_CloseObject(object);
    printf("Saved key with id: %s!\n", cli_id);
    return 0;
}

static int fill_ss_and_cache(Hash *hash, Queue *queue, int table_size,
        int cache_size)
{
    unsigned int i;
    char fake_key[TA_AES_KEY_SIZE + 1] = "11111111111111111111111111111111";
    for (i = 0; i < table_size; i++)
    {
        char fake_cli_id[TA_MQTTZ_CLI_ID_SZ + 1];
        if (i >= 1000)
            snprintf(fake_cli_id, TA_MQTTZ_CLI_ID_SZ + 1, "00000000%i", i);
        else if (i < 1000 && i >= 100)
            snprintf(fake_cli_id, TA_MQTTZ_CLI_ID_SZ + 1, "000000000%i", i);
        else if (i < 100 && i >= 10)
            snprintf(fake_cli_id, TA_MQTTZ_CLI_ID_SZ + 1, "0000000000%i", i);
        else
            snprintf(fake_cli_id, TA_MQTTZ_CLI_ID_SZ + 1, "00000000000%i", i);
        //printf("This is the fake client id: %s\n", fake_cli_id);
        save_key(fake_cli_id, fake_key);
        if (i < cache_size)
            cache_query(hash, queue, fake_cli_id);
    }
    return 0;
}

int avg(int *arr, int num_elements)
{
    unsigned int i = 0;
    int ret = 0; // double
    for (i = 0; i < num_elements; i++)
    {
        ret += *(arr + i);
    }
    return ret; 
}

static int random_query_cache(Hash *hash, Queue *queue, int table_size,
        int *times)
{
    unsigned int i;
    TEE_Time t1, t2, t_aux;
    for (i = 0; i < table_size; i++)
    {
        int rand_num = rand() % table_size;
        char rand_id[TA_MQTTZ_CLI_ID_SZ + 1];
        if (rand_num >= 1000)
            snprintf(rand_id, TA_MQTTZ_CLI_ID_SZ + 1, "00000000%i", rand_num);
        else if (rand_num < 1000 && rand_num >= 100)
            snprintf(rand_id, TA_MQTTZ_CLI_ID_SZ + 1, "000000000%i", rand_num);
        else if (rand_num < 100 && rand_num >= 10)
            snprintf(rand_id, TA_MQTTZ_CLI_ID_SZ + 1, "0000000000%i",
                    rand_num);
        else
            snprintf(rand_id, TA_MQTTZ_CLI_ID_SZ + 1, "00000000000%i",
                    rand_num);
        TEE_GetSystemTime(&t1);
        cache_query(hash, queue, rand_id);
        TEE_GetSystemTime(&t2);
        TEE_TIME_SUB(t2, t1, t_aux);
        times[i] = t_aux.seconds * 1000 + t_aux.millis;
    }
}

static TEE_Result cache_benchmarking(void *session, uint32_t param_types,
        TEE_Param params[4])
{
    TEE_Result res;
    char fke_key[TA_AES_KEY_SIZE + 1] = "11111111111111111111111111111111";
    int times[TOTAL_ELEMENTS];
    int avg_times[NUM_TESTS];
    uint32_t exp_param_types = TEE_PARAM_TYPES(
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;
    Queue *queue = init_queue(CACHE_SIZE);
    Hash *hash = init_hash(TOTAL_ELEMENTS);
    printf("Initialized Queue and Hash Table!\n");
    fill_ss_and_cache(hash, queue, TOTAL_ELEMENTS, CACHE_SIZE);
    unsigned int i;
    for (i = 0; i < NUM_TESTS; i++)
    {
        random_query_cache(hash, queue, TOTAL_ELEMENTS, times);
        avg_times[i] = avg(times, TOTAL_ELEMENTS);
        printf("Finished experiment %i!\n", i);
    }
    print_cache_status(hash);
    for (i = 0; i < NUM_TESTS; i++)
        printf("%i\n", avg_times[i]);
    //printf("Average: %f\n", avg(times, TOTAL_ELEMENTS));
    free_queue(queue);
    free_hash(hash);
    res = TEE_SUCCESS;
    return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void __unused **session)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *session)
{
	/* Nothing to do */
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *session,
				      uint32_t command,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	switch (command) {
        case TA_CACHE_BENCHMARK:
            return cache_benchmarking(session, param_types, params);
	default:
		EMSG("Command ID 0x%x is not supported", command);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
