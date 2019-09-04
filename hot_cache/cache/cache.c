#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define CACHE_SIZE      3
#define TOTAL_ELEMENTS  12
#define OBJ_ID_SIZE     12
#define OBJ_SIZE        32
#define CACHE_MODE_LRU  0
#define KEY_SIZE        16

typedef struct Node {
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

Node* init_node(char *data)
{
    Node *tmp = (Node *) malloc(sizeof(Node));
    tmp->data = (char *) malloc(sizeof(char) * (KEY_SIZE + 1));
    strncpy(tmp->data, data, KEY_SIZE);
    tmp->data[KEY_SIZE] = '\0';
    tmp->prev = tmp->next = NULL;
    return tmp;
}

int free_node(Node *node)
{
    free(node->data);
    return 0;
}

Queue* init_queue(int max_size)
{
    Queue *queue = (Queue *) malloc(sizeof(Queue));
    queue->first = NULL;
    queue->last = NULL;
    queue->size = 0;
    queue->max_size = max_size;
    return queue;
}

int free_queue(Queue *queue)
{
    free(queue->first);
    free(queue->last);
    return 0;
}

Hash* init_hash(int capacity)
{
    Hash *hash = (Hash *) malloc(sizeof(Hash));
    hash->capacity = capacity;
    hash->array = (Node **) malloc(sizeof(Node*) * hash->capacity);
    unsigned int i;
    for (i = 0; i < hash->capacity; i++)
        hash->array[i] = NULL;
    return hash;
}

int free_hash(Hash *hash)
{
    free(hash->array);
    return 0;
}

Node* queue_pop(Queue *queue)
{
    // FIFO policy for the time being
    if (queue->size == 0)
        return NULL;
    Node *old_last = queue->last;
    queue->last = old_last->prev;
    free_node(old_last); 
    free(old_last); 
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

/*
int cache_query(mqttz_cache *cache, char *oid, char *o)
{
    int i;
    for (i = 0; i < CACHE_SIZE; ++i)
    {
        if (strncmp(cache->obj_id + OBJ_ID_SIZE * i, oid, OBJ_ID_SIZE) == 0)
        {
            // Cache hit!
            printf("MQT-TZ: Cache hit!\n");
            strncpy(o, cache->obj + OBJ_SIZE * i, OBJ_SIZE);
            return 0;
        }
    }
    // Cache Miss
    printf("MQT-TZ: Cache Miss!\n");
    // Read from Secure Storage
    // Load to Cache
    return 0;
}*/

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
    printf("Current Hash Status:\n\t- Table Size: %i\n\t", hash->capacity);
    printf("\t- Cache Size: %i\n\t- Elements:\n", CACHE_SIZE);
    unsigned int i;
    for (i = 0; i < hash->capacity; i++)
        printf("\t\t%i -> %s\n", i, hash->array[i]->data);
    printf("-----------------------\n");
}

int main()
{
    Queue *q = init_queue(CACHE_SIZE);
    Hash *hash = init_hash(TOTAL_ELEMENTS);
    printf("Initialized Queue!\n");
    print_queue_status(q);
    queue_push(q, init_node("jaja"));
    print_queue_status(q);
    queue_push(q, init_node("jeje"));
    print_queue_status(q);
    queue_push(q, init_node("jiji"));
    print_queue_status(q);
    queue_push(q, init_node("jojo"));
    print_queue_status(q);
    queue_pop(q);
    print_queue_status(q);
    free_queue(q);
    free(q);
    return 0;
}

/*
int init_cache(mqttz_cache *cache, int mode)
{
    cache->obj_id = malloc(sizeof(char) * OBJ_ID_SIZE * CACHE_SIZE + 1);
    if (cache->obj_id == NULL)
        return 1;
    memset(cache->obj_id, '\0', sizeof(char) * OBJ_ID_SIZE 
            * CACHE_SIZE + 1);
    cache->obj = malloc(sizeof(char) * OBJ_SIZE * CACHE_SIZE + 1);
    if (cache->obj == NULL)
        return 1;
    memset(cache->obj, '\0', sizeof(char) * OBJ_SIZE * CACHE_SIZE + 1);
    cache->mode = mode;
    cache->queue = malloc(sizeof cache->queue);
    init_queue(cache->queue);
    return 0;
}

int free_cache(mqttz_cache *cache)
{
    free(cache->obj_id);
    free(cache->obj);
    free_queue(cache->queue);
    return 0;
}*/
