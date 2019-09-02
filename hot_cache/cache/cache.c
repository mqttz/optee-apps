#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define CACHE_SIZE      3
#define OBJ_ID_SIZE     12
#define OBJ_SIZE        32
#define CACHE_MODE_LRU  0

typedef struct Node {
    int data;
    struct Node *next;
    struct Node *prev;
} Node;

typedef struct Queue {
    Node *first;
    Node *last;
    int size;
} Queue;

typedef struct mqttz_cache {
    char *obj_id;
    char *obj;
    int mode;
// If LRU TODO change at compile time
    Queue *queue;
} mqttz_cache;

int init_queue(Queue *queue)
{
    queue->first = NULL;
    queue->last = NULL;
    queue->size = 0;
    return 0;
}

int free_queue(Queue *queue)
{
    // TODO
    return 0;
}

Node* queue_pop(Queue *queue)
{
    // FIFO policy for the time being
    if (queue->size == 0)
        return NULL;
    Node *old_last = queue->last;
    queue->last = old_last->prev;
    //free(old_last); FIXME
    queue->size -= 1;
    return old_last;
}

int queue_push(Queue *queue, int data)
{
    // FIFO policy for the time being
    Node *tmp = (Node *) malloc(sizeof(Node)); 
    tmp->prev = NULL;
    tmp->data = data;
    if (queue->size == CACHE_SIZE)
        queue_pop(queue);
    if (queue->first != NULL)
    {
        queue->first->prev = tmp;
        tmp->next = queue->first;
    }
    else
    {
        queue->last = tmp;
    }
    queue->first = tmp;
    queue->size += 1;
    return 0;
}

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
}

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
        printf("\t\t%i -> %i\n", i, current->data);
        current = current->next;
    }
    printf("-----------------------\n");
}

int main()
{
    Queue *q = (Queue *) malloc(sizeof(Queue));
    init_queue(q);
    printf("Initialized Queue!\n");
    print_queue_status(q);
    queue_push(q, 23);
    print_queue_status(q);
    queue_push(q, 120);
    print_queue_status(q);
    queue_push(q, 929);
    print_queue_status(q);
    queue_push(q, 111);
    print_queue_status(q);
    queue_pop(q);
    print_queue_status(q);
//    mqttz_cache *cache;
//    if (init_cache(cache) != 0)
//        printf("MQT-TZ ERROR: Could not initialize cache queue!");
//    return 0;
}
