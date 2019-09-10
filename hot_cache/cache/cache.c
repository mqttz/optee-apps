#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define CACHE_SIZE      2
#define TOTAL_ELEMENTS  4
#define OBJ_ID_SIZE     12
#define OBJ_SIZE        32
#define CACHE_MODE_LRU  0
#define KEY_SIZE        16

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

Node* init_node(char *id, char *data)
{
    Node *tmp = (Node *) malloc(sizeof(Node));
    tmp->id = (char *) malloc(sizeof(char) * (OBJ_ID_SIZE + 1));
    strncpy(tmp->id, id, OBJ_ID_SIZE);
    tmp->id[OBJ_ID_SIZE] = '\0';
    tmp->data = (char *) malloc(sizeof(char) * (KEY_SIZE + 1));
    strncpy(tmp->data, data, KEY_SIZE);
    tmp->data[KEY_SIZE] = '\0';
    tmp->prev = tmp->next = NULL;
    return tmp;
}

int free_node(Node *node)
{
    free(node->id);
    free(node->data);
    free(node); //TODO
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
    free(queue);
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
    free(hash);
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
        queue->last == node->prev;
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
        reqPage = init_node(obj_id, "1111111111111111");
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

int main()
{
    Queue *q = init_queue(CACHE_SIZE);
    Hash *hash = init_hash(TOTAL_ELEMENTS);
    printf("Initialized Queue!\n");
    print_cache_status(hash);
    cache_query(hash, q, "000000000000");
    print_cache_status(hash);
    cache_query(hash, q, "000000000001");
    print_cache_status(hash);
    cache_query(hash, q, "000000000002");
    print_cache_status(hash);
    cache_query(hash, q, "000000000003");
    print_cache_status(hash);
    free_queue(q);
    free_hash(hash);
    return 0;
}
