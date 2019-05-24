// Implementation of an LRU Cache. We base on the following tutorial
// https://www.geeksforgeeks.org/lru-cache-implementation/
// Number of pages -> Total page numbers that can be referred to
// Number of frames -> Cache capacity
#include <stdio.h>
#include <stdlib.h>

/**
 * Queue Node: it stores the reference to the page we store in memory.
 */
typedef struct QNode
{
    struct QNode *prev, *next;
    unsigned pageNumber;
} QNode;

/**
 * Queue: Implementation of a FIFO queue.
 *
 * - count: Number of filled frames
 * - numberOfFrames: Total number of frames
 * - front/rear: pointers to first and last element in the queue.
 */
typedef struct Queue
{
    unsigned count;
    unsigned numberOfFrames;
    QNode *front, *rear;
} Queue;

/**
 * Hash: collection of pointers to Queue nodes
 *
 * - capacity: total number of pages
 * - array: array of queue nodes
 */
typedef struct Hash
{
    int capacity;
    QNode *array;
} Hash;

/**
 * Create a new QNode object
 *
 * - pageNumber: assigned page number
 */
QNode* newQNode (unsigned pageNumber)
{
    // Allocate memory and assign page number
    QNode* tmp = (QNode *) malloc(sizeof(QNode));
    tmp->pageNumber = pageNumber;
    tmp->prev = tmp->next = NULL;
    return tmp;
}

/**
 * Create a new Queue object
 *
 * - numberOfFrames: capacity of the queue
 */
Queue* createQueue (int numberOfFrames)
{
    Queue* queue = (Queue *) malloc(sizeof(Queue));
    queue->count = 0;
    queue->numberOfFrames = numberOfFrames;
    queue->front = queue->rear = NULL;
    return queue;
}

/**
 * Create a new Hash object
 *
 * - numberOfFrames: capacity of the queue
 */
Hash* createHash (int capacity)
{
    Hash* hash = (Hash *) malloc(sizeof(Hash));
    hash->capacity = capacity;
    hash->array = (QNode **) malloc(hash->capacity * sizeof(QNode*));
    for (int i = 0; i < hash->capacity; ++i)
        hash->array[i] = NULL;
    return hash;
}

// Check if there si a slot avaialable in the queue
int areAllFramesFull (Queue* queue)
{
    return queue->count == queue->numberOfFrames;
}

// Check if queue is empty
int isQueueEmpty (Queue* queue)
{
    return queue->rear == NULL;
}

/*
 * Delete a frame from the queue: note that we delete the last element of the
 * queue given that is the least recently used.
 */
void deQueue (Queue* queue)
{
    if (isQueueEmpty(queue))
        return;

    // If it is the only node, change front
    if (queue->front == queue-> rear)
        queue->front = NULL;

    QNode* temp = queue->rear;
    queue->rear = queue->rear->prev;
    if (queue->rear)
        queue->rear->next = NULL;
    free(temp);
    queue->count--;
}

/*
 * Add a page with a given pageNumber to both queue and hash
 *
 * - queue: Queue where to add the element
 * - hash: hash where to add the element
 * - pageNumber: assigned page number to the new element
 */
void enQueue (Queue* queue, Hash* hash, unsigned pageNumber)
{
    // Chech if there is space in the cache
    if (areAllFramesFull)
    {
        hash->array[queue->rear->pageNumber] = NULL;
        deQueue(queue);
    }

    // Create a new node with the given page number
    // Add the node to the front of the queue (most recently used)
    QNode* temp = newQNode(pageNumber);
    temp->next = queue->front;
    if (isQueueEmpty(queue))
        queue->front = queue->rear = temp;
    else
    {
        queue->front->prev = temp;
        queue->front = temp;
    }
    hash->array[temp->pageNumber] = temp;
    queue->count++;
}

/*
 * Callback when a page with given `pageNumber` is referenced. Either:
 *  1. Frame is not in memory: we bring it in memory and add it to the front
 *     of the queue.
 *  2. Frame is in memory: we move the frame to the front of the queue.
 */
void referencePage (Queue* queue, Hash* hash, unsigned pageNumber)
{
    // If the page is not in memory, we bring it to memory
    QNode* reqPage = hash->array[pageNumber];
    if (reqPage == NULL) // Case 1
        enQueue(queue, hash, pageNumber);
    else if (reqPage != queue->front) // Case 2
    {
        // Unlink age from its current location
        reqPage->prev->next = reqPage->next;
        if (reqPage->next)
            reqPage->next->prev = reqPage->prev;
        else // reqPage->next == NULL => reqPage == queue->rear
        {
            queue->rear = reqPage->prev;
            // We already have reqPage->prev->next == NULL;
        }
        // Put requested page in fron
        reqPage->next = queue->front;
        queue->front->prev = reqPage;
        reqPage->prev = NULL;
        queue->front = reqPage;
    }
}







    
