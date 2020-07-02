#include <arpa/inet.h>
#include <fcntl.h> // for open
#include <math.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <tee_client_api.h>
#include <threaded_socket_ta.h>
#include <unistd.h> // for close

#define OP_BENCHMARK        0
#define TPUT_BENCHMARK      1
#define NUM_THREADS         4

struct ta_ctx {
    TEEC_Context ctx;
    TEEC_Session sess;
};

struct socket_handle {
    uint32_t ip_vers;
    char *addr;
    uint16_t tcp_port;
    uint16_t udp_port;
    char *buf; // This buffer is used to store the TEE Socket Handle
    size_t buffer_size;
};

struct benchmark_times {
    double *open_times;
    double *close_times;
    double *send_times;
};

struct thread_args {
    struct socket_handle *handle;
    int num_tests;
    int num_send;
    char *data;
    size_t data_sz;
    int threadID;
};

double avg(double *arr, int num_elements)
{
    double ret = 0.0;
    uint16_t i;
    for (i = 0; i < num_elements; i++)
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

int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y)
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

static TEEC_Result prepare_tee_session(struct ta_ctx *t_ctx)
{
	TEEC_UUID uuid = TA_THREADED_SOCKET_UUID;
	uint32_t origin;
	TEEC_Result res;
	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &t_ctx->ctx);
	if (res != TEEC_SUCCESS)
    {
		printf("TEEC_InitializeContext failed with code 0x%x\n", res);
        return res;
    }
	/* Open a session with the TA */
	res = TEEC_OpenSession(&t_ctx->ctx, &t_ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
    {
		printf("TEEC_Opensession failed with code 0x%x origin 0x%x\n", res, origin);
        return res;
    }
    return res;
}

static TEEC_Result terminate_tee_session(struct ta_ctx *t_ctx)
{
	TEEC_CloseSession(&t_ctx->sess);
	TEEC_FinalizeContext(&t_ctx->ctx);
    return TEEC_SUCCESS;
}

static TEEC_Result tee_socket_tcp_open(struct ta_ctx *t_ctx,
        struct socket_handle *handle)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t *ret_orig;
    uint32_t *error;
    
    op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_VALUE_INPUT,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_OUTPUT,
            TEEC_VALUE_OUTPUT);

    op.params[0].value.a = handle->ip_vers;
    op.params[0].value.b = handle->tcp_port;
    op.params[1].tmpref.buffer = (void *) handle->addr;
    op.params[1].tmpref.size = strlen(handle->addr) + 1;
    op.params[2].tmpref.buffer = handle->buf;
    op.params[2].tmpref.size = handle->buffer_size;

    res = TEEC_InvokeCommand(&t_ctx->sess, TA_SOCKET_CMD_TCP_OPEN, &op, ret_orig);

    handle->buffer_size = op.params[2].tmpref.size;
    *error = op.params[3].value.a;
    return res;
}

static TEEC_Result tee_socket_udp_open(struct ta_ctx *t_ctx,
				  struct socket_handle *handle)
{
	TEEC_Result res;
	TEEC_Operation op;
    uint32_t *ret_orig;
    uint32_t *error;

	op.params[0].value.a = handle->ip_vers;
	op.params[0].value.b = handle->udp_port;
	op.params[1].tmpref.buffer = (void *) handle->addr;
	op.params[1].tmpref.size = strlen(handle->addr) + 1;
	op.params[2].tmpref.buffer = handle->buf;
	op.params[2].tmpref.size = handle->buffer_size;

	op.paramTypes = TEEC_PARAM_TYPES(
                        TEEC_VALUE_INPUT,
					    TEEC_MEMREF_TEMP_INPUT,
					    TEEC_MEMREF_TEMP_OUTPUT,
					    TEEC_VALUE_OUTPUT);

	res = TEEC_InvokeCommand(&t_ctx->sess, TA_SOCKET_CMD_UDP_OPEN,
				 &op, ret_orig);

	handle->buffer_size = op.params[2].tmpref.size;
	*error = op.params[3].value.a;
	return res;
}

static TEEC_Result tee_socket_send(struct ta_ctx *t_ctx,
			      struct socket_handle *handle,
			      const void *data, size_t *dlen)
{
	TEEC_Result res;
	TEEC_Operation op;
    uint32_t *ret_orig;
    uint32_t timeout = 30;

	op.params[0].tmpref.buffer = handle->buf;
	op.params[0].tmpref.size = handle->buffer_size;
	op.params[1].tmpref.buffer = (void *)data;
	op.params[1].tmpref.size = *dlen;
	op.params[2].value.a = timeout;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INOUT, TEEC_NONE);

	res = TEEC_InvokeCommand(&t_ctx->sess, TA_SOCKET_CMD_SEND, &op, ret_orig);

	*dlen = op.params[2].value.b;
	return res;
}

/*
static TEEC_Result tee_socket_recv(TEEC_Session *session,
			      struct socket_handle *handle,
			      void *data, size_t *dlen,
			      uint32_t timeout, uint32_t *ret_orig)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	op.params[0].tmpref.buffer = handle->buf;
	op.params[0].tmpref.size = handle->blen;
	op.params[1].tmpref.buffer = (void *)data;
	op.params[1].tmpref.size = *dlen;
	op.params[2].value.a = timeout;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(session, TA_SOCKET_CMD_RECV, &op, ret_orig);

	*dlen = op.params[1].tmpref.size;
	return res;
}

*/

static TEEC_Result tee_socket_close(struct ta_ctx *t_ctx,
        struct socket_handle *handle)
{
	TEEC_Operation op;
    uint32_t *ret_orig;

	op.params[0].tmpref.buffer = handle->buf;
	op.params[0].tmpref.size = handle->buffer_size;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(&t_ctx->sess, TA_SOCKET_CMD_CLOSE, &op, ret_orig);
}

int ree_tcp_socket_client(struct socket_handle *s_handle, int num_send,
                          char *data, int iter)
{
    int sock = 0;
    struct sockaddr_in serv_addr;
    // Open + Connect
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) { 
        printf("Error creating Socket!\n"); 
        return 1; 
    } 
    memset(&serv_addr, '0', sizeof(serv_addr)); 
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(s_handle->tcp_port); 
    if(inet_pton(AF_INET, s_handle->addr, &serv_addr.sin_addr)<=0)  
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    } 
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
        return -1; 
    } 
    // Send
    for (unsigned int j = 0; j < num_send; ++j)
        send(sock, data, strlen(data), 0);
    // Close
    close(sock);
    return 0;
}

int ree_udp_socket_client(struct socket_handle *s_handle, int num_send, 
                          char *data, int iter)
{    
    int sockfd; 
    struct sockaddr_in servaddr; 
    // Open: Create + Connect
    bzero(&servaddr, sizeof(servaddr)); 
    servaddr.sin_addr.s_addr = inet_addr(s_handle->addr); 
    servaddr.sin_port = htons(s_handle->udp_port); 
    servaddr.sin_family = AF_INET; 
    sockfd = socket(AF_INET, SOCK_DGRAM, 0); 
    if(connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) 
    { 
        printf("\n Error connecting to UDP server. \n"); 
        return 1;
    } 
    // Send
    for (unsigned int j = 0; j < num_send; ++j)
        sendto(sockfd, data, strlen(data), 0, (struct sockaddr*) NULL,
               sizeof(servaddr)); 
    // Close
    close(sockfd); 
    return 0;
}

void *ree_tcp_benchmark(void *thread_args)
{
    struct thread_args *thread_data;
    thread_data = (struct thread_args *) thread_args;
    for (unsigned int i = 0; i < thread_data->num_tests; i++)
    {
        //printf("Starting REE TCP test #%i from thread %i!\n", i, thread_data->threadID);
        if (ree_tcp_socket_client(thread_data->handle, thread_data->num_send,
                                  thread_data->data, i) != 0)
        {
            printf("Error running REE TCP test!\n");
            return;
        }
    }
    return;
}

void *ree_udp_benchmark(void *thread_args)
{
    struct thread_args *thread_data;
    thread_data = (struct thread_args *) thread_args;
    for (unsigned int i = 0; i < thread_data->num_tests; i++)
    {
        //printf("Starting REE UDP test #%u!\n", i);
        if (ree_udp_socket_client(thread_data->handle, thread_data->num_send, 
                                  thread_data->data, i) != 0)
        {
            printf("Error running REE UDP test!\n");
            return;
        }
    }
    return;
}

void *tee_tcp_benchmark(void *thread_args)
{
    struct ta_ctx t_ctx;
    struct thread_args *thread_data;
    thread_data = (struct thread_args *) thread_args;
    for (unsigned int i = 0; i < thread_data->num_tests; i++)
    {
        //printf("Starting TEE TCP test #%u!\n", i);
        memset((void *) thread_data->handle->buf, '\0', 1024 * sizeof(char));
        thread_data->handle->buffer_size = 1024;
        if (prepare_tee_session(&t_ctx) != TEEC_SUCCESS)
        {
            printf("Error initializing TEE Session!\n");
            return;
        }
        if (tee_socket_tcp_open(&t_ctx, thread_data->handle) != TEEC_SUCCESS)
        {
            printf("Error opneing TCP Socket in the TEE!\n");
            return;
        }
        for (unsigned int j = 0; j < thread_data->num_send; j++)
        {
            if (tee_socket_send(&t_ctx, thread_data->handle,
                                thread_data->data,
                                &thread_data->data_sz) != TEEC_SUCCESS)
            {
                printf("Error sending data from the TEE!\n");
                return;
            }
        }
        if (tee_socket_close(&t_ctx, thread_data->handle) != TEEC_SUCCESS)
        {
            printf("Error closing TCP Socket in the TEE!\n");
            return;
        }
        if (terminate_tee_session(&t_ctx) != TEEC_SUCCESS)
        {
            printf("Error terminating TEE Session!\n");
            return;
        }
    }
}

void *tee_udp_benchmark(void *thread_args)
{
    struct ta_ctx t_ctx;
    struct thread_args *thread_data;
    thread_data = (struct thread_args *) thread_args;
    for (unsigned int i = 0; i < thread_data->num_tests; i++)
    {
        //printf("Starting TEE UDP test #%u!\n", i);
        memset((void *) thread_data->handle->buf, '\0', 1024 * sizeof(char));
        thread_data->handle->buffer_size = 1024;
        if (prepare_tee_session(&t_ctx) != TEEC_SUCCESS)
        {
            printf("Error initializing TEE Session!\n");
            return;
        }
        if (tee_socket_udp_open(&t_ctx, thread_data->handle) != TEEC_SUCCESS)
        {
            printf("Error opneing TCP Socket in the TEE!\n");
            return;
        }
        for (unsigned int j = 0; j < thread_data->num_send; j++)
        {
            if (tee_socket_send(&t_ctx, thread_data->handle,
                                thread_data->data,
                                &thread_data->data_sz) != TEEC_SUCCESS)
            {
                printf("Error sending data from the TEE!\n");
                return;
            }
        }
        if (tee_socket_close(&t_ctx, thread_data->handle) != TEEC_SUCCESS)
        {
            printf("Error closing TCP Socket in the TEE!\n");
            return;
        }
        if (terminate_tee_session(&t_ctx) != TEEC_SUCCESS)
        {
            printf("Error terminating TEE Session!\n");
            return;
        }
    }
    return;
}

int main()
{
    // Data & Param Initialization
    char *buf;
    buf = (char *) calloc(1024, sizeof(char));
    struct socket_handle s_handle = {
        .ip_vers = 0,
        .addr = "10.0.2.2",
        .tcp_port = 9999,
        .udp_port = 9998,
        .buf = buf,
        .buffer_size = 1024
    };
    char *data = (char *) calloc(1 * 1024 + 1, sizeof(char));
    memset((void *) data, 'A', 1 * 1024 * sizeof(char));
    data[1 * 1024] = "\0";
    size_t data_sz = strlen(data);
    struct timeval t_ini, t_end, t_diff;
    int num_tests = 10;
    int num_mult[4] = {1, 10, 100, 1000};
    int rc;
    for (unsigned int l = 0; l < 4; ++l)
    {
        int num_send[4] = {12 * num_mult[l], 6 * num_mult[l], 
                           4 * num_mult[l], 3 * num_mult[l]};
        //int num_threads[4] = {1,2,3,4};
        int num_threads[4] = {1,2,1,2};
        double ree_tcp_times[4], ree_udp_times[4], tee_tcp_times[4], tee_udp_times[4];
        for (unsigned int j = 0; j < 4; ++j)
        {
            //printf("Starting experiment w/ %i threads and %i sends!\n",
                    //num_threads[j], num_send[j]);
            struct thread_args thread_args_array[num_threads[j]];
            for (unsigned int i = 0; i < num_threads[j]; i++)
            {
                thread_args_array[i] = (struct thread_args) {
                    .handle = &s_handle,
                    .num_tests = num_tests,
                    .num_send = num_send[j],
                    .data = data,
                    .data_sz = data_sz,
                    .threadID = i
                };
            }
            pthread_t threads[num_threads[j]];
            unsigned int t;
            // REE TCP
            //printf("Running REE TCP Tests...\n");
            gettimeofday(&t_ini, NULL);
            for (t = 0; t < num_threads[j]; t++)
            {
                rc = pthread_create(&threads[t], NULL, ree_tcp_benchmark, 
                                    (void *) &thread_args_array[t]);
                if (rc)
                {
                    printf("Error creating thread %i!\n", t);
                    return 1;
                }
                //printf("Succesfully created thread %i!\n", t);
            }
            for (t = 0; t < num_threads[j]; t++)
            {
                pthread_join(threads[t], NULL);
            }
            gettimeofday(&t_end, NULL);
            if (timeval_subtract(&t_diff, &t_end, &t_ini))
            {
                printf("ERROR: Negative difference?!\n");
                return 1;
            }
            ree_tcp_times[j] = t_diff.tv_sec * 1000 + t_diff.tv_usec / 1000.0;
            // REE UDP
            //printf("Running REE UDP Tests...\n");
            gettimeofday(&t_ini, NULL);
            for (t = 0; t < num_threads[j]; t++)
            {
                rc = pthread_create(&threads[t], NULL, ree_udp_benchmark, 
                                    (void *) &thread_args_array[t]);
                if (rc)
                {
                    printf("Error creating thread %i!\n", t);
                    return 1;
                }
                //printf("Succesfully created thread %i!\n", t);
            }
            for (t = 0; t < num_threads[j]; t++)
            {
                pthread_join(threads[t], NULL);
            }
            gettimeofday(&t_end, NULL);
            if (timeval_subtract(&t_diff, &t_end, &t_ini))
            {
                printf("ERROR: Negative difference?!\n");
                return 1;
            }
            ree_udp_times[j] = t_diff.tv_sec * 1000 + t_diff.tv_usec / 1000.0;
            // TEE TCP
            if (j < 2)
            {
                //printf("Running TEE TCP Tests...\n");
                gettimeofday(&t_ini, NULL);
                for (t = 0; t < num_threads[j]; t++)
                {
                    rc = pthread_create(&threads[t], NULL, tee_tcp_benchmark, 
                                        (void *) &thread_args_array[t]);
                    if (rc)
                    {
                        printf("Error creating thread %i!\n", t);
                        return 1;
                    }
                    //printf("Succesfully created thread %i!\n", t);
                }
                for (t = 0; t < num_threads[j]; t++)
                {
                    pthread_join(threads[t], NULL);
                }
                gettimeofday(&t_end, NULL);
                if (timeval_subtract(&t_diff, &t_end, &t_ini))
                {
                    printf("ERROR: Negative difference?!\n");
                    return 1;
                }
                tee_tcp_times[j] = t_diff.tv_sec * 1000 + t_diff.tv_usec / 1000.0;
                // TEE UDP
                //printf("Running TEE UDP Tests...\n");
                gettimeofday(&t_ini, NULL);
                for (t = 0; t < num_threads[j]; t++)
                {
                    rc = pthread_create(&threads[t], NULL, tee_udp_benchmark, 
                                        (void *) &thread_args_array[t]);
                    if (rc)
                    {
                        printf("Error creating thread %i!\n", t);
                        return 1;
                    }
                    //printf("Succesfully created thread %i!\n", t);
                }
                for (t = 0; t < num_threads[j]; t++)
                {
                    pthread_join(threads[t], NULL);
                }
                gettimeofday(&t_end, NULL);
                if (timeval_subtract(&t_diff, &t_end, &t_ini))
                {
                    printf("ERROR: Negative difference?!\n");
                    return 1;
                }
                tee_udp_times[j] = t_diff.tv_sec * 1000 + t_diff.tv_usec / 1000.0;
            }
            //printf("Experiment done!\n");
        }
        printf("--------------- NUM MULT %i ---------------\n", num_mult[l]);
        printf("------- REE Average (TCP/UDP) Times -------\n");
        printf("%f,%f,%f,%f\n",
                ree_tcp_times[0] / num_tests,
                ree_tcp_times[1] / num_tests,
                ree_tcp_times[2] / num_tests,
                ree_tcp_times[3] / num_tests);
        printf("%f,%f,%f,%f\n",
                ree_udp_times[0] / num_tests,
                ree_udp_times[1] / num_tests,
                ree_udp_times[2] / num_tests,
                ree_udp_times[3] / num_tests);
        printf("------- TEE Average (TCP/UDP) Times -------\n");
        printf("%f,%f,%f,%f\n",
                tee_tcp_times[0] / num_tests,
                tee_tcp_times[1] / num_tests,
                tee_tcp_times[2] / num_tests,
                tee_tcp_times[3] / num_tests);
        printf("%f,%f,%f,%f\n",
                tee_udp_times[0] / num_tests,
                tee_udp_times[1] / num_tests,
                tee_udp_times[2] / num_tests,
                tee_udp_times[3] / num_tests);
    }
    return 0;
}
