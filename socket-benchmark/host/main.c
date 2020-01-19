#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <tee_client_api.h>
#include <socket_benchmark_ta.h>

struct ta_ctx {
    TEEC_Context ctx;
    TEEC_Session sess;
};

struct socket_handle {
    char *remote_ip;
    int port;
    size_t buffer_size;
};

static TEEC_Result prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_SOCKET_BENCHMARK_UUID;
	uint32_t origin;
	TEEC_Result res;
	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
    {
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
        return res;
    }
	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
    {
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
        return res;
    }
    return res;
}

static TEEC_Result terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
    return TEEC_SUCCESS;
}

static TEEC_Result tee_socket_tcp_open(TEEC_Session *session, uint32_t ip_vers,
        const char *addr, uint16_t port, struct socket_handle *handle,
        uint32_t *ret_orig, uint32_t *error);
{
    TEEC_Result res = TEEC_ERROR_GENERIC;
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    
    memset(handle, 0, sizeof *handle);
    op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_VALUE_INPUT,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_OUTPUT,
            TEEC_VALUE_OUTPUT);

    op.params[0].value.a = ip_vers;
    op.params[0].value.b = port;
    op.params[1].tmpref.buffer = (void *) addr;
    op.params[1].tmpref.size = strlen(addr) + 1;
    op.params[2].tmpref.buffer = handle->buf;
    op.params[2].tmpref.size = sizeof handle->size;

    res = TEEC_InvokeCommand(session, TA_SOCKET_CMD_TCP_OPEN, &op, ret_orig);

    handle->blen = op.params[2].tmpref.size;
    *error = op.params[3].value.a;
    return res;
}

static TEEC_Result tee_socket_send(TEEC_Session *session,
			      struct socket_handle *handle,
			      const void *data, size_t *dlen,
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
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INOUT, TEEC_NONE);

	res = TEEC_InvokeCommand(session, TA_SOCKET_CMD_SEND, &op, ret_orig);

	*dlen = op.params[2].value.b;
	return res;
}

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

static TEEC_Result tee_socket_get_error(TEEC_Session *session,
			      struct socket_handle *handle,
			      uint32_t *proto_error, uint32_t *ret_orig)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	op.params[0].tmpref.buffer = handle->buf;
	op.params[0].tmpref.size = handle->blen;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(session, TA_SOCKET_CMD_ERROR, &op, ret_orig);

	*proto_error = op.params[1].value.a;
	return res;
}

static TEEC_Result socket_close(TEEC_Session *session,
			      struct socket_handle *handle, uint32_t *ret_orig)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	op.params[0].tmpref.buffer = handle->buf;
	op.params[0].tmpref.size = handle->blen;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(session, TA_SOCKET_CMD_CLOSE, &op, ret_orig);
}

static TEEC_Result socket_ioctl(TEEC_Session *session,
			      struct socket_handle *handle, uint32_t ioctl_cmd,
			      void *data, size_t *dlen, uint32_t *ret_orig)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	op.params[0].tmpref.buffer = handle->buf;
	op.params[0].tmpref.size = handle->blen;
	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = *dlen;
	op.params[2].value.a = ioctl_cmd;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INOUT,
					 TEEC_VALUE_INPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(session, TA_SOCKET_CMD_IOCTL, &op, ret_orig);

	*dlen = op.params[1].tmpref.size;
	return res;
}

int ree_tcp_socket_client(struct socket_handle *s_handle, char *buffer)
{
    int sock = 0;
    struct sockaddr_in address;
    struct sockaddr_in serv_addr;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) { 
        printf("Error creating Socket!\n"); 
        return 1; 
    } 
    memset(&serv_addr, '0', sizeof(serv_addr)); 
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(s_handle->port); 
    // Convert IPv4 and IPv6 addresses from text to binary form 
    if(inet_pton(AF_INET, s_handle->remote_ip, &serv_addr.sin_addr)<=0)  
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    } 
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
        return -1; 
    } 
    //ree_tcp_client(sock, buffer);
    strcpy(buffer, "Hello world from Qemu!\n");
    send(sock, hello, strlen(buffer), 0);
    close(sock);
    return 0;
}

int main()
{
    TEEC_Result res;
    struct ta_ctx ctx;
    const size_t buf_size = 16 * 1024;
    char *buf;

    if (prepare_tee_session(&ctx) != TEEC_SUCCESS)
    {
        printf("Error initializing TEE Session!\n");
        return 1;
    }

    struct socket_handle s_handle = {
        .remote_ip = "10.0.2.2",
        .port = 9998,
        .buffer_size = 1024
    };
    buf = (char *) caloc(0, s_handle.buffer_size);
    ree_tcp_socket_client(&s_handle, buf);

    if (terminate_tee_session(&ctx) != TEEC_SUCCESS)
    {
        printf("Error terminating TEE Session!\n");
        return 1;
    }

    return 0;
}
