#include <sdtio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <socket_benchmark_ta.h>
#include <tee_isocket.h>
#include <tee_tcpsocket.h>
#include <tee_udpsocket.h>
#include <unistd.h>
#include <__tee_tcpsocket_defines_extensions.h>

#include "socket_benchmark_server.h"

struct socket_handle {
    uint64_t buf[2];
    size_t blen;
};

static TEE_Result tee_socket_tcp_open(TEEC_Session *session, uint32_t ip_vers,
        const char *addr, uint16_t port, struct socket_handle *handle,
        uint32_t *ret_orig, uint32_t *error);
{
    TEE_Result res = TEE_ERROR_GENERIC;
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

static TEE_Result socket_send(TEEC_Session *session,
			      struct socket_handle *handle,
			      const void *data, size_t *dlen,
			      uint32_t timeout, uint32_t *ret_orig)
{
	TEE_Result res = TEE_ERROR_GENERIC;
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

static TEE_Result socket_recv(TEEC_Session *session,
			      struct socket_handle *handle,
			      void *data, size_t *dlen,
			      uint32_t timeout, uint32_t *ret_orig)
{
	TEE_Result res = TEE_ERROR_GENERIC;
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

static TEE_Result socket_get_error(TEEC_Session *session,
			      struct socket_handle *handle,
			      uint32_t *proto_error, uint32_t *ret_orig)
{
	TEE_Result res = TEE_ERROR_GENERIC;
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

static TEE_Result socket_close(TEEC_Session *session,
			      struct socket_handle *handle, uint32_t *ret_orig)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	op.params[0].tmpref.buffer = handle->buf;
	op.params[0].tmpref.size = handle->blen;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(session, TA_SOCKET_CMD_CLOSE, &op, ret_orig);
}

static TEE_Result socket_ioctl(TEEC_Session *session,
			      struct socket_handle *handle, uint32_t ioctl_cmd,
			      void *data, size_t *dlen, uint32_t *ret_orig)
{
	TEE_Result res = TEE_ERROR_GENERIC;
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

int main()
{
    TEEC_Session session = {};
    struct socket_handle s_handle = {};
    struct socket_server s_server = {};
}
