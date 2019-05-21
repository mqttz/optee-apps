#include <arpa/inet.h>
#include <err.h>
#include <math.h>
#include <netinet/in.h> 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h> 
#include <sys/time.h>
#include <regex.h>
#include <unistd.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* TA API: UUID and command IDs */
#include <hot_cache_ta.h>

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

#define MAX         80
#define PORT        9999
#define REMOTE_IP   "10.0.2.2"

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_HOT_CACHE_UUID;
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


void func(int sockfd, struct test_ctx &ctx)
{
    char buff[MAX];
	char out_buff[MAX];
	char cli_id[10]; // TODO: define ID format?
	char cmd[4]; 
    int n;
	TEEC_Result res;
	regex_t regex;
	regmatch_t rm[3];
	int reti;
	reti = regcomp(&regex, "^(get|set)_key\\((.*?)\\)", REG_EXTENDED);
	if (reti) {
		printf("Could not compile regex!\n");
		exit(1);
	}

    // Infinite Server Loop
    for (;;) {
        memset(buff, '\0', MAX);
        memset(out_buff, '\0', MAX);
		memset(cli_id, '\0', sizeof(cli_id));
		memset(cmd, '\0', sizeof(cmd));
        n = 0;

        // Process client's message
        read(sockfd, buff, sizeof(buff));
		// Debug:
        printf("From client: %s", buff);
		// Parse client's command
		reti = regexec(&regex, buff, 3, rm, 0);
		if (!reti) {
			strncpy(cmd, &buff[rm[1].rm_so], (int) rm[1].rm_eo - rm[1].rm_so);
			strncpy(cli_id, &buff[rm[2].rm_so], (int) rm[2].rm_eo - rm[2].rm_so);
			if (strcmp(cmd, "get") == 0) {
				strcpy(out_buff, "Get command parsed!\n");
                // Check if id format is sane
                // Check if cli_id is in Rich OS map
                read_secure_object(&ctx, cli_id, out_buff, sizeof(out_buff));
			} else if (strcmp(cmd, "set") == 0) {
				strcpy(out_buff, "Set command parsed!\n");
                char *found = strchr(cli_id, ',');
                if (found) {
                    char *cl_id = strtok(cli_id, ",");
                    char *cl_key = strtok(NULL, ",");
                    // Check if cli_id in Rich OS map
                    write_secure_object(&ctx, cli_id, cl_key, sizeof(cl_key));
                } else {
                    printf("Have not provided enough arguments for set!\n");
                }
			} else {
				strcpy(out_buff, "Wrong command introduced!\n");
			}
		} else {
			strcpy(out_buff, "Wrong command introduced!\n");
		}

        // Send response to client
        write (sockfd, out_buff, sizeof(out_buff));
    }
}

int main(int argc, char *argv[])
{
	struct test_ctx ctx;
    struct timeval t1, t2;

    // Dummy TEE Context to check if all files are OK
	prepare_tee_session(&ctx);

    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    char *hello =  "Hello from server";

    // Creating Socket File Descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket Failed");
        exit(EXIT_FAILURE);
    }

    // Attaching to port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                                                            sizeof(opt))) {
        perror("Set Socket Options Failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( PORT );

    if (bind(server_fd, (struct sockaddr *) &address, sizeof(address)) < 0) {
        perror("Bind Failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("Listen Failed");
        exit(EXIT_FAILURE);
    }
    if ((new_socket = accept(server_fd, (struct sockaddr *) &address,
                    (socklen_t *) &addrlen)) < 0) {
        perror("Accept Failed");
        exit(EXIT_FAILURE);
    }
    
    // Chatting between server and client
    func(new_socket, &ctx);

    // Close the socket when finished
    close(server_fd);

    // Terminate Dummy TEE Context
	terminate_tee_session(&ctx);
	return 0;
}
