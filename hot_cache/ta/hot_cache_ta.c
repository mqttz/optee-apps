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

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <hot_cache_ta.h>

#define AES128_KEY_BIT_SIZE		128
#define AES128_KEY_BYTE_SIZE		(AES128_KEY_BIT_SIZE / 8)
#define AES256_KEY_BIT_SIZE		256
#define AES256_KEY_BYTE_SIZE		(AES256_KEY_BIT_SIZE / 8)

typedef struct aes_cipher {
    uint32_t algo;
    uint32_t mode;
    uint32_t key_size;
    TEE_OperationHandle op_handle;
    TEE_ObjectHandle key_handle;
} aes_cipher;

static TEE_Result alloc_resources(void *sess, uint32_t mode, char *key,
        char *iv)
{
    aes_cipher *session;
    TEE_Attribute attr;
    TEE_Result res;
    session = (aes_cipher *)sess;
    session->algo = TEE_ALG_AES_CBC_NOPAD;
    session->key_size = TA_AES_KEY_SIZE;
    switch (mode) {
        case TA_AES_MODE_ENCODE:
            session->mode = TEE_MODE_ENCRYPT;
            break;
        case TA_AES_MODE_DECODE:
            session->mode = TEE_MODE_DECRYPT;
            break;
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }
    // Free previous operation handle
    if (session->op_handle != TEE_HANDLE_NULL)
        TEE_FreeOperation(session->op_handle);
    // Allocate operation
    res = TEE_AllocateOperation(&session->op_handle, session->algo,
            session->mode, session->key_size * 8);
    if (res != TEE_SUCCESS)
    {
        session->op_handle = TEE_HANDLE_NULL;
        goto err;
    }
    // Free Previous Key Handle
    if (session->key_handle != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(session->key_handle);
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, session->key * 8,
            &session->key_handle);
    if (res != TEE_SUCCESS)
    {
        session->key_handle = TEE_HANDLE_NULL;
        goto err;
    }
    // Load Key 
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, session->key_size);
    res = TEE_PopulateTransientObject(session->key_handle, &attr, 1);
    if (res != TEE_SUCCESS)
        goto err;
    res = TEE_SetOperationKey(session->op_handle, session->key_handle);
    if (res != TEE_SUCCESS)
        goto err;
    // Load IV
    TEE_CipherInit(session->op_handle, iv, TA_AES_IV_SIZE);
    return res;
err:
    if (session->op_handle != TEE_HANDLE_NULL)
        TEE_FreeOperation(session->op_handle);
    session->op_handle = TEE_HANDLE_NULL;
    if (session->key_handle != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(session->key_handle);
    session->key_handle = TEE_HANDLE_NULL;
    return res;
}

/*
 * Read Raw Object from Secure Storage within TA
 *
 * This method reads an object from Secure Storage but is always invoked
 * from within a TA. Hence why we don't check the parameter types.
 */
static TEE_Result read_raw_object(char *cli_id, size_t cli_id_size, char *data,
        size_t data_sz)
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_ObjectInfo object_info;
	TEE_Result res;
	uint32_t read_bytes;
    // Check if object is in memory
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					cli_id, cli_id_sz,
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_SHARE_READ,
					&object);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open persistent object, res=0x%08x", res);
		TEE_Free(obj_id);
		return res;
	}
	res = TEE_GetObjectInfo1(object, &object_info);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to create persistent object, res=0x%08x", res);
		goto exit;
	}
	if (object_info.dataSize > data_sz) {
		/*
		 * Provided buffer is too short.
		 * Return the expected size together with status "short buffer"
		 */
		params[1].memref.size = object_info.dataSize;
		res = TEE_ERROR_SHORT_BUFFER;
		goto exit;
	}
	res = TEE_ReadObjectData(object, data, object_info.dataSize,
				 &read_bytes);
	if (res != TEE_SUCCESS || read_bytes != object_info.dataSize) {
		EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
				res, read_bytes, object_info.dataSize);
		goto exit;
	}
	params[1].memref.size = read_bytes;
exit:
	TEE_CloseObject(object);
	return res;
}

static TEE_Result cipher_buffer(void *sess, char *enc_data,
        size_t enc_data_size, char *dec_data, size_t dec_data_size)
{
    aes_cipher *session;
    session = (aes_cipher *) sess;
    if (session->op_handle == TEE_HANDLE_NULL)
        return TEE_ERROR_BAD_STATE;
    return TEE_CipherUpdate(session->op_handle, enc_data, enc_data_size,
            dec_data, dec_data_size)
}

static int get_key(char *cli_id, char *cli_key)
{
    // TODO Implement Cache Logic
    size_t read_bytes;
    if ((read_raw_object(cli_id, strlen(cli_id), cli_key, read_bytes) 
            != TEE_SUCCESS))// || (read_bytes != TA_AES_KEY_SIZE))
    {
        return 1;
    }
    return 0;
}

static TEE_Result payload_reencryption(void *session, uint32_t param_types,
        TEE_Param params[4])
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(
            TEE_PARAM_TYPE_MEMREF_INPUT,
            TEE_PARAM_TYPE_MEMREF_INOUT,
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;
    // TODO
    // 1. Decrypt from Origin
    char *ori_cli_id;
    char *ori_cli_iv;
    char *ori_cli_data;
    size_t data_size = params[0].memref.size - TA_MQTTZ_CLI_ID_SZ 
            - TA_AES_IV_SIZE;
    ori_cli_id = TEE_Malloc(sizeof *ori_cli_id * (TA_MQTTZ_CLI_ID_SZ + 1), 0);
    ori_cli_iv = TEE_Malloc(sizeof *ori_cli_id * (TA_AES_IV_SIZE + 1), 0);
    ori_cli_data = TEE_Malloc(sizeof *ori_cli_id * (TA_AES_KEY_SIZE + 1), 0);
    if (!(ori_cli_id && ori_cli_iv && ori_cli_data))
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }
    TEE_MemMove(ori_cli_id, params[0].memref.buffer, TA_MQTTZ_CLI_ID_SZ);
    ori_cli_id[TA_MQTTZ_CLI_ID_SZ] = '\0';
    TEE_MemMove(ori_cli_iv, params[0].memref.buffer + TA_MQTTZ_CLI_ID_SZ,
            TA_AES_IV_SIZE);
    ori_cli_iv[TA_AES_IV_SIZE] = '\0';
    TEE_MemMove(ori_cli_data, params[0].memref.buffer + TA_MQTTZ_CLI_ID_SZ
            + TA_AES_IV_SIZE, data_size);
    // 2. Read key from secure storage
    char *ori_cli_key;
    ori_cli_key = TEE_Malloc(sizeof *ori_cli_key * (TA_AES_KEY_SIZE + 1), 0);
    if (get_key(ori_cli_id, ori_cli_key) != 0)
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }
    // 2. Encrypt to Destination
    if (alloc_resources(session, TA_AES_MODE_DECODE, ori_cli_key, ori_cli_iv)
            != TEE_SUCCESS)
    {
        res = TEE_GENERIC;
        goto exit;
    }
    char *dec_data;
    dec_data = TEE_Malloc(sizeof *dec_data * data_size, 0);
    if (!dec_data)
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }
    if (cipher_buffer(session, ori_cli_data, data_size,
            params[1].memref.buffer, &params[1].memref.size) != TEE_SUCCESS)
    {
        res = TEE_ERROR_GENERIC;
        goto exit;
    }
    goto exit;
exit:
    TEE_Free(ori_cli_id);
    TEE_Free(ori_cli_iv);
    TEE_Free(ori_cli_data);
    TEE_Free(ori_cli_key);
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
    aes_cipher *sess;
    sess = TEE_Malloc(sizeof *sess, 0);
    if (!sess)
        return TEE_ERROR_OUT_OF_MEMORY;
    sess->key_handle = TEE_HANDLE_NULL;
    sess->op_handle = TEE_HANDLE_NULL;
    *session = (void *)sess;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *session)
{
    aes_cipher *sess;
    sess = (aes_cipher *) session;
    if (sess->key_handle != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(sess->key_handle);
    if (sess->op_handle != TEE_HANDLE_NULL)
        TEE_FreeOperation(sess->op_handle);
    TEE_Free(sess);
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *session,
				      uint32_t command,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	switch (command) {
	case TA_SECURE_STORAGE_CMD_WRITE_RAW:
		return create_raw_object(param_types, params);
	case TA_SECURE_STORAGE_CMD_READ_RAW:
		return read_raw_object(param_types, params);
	case TA_SECURE_STORAGE_CMD_DELETE:
		return delete_object(param_types, params);
    case TA_REENCRYPT:
        return payload_reencryption(session, param_types, params);
	default:
		EMSG("Command ID 0x%x is not supported", command);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
