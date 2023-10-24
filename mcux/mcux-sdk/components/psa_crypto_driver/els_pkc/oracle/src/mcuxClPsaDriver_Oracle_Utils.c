/*
 * Copyright 2022-2023 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <mcuxClPsaDriver_Oracle_Utils.h>
#include <mcuxClPsaDriver_Oracle_ElsUtils.h>
#include <mcuxClPsaDriver_Oracle_Macros.h>

//#if defined (PSA_CRYPTO_MBEDTLS_STANDALONE)
#include <psa/crypto.h>
//#else
//#include <mbed_psa/crypto.h>
//#endif
#include <mbedtls/platform.h>
#include "crypto_values.h"
#include "mcuxClEls_Types.h"

#include "stdlib.h"

// Tags used in PSA commands
#define PSA_CMD_TAG_MAGIC               0x40
#define PSA_CMD_TAG_KEY_ID              0x41
#define PSA_CMD_TAG_PERMITTED_ALGORITHM 0x42
#define PSA_CMD_TAG_KEY_USAGE_FLAGS     0x43
#define PSA_CMD_TAG_KEY_TYPE            0x44
#define PSA_CMD_TAG_KEY_BITS            0x45
#define PSA_CMD_TAG_KEY_LIFETIME        0x46
#define PSA_CMD_TAG_WRAPPING_KEY_ID     0x50
#define PSA_CMD_TAG_WRAPPING_ALGORITHM  0x51
#define PSA_CMD_TAG_IV                  0x52
#define PSA_CMD_TAG_SIGNATURE_KEY_ID    0x53
#define PSA_CMD_TAG_SIGNATURE_ALGORITHM 0x54
#define PSA_CMD_TAG_KEYIN_CMD           0x55
#define PSA_CMD_TAG_SIGNATURE           0x5E

// Algorithms used in EL2GO blobs
#define BLOB_SIGN_ALGORITHM_CMAC        0x01
#define BLOB_WRAP_ALGORITHM_RFC3394     0x01
#define BLOB_WRAP_ALGORITHM_AES_CBC     0x02

// PSA command context
typedef struct psa_cmd_s
{
    psa_key_attributes_t attributes;
    const uint8_t *magic;
    size_t magic_size;
    uint32_t key_id;
    uint32_t key_lifetime;
    uint32_t wrapping_key_id;
    uint32_t wrapping_algorithm;
    const uint8_t *iv;
    size_t iv_size;
    uint32_t signature_key_id;
    uint32_t signature_algorithm;
    const uint8_t *keyincmd;
    size_t keyincmd_size;
    const uint8_t *signature;
    size_t signature_size;
} psa_cmd_t;

#define ELS_AVAILABLE_SLOTS 20

// TODO: get the key size from the generated key
#define PUBLIC_KEY_SIZE 64

#define CMAC_BLOCK_SIZE 16
#define BLOCK_SIZE_MAX  1500

typedef struct css_key_slot_handler_s
{
    uint32_t busy;
    mbedtls_svc_key_id_t key_id;
    uint8_t storage;
    uint8_t *public_key;
    size_t public_key_size;
} css_key_slot_handler_t;

css_key_slot_handler_t slot_handler_array[ELS_AVAILABLE_SLOTS] = {0};

static size_t ceil_to_blocksize(size_t len, size_t blocksize)
{
    return ((len + (blocksize - 1)) / blocksize) * blocksize;
}

/** @brief Pads the data following iso7816
 *
 */
static psa_status_t pad_iso7816d4(uint8_t *data, size_t unpadded_length, size_t blocksize, size_t *padded_length)
{
    psa_status_t psa_status = PSA_SUCCESS;

    *padded_length        = ceil_to_blocksize(unpadded_length + 1 /* always inserted padding 0x80 */, blocksize);
    data[unpadded_length] = 0x80;
    memset(&data[unpadded_length + 1], 0, *padded_length - (unpadded_length + 1));
    return psa_status;
}

/** @brief Unpads the data following iso7816
 *
 */
static psa_status_t unpad_iso7816d4(uint8_t *data, size_t *data_size)
{
    psa_status_t psa_status = PSA_SUCCESS;

    int count = *data_size - 1;
    while (count > 0 && data[count] == 0)
    {
        count--;
    }

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(data[count] == 0x80, PSA_ERROR_INVALID_ARGUMENT,
                                         "iso_7816_unpad failed, pad block corrupted");

    *data_size -= *data_size - count;
exit:
    return psa_status;
}

/** @brief Gets the 32-bit value from the value buffer.
 *
 */
static uint32_t get_uint32_val(const uint8_t *input)
{
    uint32_t output = 0U;
    output          = *(input);
    output <<= 8;
    output |= *(input + 1);
    output <<= 8;
    output |= *(input + 2);
    output <<= 8;
    output |= *(input + 3);
    return output;
}

/** @brief Gets the 16-bit value from the value buffer.
 *
 */
static uint16_t get_uint16_val(const uint8_t *input)
{
    uint16_t output = 0U;
    output          = *input;
    output <<= 8;
    output |= *(input + 1);
    return output;
}

// Function taken from MbedTLS
static int get_len(const unsigned char **p, const unsigned char *end, size_t *len)
{
    if ((end - *p) < 1)
        return (PSA_ERROR_INVALID_ARGUMENT);

    if ((**p & 0x80) == 0)
        *len = *(*p)++;
    else
    {
        switch (**p & 0x7F)
        {
            case 1:
                if ((end - *p) < 2)
                    return (PSA_ERROR_INVALID_ARGUMENT);

                *len = (*p)[1];
                (*p) += 2;
                break;

            case 2:
                if ((end - *p) < 3)
                    return (PSA_ERROR_INVALID_ARGUMENT);

                *len = ((size_t)(*p)[1] << 8) | (*p)[2];
                (*p) += 3;
                break;

            case 3:
                if ((end - *p) < 4)
                    return (PSA_ERROR_INVALID_ARGUMENT);

                *len = ((size_t)(*p)[1] << 16) | ((size_t)(*p)[2] << 8) | (*p)[3];
                (*p) += 4;
                break;

            case 4:
                if ((end - *p) < 5)
                    return (PSA_ERROR_INVALID_ARGUMENT);

                *len = ((size_t)(*p)[1] << 24) | ((size_t)(*p)[2] << 16) | ((size_t)(*p)[3] << 8) | (*p)[4];
                (*p) += 5;
                break;

            default:
                return (PSA_ERROR_INVALID_ARGUMENT);
        }
    }
    if (*len > (size_t)(end - *p))
        return (PSA_ERROR_INVALID_ARGUMENT);

    return (0);
}
// Function taken from MbedTLS
static int get_tag(const unsigned char **p, const unsigned char *end, size_t *len, int tag)
{
    if ((end - *p) < 1)
        return (PSA_ERROR_INVALID_ARGUMENT);

    if (**p != tag)
        return (PSA_ERROR_INVALID_ARGUMENT);

    (*p)++;

    return (get_len(p, end, len));
}

static psa_status_t parse_psa_import_command(const uint8_t *data, size_t data_size, psa_cmd_t *psa_cmd)
{
    psa_status_t psa_status = PSA_ERROR_INVALID_ARGUMENT;

    uint8_t tag    = 0U; // the tag of the current TLV
    size_t cmd_len = 0U; // the length of the current TLV

    const uint8_t *cmd_ptr = NULL;
    const uint8_t *end     = NULL;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(data != NULL, PSA_ERROR_INVALID_ARGUMENT, "The command is null");
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(psa_cmd != NULL, PSA_ERROR_INVALID_ARGUMENT,
                                         "The key attributes context is null");

    memset(psa_cmd, 0, sizeof(psa_cmd_t));
    psa_cmd->attributes = psa_key_attributes_init();

    cmd_ptr = data;
    end     = cmd_ptr + data_size;

    while ((cmd_ptr + 1) < end)
    {
        tag        = *cmd_ptr;
        psa_status = get_tag(&cmd_ptr, end, &cmd_len, tag);
        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("get_tag failed: 0x%x", psa_status);

        switch (tag)
        {
            case PSA_CMD_TAG_MAGIC:
                psa_cmd->magic      = cmd_ptr;
                psa_cmd->magic_size = cmd_len;
                break;
            case PSA_CMD_TAG_KEY_ID:
                psa_cmd->key_id = get_uint32_val(cmd_ptr);
                break;
            case PSA_CMD_TAG_PERMITTED_ALGORITHM:
                psa_set_key_algorithm(&psa_cmd->attributes, (psa_algorithm_t)get_uint32_val(cmd_ptr));
                break;
            case PSA_CMD_TAG_KEY_USAGE_FLAGS:
                psa_set_key_usage_flags(&psa_cmd->attributes, (psa_key_usage_t)get_uint32_val(cmd_ptr));
                break;
            case PSA_CMD_TAG_KEY_TYPE:
                psa_set_key_type(&psa_cmd->attributes, (psa_key_type_t)get_uint16_val(cmd_ptr));
                break;
            case PSA_CMD_TAG_KEY_BITS:
                psa_set_key_bits(&psa_cmd->attributes, (size_t)get_uint32_val(cmd_ptr));
                break;
            case PSA_CMD_TAG_KEY_LIFETIME:
                psa_cmd->key_lifetime = get_uint32_val(cmd_ptr);
                break;
            case PSA_CMD_TAG_WRAPPING_KEY_ID:
                psa_cmd->wrapping_key_id = get_uint32_val(cmd_ptr);
                break;
            case PSA_CMD_TAG_WRAPPING_ALGORITHM:
                psa_cmd->wrapping_algorithm = get_uint32_val(cmd_ptr);
                break;
            case PSA_CMD_TAG_IV:
                psa_cmd->iv      = cmd_ptr;
                psa_cmd->iv_size = cmd_len;
                break;
            case PSA_CMD_TAG_SIGNATURE_KEY_ID:
                psa_cmd->signature_key_id = get_uint32_val(cmd_ptr);
                break;
            case PSA_CMD_TAG_SIGNATURE_ALGORITHM:
                psa_cmd->signature_algorithm = get_uint32_val(cmd_ptr);
                break;
            case PSA_CMD_TAG_KEYIN_CMD:
                psa_cmd->keyincmd      = cmd_ptr;
                psa_cmd->keyincmd_size = cmd_len;
                break;
            case PSA_CMD_TAG_SIGNATURE:
                psa_cmd->signature      = cmd_ptr;
                psa_cmd->signature_size = cmd_len;
                break;
            default:
                break;
        }
        cmd_ptr += cmd_len;
    }

exit:

    return psa_status;
}

static inline bool is_same_key_id(mbedtls_svc_key_id_t a, mbedtls_svc_key_id_t b)
{
#if !defined (MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
    return a == b;
#else
    return a.owner == b.owner && a.key_id == b.key_id;
#endif
}

static inline uint32_t get_key_size_bytes(const mcuxClEls_KeyProp_t *prop)
{
    return prop->bits.ksize == MCUXCLELS_KEYPROPERTY_KEY_SIZE_128 ? 16 : 32;
}

static bool is_ns_owned_key(mbedtls_svc_key_id_t key_id)
{
#if !defined (MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
    return 0;
#else
    PRINTF("key_id.id: 0x%x, .owner: 0x%x", key_id.MBEDTLS_PRIVATE(key_id), key_id.MBEDTLS_PRIVATE(owner));
    return key_id.MBEDTLS_PRIVATE(owner) < 0;
#endif
}

static mcuxClEls_KeyIndex_t get_usable_key_slot(mcuxClEls_KeyIndex_t target_key_slot, const mcuxClEls_KeyProp_t *prop)
{
    uint32_t required_keyslots = get_key_size_bytes(prop) / 16;
    // If a dedicated keyslot is given in the recipe, use this one.
    if (target_key_slot < MCUXCLELS_KEY_SLOTS)
    {
        if (mcuxClPsaDriver_Oracle_ElsUtils_IsFreeKeySlot(target_key_slot, required_keyslots))
        {
            return target_key_slot;
        }
        // Return an invalid keyslot.
        return MCUXCLELS_KEY_SLOTS;
    }
    // The recipe does not contain a dedicated keyslot, use the next free one.
    return mcuxClPsaDriver_Oracle_ElsUtils_GetFreeKeySlot(required_keyslots);
}

static psa_status_t free_key_in_slot_handler(uint32_t slot_id)
{
    if (slot_handler_array[slot_id].busy)
    {
#if !defined (MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
        slot_handler_array[slot_id].key_id        = 0;
#else
        slot_handler_array[slot_id].key_id.owner  = 0;
        slot_handler_array[slot_id].key_id.key_id = 0;
#endif
        mbedtls_free(slot_handler_array[slot_id].public_key);
        slot_handler_array[slot_id].storage         = STORAGE_TEMP_KEY;
        slot_handler_array[slot_id].public_key      = NULL;
        slot_handler_array[slot_id].public_key_size = 0U;
        slot_handler_array[slot_id].busy            = 0x00;
        return PSA_SUCCESS;
    }

    return PSA_ERROR_DOES_NOT_EXIST;
}

static void save_key_in_slot_handler(
    uint32_t slot_id, mbedtls_svc_key_id_t key_id, uint8_t storage, uint8_t *public_key, size_t public_key_size)
{
    free_key_in_slot_handler(slot_id);

    slot_handler_array[slot_id].key_id  = key_id;
    slot_handler_array[slot_id].storage = storage;
    if ((public_key != NULL) && (public_key_size != 0U))
    {
        slot_handler_array[slot_id].public_key      = public_key;
        slot_handler_array[slot_id].public_key_size = public_key_size;
    }
    slot_handler_array[slot_id].busy = 0xFF;
}

psa_status_t mcuxClPsaDriver_Oracle_Utils_GetSlotFromKeyId(mbedtls_svc_key_id_t key_id, uint32_t *slot_id)
{
    *slot_id = 0U;
    for (uint32_t slot_id_i = 0U; slot_id_i < ELS_AVAILABLE_SLOTS; slot_id_i++)
    {
        if ((slot_handler_array[slot_id_i].busy) && (is_same_key_id(slot_handler_array[slot_id_i].key_id, key_id)) &&
            (slot_handler_array[slot_id_i].storage == STORAGE_FINAL_KEY))
        {
            *slot_id = slot_id_i;
            return PSA_SUCCESS;
        }
    }
    return PSA_ERROR_DOES_NOT_EXIST;
}

psa_status_t mcuxClPsaDriver_Oracle_Utils_GetPublicKeyFromHandler(mbedtls_svc_key_id_t key_id,
                                                                  uint8_t **public_key,
                                                                  size_t *public_key_size)
{
    uint32_t slot_id        = 0U;
    psa_status_t psa_status = PSA_ERROR_DOES_NOT_EXIST;

    psa_status = mcuxClPsaDriver_Oracle_Utils_GetSlotFromKeyId(key_id, &slot_id);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error in getting the slot from the key ID");

    if ((slot_handler_array[slot_id].public_key != NULL) && (slot_handler_array[slot_id].public_key_size != 0))
    {
        *public_key      = slot_handler_array[slot_id].public_key;
        *public_key_size = slot_handler_array[slot_id].public_key_size;
        return PSA_SUCCESS;
    }
exit:
    return psa_status;
}

#if defined(MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV)
static psa_status_t parse_keyprov_step(mbedtls_svc_key_id_t key_id,
                                       const uint8_t *param_data,
                                       uint8_t param_data_length,
                                       key_recipe_step_t *step)
{
    psa_status_t psa_status = PSA_SUCCESS;

    step->operation               = OP_KEYPROV;
    step->keyprov.target_key_slot = UINT32_MAX;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(param_data != NULL, PSA_ERROR_INVALID_ARGUMENT, "NULL pointer");
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(param_data_length > 0, PSA_ERROR_INVALID_ARGUMENT, "Length is 0");

    const uint8_t *param_ptr = param_data;
    const uint8_t *end       = param_ptr + param_data_length;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(param_ptr < end, PSA_ERROR_INVALID_ARGUMENT, "Overflow");

    param_ptr = param_data;
    end       = param_ptr + param_data_length;

    while (param_ptr < end)
    {
        // Assume every tag is followed by one byte of length.
        PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(param_ptr, 1, end, PSA_ERROR_INVALID_ARGUMENT,
                                                         "Invalid ELS command structure");
        switch (*param_ptr)
        {
            case TAG_PARAM_TARGET_KEY_ID:
                PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*(param_ptr + 1) == 4, PSA_ERROR_INVALID_ARGUMENT,
                                                     "Invalid ELS command structure");
                PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(param_ptr, 2 + 4, end, PSA_ERROR_INVALID_ARGUMENT,
                                                                 "Invalid ELS command structure");
                step->keyprov.target_key_slot = get_uint32_val(param_ptr + 2);
                break;
            case TAG_PARAM_TARGET_KEY_PROP:
                PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*(param_ptr + 1) == 4, PSA_ERROR_INVALID_ARGUMENT,
                                                     "Invalid ELS command structure");
                PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(param_ptr, 2 + 4, end, PSA_ERROR_INVALID_ARGUMENT,
                                                                 "Invalid ELS command structure");
                step->keyprov.key_properties.word.value = get_uint32_val(param_ptr + 2);
                break;
            case TAG_PARAM_KEY_PART1:
                // This keyshare has a fixed length.
                PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*(param_ptr + 1) == sizeof(step->keyprov.key_part_1),
                                                     PSA_ERROR_INVALID_ARGUMENT, "Invalid ELS command structure");
                PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(param_ptr, 2 + sizeof(step->keyprov.key_part_1), end,
                                                                 PSA_ERROR_INVALID_ARGUMENT,
                                                                 "Invalid ELS command structure");
                memcpy(step->keyprov.key_part_1, param_ptr + 2, sizeof(step->keyprov.key_part_1));
                break;
            case TAG_PARAM_KEY_PART2:
                // This keyshare has a maximum length.
                step->keyprov.key_part_2_len = *(param_ptr + 1);
                PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(step->keyprov.key_part_2_len <= sizeof(step->keyprov.key_part_2),
                                                     PSA_ERROR_INVALID_ARGUMENT, "Invalid ELS command structure");

                PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(param_ptr, 2 + step->keyprov.key_part_2_len, end,
                                                                 PSA_ERROR_INVALID_ARGUMENT,
                                                                 "Invalid ELS command structure");
                memcpy(step->keyprov.key_part_2, param_ptr + 2, step->keyprov.key_part_2_len);
                break;
            case TAG_PARAM_OPTION:
                PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*(param_ptr + 1) == 4, PSA_ERROR_INVALID_ARGUMENT,
                                                     "Invalid ELS command structure");
                PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(param_ptr, 2 + 4, end, PSA_ERROR_INVALID_ARGUMENT,
                                                                 "Invalid ELS command structure");
                step->keyprov.options.word.value = get_uint32_val(param_ptr + 2);
                break;
            default:
                return PSA_ERROR_INVALID_ARGUMENT;
        }

        param_ptr += 2 + *(param_ptr + 1);
    }

    if (is_ns_owned_key(key_id) && (step->keyprov.key_properties.bits.upprot_sec == MCUXCLELS_KEYPROPERTY_SECURE_TRUE))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
exit:
    return psa_status;
}
#endif /* MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV */

static psa_status_t parse_ckdf_step(mbedtls_svc_key_id_t key_id,
                                    const uint8_t *param_data,
                                    uint8_t param_data_length,
                                    key_recipe_step_t *step)
{
    psa_status_t psa_status = PSA_SUCCESS;

    step->operation            = OP_CKDF;
    step->ckdf.target_key_slot = UINT32_MAX;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(param_data != NULL, PSA_ERROR_INVALID_ARGUMENT, "NULL pointer");
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(param_data_length > 0, PSA_ERROR_INVALID_ARGUMENT, "Length is 0");

    const uint8_t *param_ptr = param_data;
    const uint8_t *end       = param_ptr + param_data_length;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(param_ptr < end, PSA_ERROR_INVALID_ARGUMENT, "Overflow");

    while (param_ptr < end)
    {
        // Assume every tag is followed by one byte of length.
        PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(param_ptr, 1, end, PSA_ERROR_INVALID_ARGUMENT,
                                                         "Invalid ELS command structure");
        switch (*param_ptr)
        {
            case TAG_PARAM_DERIVATION_KEY_ID:
                PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*(param_ptr + 1) == 4, PSA_ERROR_INVALID_ARGUMENT,
                                                     "Invalid ELS command structure");
                PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(param_ptr, 2 + 4, end, PSA_ERROR_INVALID_ARGUMENT,
                                                                 "Invalid ELS command structure");
                step->ckdf.source_key_slot = get_uint32_val(param_ptr + 2);
                break;
            case TAG_PARAM_TARGET_KEY_ID:
                PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*(param_ptr + 1) == 4, PSA_ERROR_INVALID_ARGUMENT,
                                                     "Invalid ELS command structure");
                PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(param_ptr, 2 + 4, end, PSA_ERROR_INVALID_ARGUMENT,
                                                                 "Invalid ELS command structure");
                step->ckdf.target_key_slot = get_uint32_val(param_ptr + 2);
                break;
            case TAG_PARAM_TARGET_KEY_PROP:
                PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*(param_ptr + 1) == 4, PSA_ERROR_INVALID_ARGUMENT,
                                                     "Invalid ELS command structure");
                PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(param_ptr, 2 + 4, end, PSA_ERROR_INVALID_ARGUMENT,
                                                                 "Invalid ELS command structure");
                step->ckdf.key_properties.word.value = get_uint32_val(param_ptr + 2);
                break;
            case TAG_PARAM_DERIVATION_DATA:
                PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*(param_ptr + 1) == MCUXCLELS_CKDF_DERIVATIONDATA_SIZE,
                                                     PSA_ERROR_INVALID_ARGUMENT, "Invalid ELS command structure");
                PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(param_ptr, 1 + sizeof(step->ckdf.derivation_data), end,
                                                                 PSA_ERROR_INVALID_ARGUMENT,
                                                                 "Invalid ELS command structure");
                memcpy(step->ckdf.derivation_data, param_ptr + 2, sizeof(step->ckdf.derivation_data));
                break;
            default:
                return PSA_ERROR_INVALID_ARGUMENT;
        }
        param_ptr += 2 + *(param_ptr + 1);
    }

    if (is_ns_owned_key(key_id) && (step->ckdf.key_properties.bits.upprot_sec == MCUXCLELS_KEYPROPERTY_SECURE_TRUE))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

exit:
    return psa_status;
}

static psa_status_t parse_keygen_step(mbedtls_svc_key_id_t key_id,
                                      const uint8_t *param_data,
                                      uint8_t param_data_length,
                                      key_recipe_step_t *step)
{
    psa_status_t psa_status = PSA_SUCCESS;

    step->operation            = OP_KEYGEN;
    step->ckdf.target_key_slot = UINT32_MAX;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(param_data != NULL, PSA_ERROR_INVALID_ARGUMENT, "NULL pointer");
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(param_data_length > 0, PSA_ERROR_INVALID_ARGUMENT, "Length is 0");

    const uint8_t *param_ptr = param_data;
    const uint8_t *end       = param_ptr + param_data_length;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(param_ptr < end, PSA_ERROR_INVALID_ARGUMENT, "Overflow");

    while (param_ptr < end)
    {
        // Assume every tag is followed by one byte of length.
        PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(param_ptr, 1, end, PSA_ERROR_INVALID_ARGUMENT,
                                                         "Invalid ELS command structure");
        switch (*param_ptr)
        {
            case TAG_PARAM_TARGET_KEY_ID:
                PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*(param_ptr + 1) == 4, PSA_ERROR_INVALID_ARGUMENT,
                                                     "Invalid ELS command structure");
                PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(param_ptr, 2 + 4, end, PSA_ERROR_INVALID_ARGUMENT,
                                                                 "Invalid ELS command structure");
                step->keygen.target_key_slot = get_uint32_val(param_ptr + 2);
                break;
            case TAG_PARAM_TARGET_KEY_PROP:
                PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*(param_ptr + 1) == 4, PSA_ERROR_INVALID_ARGUMENT,
                                                     "Invalid ELS command structure");
                PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(param_ptr, 2 + 4, end, PSA_ERROR_INVALID_ARGUMENT,
                                                                 "Invalid ELS command structure");
                step->keygen.key_properties.word.value = get_uint32_val(param_ptr + 2);
                break;
            case TAG_PARAM_OPTION:
                PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*(param_ptr + 1) == 4, PSA_ERROR_INVALID_ARGUMENT,
                                                     "Invalid ELS command structure");
                PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(param_ptr, 2 + 4, end, PSA_ERROR_INVALID_ARGUMENT,
                                                                 "Invalid ELS command structure");
                step->keygen.options.word.value = get_uint32_val(param_ptr + 2);
                break;
            default:
                return PSA_ERROR_INVALID_ARGUMENT;
        }
        param_ptr += 2 + *(param_ptr + 1);
    }

    if (is_ns_owned_key(key_id) && (step->keygen.key_properties.bits.upprot_sec == MCUXCLELS_KEYPROPERTY_SECURE_TRUE))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

exit:
    return psa_status;
}

static psa_status_t parse_kdelete_step(mbedtls_svc_key_id_t key_id,
                                       const uint8_t *param_data,
                                       uint8_t param_data_length,
                                       key_recipe_step_t *step)
{
    psa_status_t psa_status = PSA_SUCCESS;

    step->operation            = OP_KDELETE;
    step->ckdf.target_key_slot = UINT32_MAX;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(param_data != NULL, PSA_ERROR_INVALID_ARGUMENT, "NULL pointer");
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(param_data_length > 0, PSA_ERROR_INVALID_ARGUMENT, "Length is 0");

    const uint8_t *param_ptr = param_data;
    const uint8_t *end       = param_ptr + param_data_length;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(param_ptr < end, PSA_ERROR_INVALID_ARGUMENT, "Overflow");

    while (param_ptr < end)
    {
        // Assume every tag is followed by one byte of length.
        PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(param_ptr, 1, end, PSA_ERROR_INVALID_ARGUMENT,
                                                         "Invalid ELS command structure");
        switch (*param_ptr)
        {
            case TAG_PARAM_TARGET_KEY_ID:
                PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*(param_ptr + 1) == 4, PSA_ERROR_INVALID_ARGUMENT,
                                                     "Invalid ELS command structure");
                PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(param_ptr, 2 + 4, end, PSA_ERROR_INVALID_ARGUMENT,
                                                                 "Invalid ELS command structure");
                step->kdelete.target_key_slot = get_uint32_val(param_ptr + 2);
                break;
            default:
                return PSA_ERROR_INVALID_ARGUMENT;
        }
        param_ptr += 2 + *(param_ptr + 1);
    }

exit:
    return psa_status;
}

psa_status_t is_valid_key_usage(bool *valid_key_usage)
{
    // TODO: check client_id, etc...
    *valid_key_usage = true;
    return PSA_SUCCESS;
}
#if defined(MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV)
static psa_status_t execute_keyprov_step(mbedtls_svc_key_id_t key_id,
                                         const key_recipe_step_t *step,
                                         mcuxClEls_KeyIndex_t *target_key_slot)
{
    psa_status_t psa_status = PSA_SUCCESS;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(step != NULL, PSA_ERROR_INVALID_ARGUMENT, "Invalid input pointer");

    bool valid_key_usage = false;
    psa_status           = is_valid_key_usage(&valid_key_usage);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error determining valid key usage");
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(valid_key_usage, PSA_ERROR_BAD_STATE, "Key usage is invalid!");

    *target_key_slot = get_usable_key_slot(step->keyprov.target_key_slot, &step->keyprov.key_properties);
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*target_key_slot < MCUXCLELS_KEY_SLOTS, PSA_ERROR_BAD_STATE,
                                         "No usable keyslot found (%ld)", step->keyprov.target_key_slot);

    psa_status = mcuxClPsaDriver_Oracle_ElsUtils_KeyProv(step->keyprov.options, step->keyprov.key_part_1,
                                                         step->keyprov.key_part_2, step->keyprov.key_part_2_len,
                                                         *target_key_slot, step->keyprov.key_properties);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error in ELS KEYPROV function execution");

    save_key_in_slot_handler(*target_key_slot, key_id, step->storage, NULL, 0U);
exit:
    return psa_status;
}
#endif /* MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV */

static psa_status_t execute_ckdf_step(mbedtls_svc_key_id_t key_id,
                                      const key_recipe_step_t *step,
                                      mcuxClEls_KeyIndex_t *target_key_id)
{
    psa_status_t psa_status = PSA_SUCCESS;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(step != NULL, PSA_ERROR_INVALID_ARGUMENT, "Invalid input pointer");

    bool valid_key_usage = false;
    psa_status           = is_valid_key_usage(&valid_key_usage);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error determining valid key usage");
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(valid_key_usage, PSA_ERROR_BAD_STATE, "Key usage is invalid!");

    *target_key_id = get_usable_key_slot(step->ckdf.target_key_slot, &step->ckdf.key_properties);
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*target_key_id < MCUXCLELS_KEY_SLOTS, PSA_ERROR_BAD_STATE,
                                         "No usable keyslot found (%ld)", step->ckdf.target_key_slot);

    psa_status = mcuxClPsaDriver_Oracle_ElsUtils_Ckdf(step->ckdf.source_key_slot, *target_key_id,
                                                      step->ckdf.key_properties, step->ckdf.derivation_data);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error in ELS CKDF function execution");

    save_key_in_slot_handler(*target_key_id, key_id, step->storage, NULL, 0U);

exit:
    return psa_status;
}

static psa_status_t execute_keygen_step(mbedtls_svc_key_id_t key_id,
                                        const key_recipe_step_t *step,
                                        mcuxClEls_KeyIndex_t *target_key_id)
{
    psa_status_t psa_status = PSA_SUCCESS;

    uint8_t *public_key = NULL;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(step != NULL, PSA_ERROR_INVALID_ARGUMENT, "Invalid input pointer");

    bool valid_key_usage = false;
    psa_status           = is_valid_key_usage(&valid_key_usage);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error determining valid key usage");
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(valid_key_usage, PSA_ERROR_BAD_STATE, "Key usage is invalid!");

    if (step->keygen.options.bits.kgsrc == MCUXCLELS_ECC_OUTPUTKEY_DETERMINISTIC)
    {
        *target_key_id = step->keygen.target_key_slot;
    }
    else
    {
        *target_key_id = get_usable_key_slot(step->keygen.target_key_slot, &step->keygen.key_properties);
        PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*target_key_id < MCUXCLELS_KEY_SLOTS, PSA_ERROR_BAD_STATE,
                                             "No usable keyslot found (%ld)", step->keygen.target_key_slot);
    }

    public_key = mbedtls_calloc(1, PUBLIC_KEY_SIZE);
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(public_key != NULL, PSA_ERROR_INSUFFICIENT_MEMORY,
                                         "Insufficient memory for public key allocation");

    // first byte of the key must be prepend manually
    psa_status = mcuxClPsaDriver_Oracle_ElsUtils_EccKeyGen(step->keygen.options, *target_key_id,
                                                           step->keygen.key_properties, public_key);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error in ELS ECC Key Generation function execution");

    // Hand over ownership of the public key
    save_key_in_slot_handler(*target_key_id, key_id, step->storage, public_key, PUBLIC_KEY_SIZE);
    public_key = NULL;

exit:
    mbedtls_free(public_key);
    return psa_status;
}

static psa_status_t execute_kdelete_step(mbedtls_svc_key_id_t key_id, const key_recipe_step_t *step)
{
    psa_status_t psa_status = PSA_SUCCESS;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(step != NULL, PSA_ERROR_INVALID_ARGUMENT, "Invalid input pointer");

    psa_status = mcuxClPsaDriver_Oracle_ElsUtils_KeyDelete(step->kdelete.target_key_slot);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("mcuxClPsaDriver_Oracle_ElsUtils_KeyDelete failed: 0x%x", psa_status);
    free_key_in_slot_handler(step->kdelete.target_key_slot);
exit:
    return psa_status;
}

psa_status_t mcuxClPsaDriver_Oracle_Utils_ParseKeyRecipe(mbedtls_svc_key_id_t key_id,
                                                         const uint8_t *buffer,
                                                         size_t buffer_size,
                                                         size_t max_number_of_steps,
                                                         key_recipe_t *recipe)
{
    psa_status_t psa_status = PSA_SUCCESS;

    uint8_t cmd_length = 0U;
    uint8_t cmd_id     = CMD_ID_CKDF;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(buffer != NULL, PSA_ERROR_INVALID_ARGUMENT, "Invalid input pointer");
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(buffer_size != 0, PSA_ERROR_INVALID_ARGUMENT, "Buffer size is 0");

    const uint8_t *cmd_ptr = buffer;
    const uint8_t *end     = buffer + buffer_size;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(cmd_ptr < end, PSA_ERROR_INVALID_ARGUMENT, "Overflow");

    size_t current_step_idx = 0u;
    while (cmd_ptr < end)
    {
        // There is no more command, exit the loop.
        if (*cmd_ptr == 0)
        {
            break;
        }

        PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(current_step_idx < max_number_of_steps, PSA_ERROR_INVALID_ARGUMENT,
                                             "Too many steps in recipe");

        PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*cmd_ptr == TAG_CMD, PSA_ERROR_INVALID_ARGUMENT,
                                             "Invalid ELS command structure");

        PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(cmd_ptr, 6, end, PSA_ERROR_INVALID_ARGUMENT, "Overflow");

        key_recipe_step_t *step = &recipe->steps[current_step_idx];
        memset(step, 0, sizeof(key_recipe_step_t));

        cmd_length = *(cmd_ptr + 1);
        PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*(cmd_ptr + 2) == TAG_CMD_OPTIONS, PSA_ERROR_INVALID_ARGUMENT,
                                             "Invalid ELS command structure");

        PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*(cmd_ptr + 3) == 0x02, PSA_ERROR_INVALID_ARGUMENT,
                                             "Invalid ELS command structure");

        cmd_id        = *(cmd_ptr + 4);
        step->storage = *(cmd_ptr + 5);
        switch (cmd_id)
        {
            case CMD_ID_CKDF:
                psa_status = parse_ckdf_step(key_id, cmd_ptr + 6, cmd_length - 4, step);
                break;
            case CMD_ID_KEY_GEN:
                psa_status = parse_keygen_step(key_id, cmd_ptr + 6, cmd_length - 4, step);
                break;
#if defined(MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV)
            case CMD_ID_KEY_PROV:
                psa_status = parse_keyprov_step(key_id, cmd_ptr + 6, cmd_length - 4, step);
                break;
#endif /* MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV */
            case CMD_ID_KEY_DELETE:
                psa_status = parse_kdelete_step(key_id, cmd_ptr + 6, cmd_length - 4, step);
                break;
            default:
                return PSA_ERROR_INVALID_ARGUMENT;
        }

        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error in ELS command execution");

        // add 4 header bytes and the total length of the parameters
        cmd_ptr += 2 + cmd_length;
        current_step_idx++;
    }
    recipe->number_of_steps = current_step_idx;

exit:
    return psa_status;
}

psa_status_t mcuxClPsaDriver_Oracle_Utils_GetKeyBufferSizeFromKeyData(const uint8_t *buffer,
                                                                      size_t buffer_size,
                                                                      size_t *recipe_length)
{
    psa_status_t psa_status = PSA_SUCCESS;
    uint8_t cmd_length      = 0U;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(buffer != NULL, PSA_ERROR_INVALID_ARGUMENT, "Invalid input pointer");
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(buffer_size != 0, PSA_ERROR_INVALID_ARGUMENT, "Buffer size is 0");

    const uint8_t *cmd_ptr = buffer;
    const uint8_t *end     = buffer + buffer_size;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(cmd_ptr < end, PSA_ERROR_INVALID_ARGUMENT, "Overflow");

    size_t current_step_idx = 0u;
    while (cmd_ptr < end)
    {
        // There is no more command, exit the loop.
        if (*cmd_ptr == 0)
        {
            break;
        }

        PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*cmd_ptr == TAG_CMD, PSA_ERROR_INVALID_ARGUMENT,
                                             "Invalid ELS command structure");

        PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(cmd_ptr, 6, end, PSA_ERROR_INVALID_ARGUMENT, "Overflow");

        cmd_length = *(cmd_ptr + 1);
        PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*(cmd_ptr + 2) == TAG_CMD_OPTIONS, PSA_ERROR_INVALID_ARGUMENT,
                                             "Invalid ELS command structure");

        PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(*(cmd_ptr + 3) == 0x02, PSA_ERROR_INVALID_ARGUMENT,
                                             "Invalid ELS command structure");

        // add 4 header bytes and the total length of the parameters
        cmd_ptr += 2 + cmd_length;
        current_step_idx++;
    }

    key_recipe_t recipe = {.number_of_steps = current_step_idx};
    *recipe_length      = mcuxClPsaDriver_Oracle_Utils_GetRecipeSize(&recipe);

exit:
    return psa_status;
}

psa_status_t mcuxClPsaDriver_Oracle_Utils_ExecuteKeyRecipe(mbedtls_svc_key_id_t key_id,
                                                           const key_recipe_t *recipe,
                                                           mcuxClEls_KeyIndex_t *target_key_slot)
{
    psa_status_t psa_status = PSA_SUCCESS;

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(recipe != NULL, PSA_ERROR_INVALID_ARGUMENT, "recipe is NULL");
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(target_key_slot != NULL, PSA_ERROR_INVALID_ARGUMENT,
                                         "target_key_slot is NULL");

    for (size_t i = 0; i < recipe->number_of_steps; i++)
    {
        const key_recipe_step_t *step = &recipe->steps[i];
        switch (step->operation)
        {
#if defined(MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV)
            case OP_KEYPROV:
                execute_keyprov_step(key_id, step, target_key_slot);
                PSA_DRIVER_SUCCESS_OR_EXIT_MSG("execute_keyprov_recipe returned 0x%x", psa_status);
                break;
#endif /* MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV */
            case OP_CKDF:
                psa_status = execute_ckdf_step(key_id, step, target_key_slot);
                PSA_DRIVER_SUCCESS_OR_EXIT_MSG("execute_ckdf_recipe returned 0x%x", psa_status);
                break;
            case OP_KEYGEN:
                psa_status = execute_keygen_step(key_id, step, target_key_slot);
                PSA_DRIVER_SUCCESS_OR_EXIT_MSG("execute_ckdf_recipe returned 0x%x", psa_status);
                break;
            case OP_KDELETE:
                psa_status = execute_kdelete_step(key_id, step);
                PSA_DRIVER_SUCCESS_OR_EXIT_MSG("execute_kdelete_recipe returned 0x%x", psa_status);
                break;
            default:
                PSA_DRIVER_ERROR("Unknown recipe operation: 0x%x", step->operation);
                goto exit;
        }
    }
exit:
    return psa_status;
}

psa_status_t mcuxClPsaDriver_Oracle_Utils_RemoveKeyFromEls(mbedtls_svc_key_id_t key_id)
{
    // In case at least one key in ELS has the associated key_id, the function the psa_status
    // will be set to PSA_SUCCESS after the successful deletion of the key
    uint32_t slot_id        = 0U;
    psa_status_t psa_status = PSA_ERROR_DOES_NOT_EXIST;
    psa_status              = mcuxClPsaDriver_Oracle_Utils_GetSlotFromKeyId(key_id, &slot_id);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error in getting slot from key id");

    psa_status = mcuxClPsaDriver_Oracle_ElsUtils_KeyDelete(slot_id);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error in key deletion");
    free_key_in_slot_handler(slot_id);
exit:
    return psa_status;
}

psa_status_t mcuxClPsaDriver_Oracle_UtilsExecuteElsDecryptCbc(uint8_t *psa_external_blob,
                                                              size_t psa_external_blob_size,
                                                              uint8_t **key_data,
                                                              size_t  *key_size,
                                                              uint32_t encKeyIdx)
{
    psa_status_t psa_status = PSA_SUCCESS;

    uint8_t *decrypted_key = NULL;
    size_t decrypted_key_length = 0;

    psa_cmd_t psa_cmd;
    psa_status = parse_psa_import_command(psa_external_blob, psa_external_blob_size, &psa_cmd);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error while parsing import blob");

    // ISO7816-4 padding ensures ciphertext and plaintext having the same length
    decrypted_key_length = psa_cmd.keyincmd_size;
    decrypted_key = mbedtls_calloc(1, decrypted_key_length);
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(decrypted_key != NULL, PSA_ERROR_INSUFFICIENT_MEMORY,
                                         "Insufficient memory for decrypted key allocation");

    // decrypt blob with key on S50 slot
    psa_status = mcuxClPsaDriver_Oracle_ElsUtils_Cipher_Decrypt(psa_cmd.keyincmd, psa_cmd.keyincmd_size, encKeyIdx,
                                                                psa_cmd.iv, decrypted_key);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error,  Cipher command failed");

    psa_status = unpad_iso7816d4(decrypted_key, &decrypted_key_length);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error,  unpad_iso7816d4 failed");

    // Hand over ownership of the decrypted key
    *key_size = decrypted_key_length;
    *key_data = decrypted_key;
    decrypted_key = NULL;

exit:
    if (decrypted_key != NULL) {
        mbedtls_platform_zeroize(decrypted_key, decrypted_key_length);
    }
    mbedtls_free(decrypted_key);
    return psa_status;
}

psa_status_t mcuxClPsaDriver_Oracle_UtilsExecuteElsKeyIn(mbedtls_svc_key_id_t key_id,
                                                         uint8_t *psa_import_blob,
                                                         size_t psa_import_blob_size,
                                                         uint32_t unwrapKeyIdx,
                                                         uint32_t targetKeyIdx)
{
    psa_status_t psa_status = PSA_SUCCESS;

    uint8_t* public_key = NULL;

    psa_cmd_t psa_cmd;
    psa_status = parse_psa_import_command(psa_import_blob, psa_import_blob_size, &psa_cmd);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error while parsing import blob");

    psa_status =
        mcuxClPsaDriver_Oracle_ElsUtils_KeyIn(psa_cmd.keyincmd, psa_cmd.keyincmd_size, unwrapKeyIdx, targetKeyIdx);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error in ELS keyin command execution");

    if (PSA_KEY_TYPE_IS_ECC(psa_get_key_type(&psa_cmd.attributes)))
    {
        // If we get here the ELS KEYIN was done, the key is in the slot. We can read the
        // properties of the key from ELS (so the KEYGEN result gets the same as the original).
        mcuxClEls_KeyProp_t keyProperties;
        psa_status = mcuxClPsaDriver_Oracle_ElsUtils_GetKeyProperties(targetKeyIdx, &keyProperties);
        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("mcuxClPsaDriver_Oracle_ElsUtils_GetKeyProperties failed");

        mcuxClEls_EccKeyGenOption_t key_gen_options;
        key_gen_options.word.value    = 0u;
        key_gen_options.bits.kgsign   = MCUXCLELS_ECC_PUBLICKEY_SIGN_DISABLE;
        key_gen_options.bits.kgsrc    = MCUXCLELS_ECC_OUTPUTKEY_DETERMINISTIC;
        key_gen_options.bits.skip_pbk = MCUXCLELS_ECC_GEN_PUBLIC_KEY;

        public_key = mbedtls_calloc(1, PUBLIC_KEY_SIZE);
        PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(public_key != NULL, PSA_ERROR_INSUFFICIENT_MEMORY,
                                             "Insufficient memory for public key allocation");

        psa_status = mcuxClPsaDriver_Oracle_ElsUtils_EccKeyGen(key_gen_options, targetKeyIdx, keyProperties, public_key);
        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("mcuxClPsaDriver_Oracle_ElsUtils_EccKeyGen failed");
    }

    // Hand over ownership of the public key
    save_key_in_slot_handler(targetKeyIdx, key_id, STORAGE_FINAL_KEY, public_key, PUBLIC_KEY_SIZE);
    public_key = NULL;

exit:
    mbedtls_free(public_key);
    return psa_status;
}

psa_status_t mcuxClPsaDriver_Oracle_UtilsValidateBlobAttributes(const psa_key_attributes_t *attributes,
                                                                const uint8_t *psa_import_blob,
                                                                size_t psa_import_blob_size,
                                                                uint32_t authKeyIdx)
{
    psa_status_t psa_status = PSA_SUCCESS;
    uint8_t *psa_import_blob_tbs             = NULL;

    psa_cmd_t psa_cmd;
    psa_status = parse_psa_import_command(psa_import_blob, psa_import_blob_size, &psa_cmd);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error while parsing import blob");

    size_t psa_import_blob_tbs_padded_length = 0;
    uint8_t pCmac[CMAC_BLOCK_SIZE];

    // Validate input PSA attributes
#if !defined (MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(id) != 0,
                                         PSA_ERROR_INVALID_ARGUMENT, "Invalid input key_id");
#else
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(id).key_id != 0,
                                         PSA_ERROR_INVALID_ARGUMENT, "Invalid input key_id");
#endif
    // Attention: Permitted algorithm can be 0 (PSA_ALG_NONE for X.509/Binary)
    // Attention: Permitted usage can be 0 (PSA_KEY_USAGE_NONE for static public keys)
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(
        (void *)(size_t)attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(type) != NULL, PSA_ERROR_INVALID_ARGUMENT,
        "Invalid input key_type");
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(
        (void *)(size_t)attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(bits) != NULL, PSA_ERROR_INVALID_ARGUMENT,
        "Invalid input key_length");
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG((void *)attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(lifetime) != NULL,
                                         PSA_ERROR_INVALID_ARGUMENT, "Invalid input key_lifetime");

    // Validate blob PSA attributes
#if !defined (MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(
        attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(id) == (psa_key_id_t)psa_cmd.key_id,
        PSA_ERROR_INVALID_ARGUMENT, "provided key_id does not match with blob key_id");
#else
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(
        attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(id).key_id == (psa_key_id_t)psa_cmd.key_id,
        PSA_ERROR_INVALID_ARGUMENT, "provided key_id does not match with blob key_id");
#endif

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(
        attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(policy).MBEDTLS_PRIVATE(alg) ==
            psa_cmd.attributes.MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(policy).MBEDTLS_PRIVATE(alg),
        PSA_ERROR_INVALID_ARGUMENT, "provided permitted_alg does not match with blob permitted_alg");

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(
        attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(policy).MBEDTLS_PRIVATE(usage) ==
            psa_cmd.attributes.MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(policy).MBEDTLS_PRIVATE(usage),
        PSA_ERROR_INVALID_ARGUMENT, "provided key_usage does not match with blob key_usage");

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(
        attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(type) ==
            psa_cmd.attributes.MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(type),
        PSA_ERROR_INVALID_ARGUMENT, "provided key_type does not match with blob key_type");

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(
        attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(bits) ==
            psa_cmd.attributes.MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(bits),
        PSA_ERROR_INVALID_ARGUMENT, "provided key_length does not match with blob key_length");

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(
        attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(lifetime) == (psa_key_lifetime_t)psa_cmd.key_lifetime,
        PSA_ERROR_INVALID_ARGUMENT, "provided key_lifetime does not match with blob key_lifetime");

    // Validate blob lifetime and wrapping parameters
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(lifetime));
    if (MCUXCLPSADRIVER_IS_S50_BLOB_STORAGE(location)) {
        PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(NXP_DIE_EL2GOIMPORT_KEK_SK == psa_cmd.wrapping_key_id,
            PSA_ERROR_INVALID_ARGUMENT, "Unknown blob wrapping_key_id");
        PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(BLOB_WRAP_ALGORITHM_RFC3394 == psa_cmd.wrapping_algorithm,
            PSA_ERROR_INVALID_ARGUMENT, "Unknown blob wrapping_algorithm");
    } else if (MCUXCLPSADRIVER_IS_S50_ENC_STORAGE(location)) {
        PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(NXP_DIE_EL2GOIMPORTTFM_KEK_SK == psa_cmd.wrapping_key_id,
            PSA_ERROR_INVALID_ARGUMENT, "Unknown blob wrapping_key_id");
        // We only support AES CBC wrapping via PSA
        PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(BLOB_WRAP_ALGORITHM_AES_CBC == psa_cmd.wrapping_algorithm,
            PSA_ERROR_INVALID_ARGUMENT, "Unknown blob wrapping_algorithm");
    } else {
        PSA_DRIVER_EXIT_STATUS_MSG(PSA_ERROR_INVALID_ARGUMENT, "Unknown blob key_lifetime")
    }

    // Validate signature parameters
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(NXP_DIE_EL2GOIMPORT_AUTH_SK == psa_cmd.signature_key_id,
        PSA_ERROR_INVALID_ARGUMENT, "Unknown blob signature_key_id");

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(BLOB_SIGN_ALGORITHM_CMAC == psa_cmd.signature_algorithm,
        PSA_ERROR_INVALID_ARGUMENT, "Unknown blob signature_algorithm");

    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(CMAC_BLOCK_SIZE == psa_cmd.signature_size,
        PSA_ERROR_INVALID_ARGUMENT, "Invalid blob CMAC size");

    // We do allocate enough memory here to also fit the padding into the buffer. This is achieved implicitly because
    // the blob size used here still includes the CMAC. The CMAC, however is excluded from the data to be signed and
    // thus in the copied buffer replaced by the padding.
    psa_import_blob_tbs = mbedtls_calloc(1, psa_import_blob_size);
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(psa_import_blob_tbs != NULL, PSA_ERROR_INSUFFICIENT_MEMORY,
                                         "Insufficient memory for padded blob allocation");

    // remove cmac value (last 16 bytes) from the copy
    psa_import_blob_size = psa_import_blob_size - CMAC_BLOCK_SIZE;
    memcpy(psa_import_blob_tbs, psa_import_blob, psa_import_blob_size);

    // pad data
    psa_status =
        pad_iso7816d4(psa_import_blob_tbs, psa_import_blob_size, CMAC_BLOCK_SIZE, &psa_import_blob_tbs_padded_length);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("padding data failed");

    psa_status =
        mcuxClPsaDriver_Oracle_ElsUtils_Cmac(psa_import_blob_tbs,
                                             psa_import_blob_size, // Attention, ELS expects size before padding
                                             authKeyIdx, &pCmac[0]);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error in VerifyCmac keyin command execution");

    for (size_t i = 0; i < CMAC_BLOCK_SIZE; i++)
    {
        if (psa_cmd.signature[i] != pCmac[i])
        {
            psa_status = PSA_ERROR_INVALID_SIGNATURE;
            PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error, Blob cmac value does not match calculated cmac value");
        }
    }

exit:
    if(psa_import_blob_tbs)
    {
        mbedtls_free(psa_import_blob_tbs);
    }
    return psa_status;
}
