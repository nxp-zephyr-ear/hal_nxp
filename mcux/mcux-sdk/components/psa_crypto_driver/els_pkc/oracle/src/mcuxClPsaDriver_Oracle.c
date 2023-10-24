/*
 * Copyright 2022-2023 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <mcuxClPsaDriver_Oracle.h>
#include <mcuxClPsaDriver_Oracle_Utils.h>
#include <mcuxClPsaDriver_Oracle_Macros.h>
#include <mcuxClPsaDriver.h>
//#if defined (PSA_CRYPTO_MBEDTLS_STANDALONE)
#include <psa/crypto_extra.h>
//#else
//#include <mbed_psa/crypto_extra.h>
//#endif
#include <mbedtls/platform.h>
#include <string.h>
#include "crypto.h"

/* If TF-M Builtin keys are being used in project,
 then use rw61x specific plat builtin keys */
#if defined(PSA_CRYPTO_DRIVER_TFM_BUILTIN_KEY_LOADER)
#include "tfm_crypto_defs.h"
#include "tfm_plat_crypto_keys.h"
#include "tfm_builtin_key_ids_rw61x.h"
#endif /* PSA_CRYPTO_DRIVER_TFM_BUILTIN_KEY_LOADER */

#include "mcuxClPsaDriver_Oracle_ElsUtils.h"

#include <internal/mcuxClPsaDriver_Internal.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClKey_Functions_Internal.h>

#if !defined (MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
static const mbedtls_svc_key_id_t el2goimport_kek_sk_id  = NXP_DIE_EL2GOIMPORT_KEK_SK;
static const mbedtls_svc_key_id_t el2goimporttfm_kek_sk_id = NXP_DIE_EL2GOIMPORTTFM_KEK_SK;
static const mbedtls_svc_key_id_t el2goimport_auth_sk_id = NXP_DIE_EL2GOIMPORT_AUTH_SK;
#else
static const mbedtls_svc_key_id_t el2goimport_kek_sk_id  = {
    .MBEDTLS_PRIVATE(owner) = 0, .MBEDTLS_PRIVATE(key_id) = NXP_DIE_EL2GOIMPORT_KEK_SK
};
static const mbedtls_svc_key_id_t el2goimporttfm_kek_sk_id = {
    .MBEDTLS_PRIVATE(owner) = 0, .MBEDTLS_PRIVATE(key_id) = NXP_DIE_EL2GOIMPORTTFM_KEK_SK
};
static const mbedtls_svc_key_id_t el2goimport_auth_sk_id = {
    .MBEDTLS_PRIVATE(owner) = 0, .MBEDTLS_PRIVATE(key_id) = NXP_DIE_EL2GOIMPORT_AUTH_SK
};
#endif

#if USE_A0_DEVELOPMENT_RECIPES

#define MAX_RECIPE_STEPS 10

#define RECIPE_STEP_CREATE_NXP_DIE_EXT_MK_SK                                                                        \
    {                                                                                                               \
        .operation = OP_KEYPROV, .storage = STORAGE_TEMP_KEY,                                                       \
        .keyprov = {                                                                                                \
            .target_key_slot           = 0x0A,                                                                      \
            .key_properties.word.value = 0xa0010000,                                                                \
            .options.word.value        = 0x00000000,                                                                \
            .key_part_1 =                                                                                           \
                {                                                                                                   \
                    0x4e, 0x53, 0x27, 0x90, 0x94, 0xbe, 0x56, 0xa8, 0x27, 0x67, 0x53, 0x40, 0xac, 0x51, 0xa4, 0xbc, \
                    0x39, 0xb5, 0x41, 0xa5, 0x22, 0x6e, 0xe3, 0x83, 0x43, 0xbd, 0x99, 0xa4, 0x4a, 0x7e, 0x61, 0xdf, \
                },                                                                                                  \
            .key_part_2_len = 64,                                                                                   \
            .key_part_2 =                                                                                           \
                {                                                                                                   \
                    0xcb, 0x30, 0xfa, 0x0c, 0x17, 0x35, 0x5d, 0x8a, 0x3a, 0xcc, 0x82, 0x4f, 0xd1, 0x3b, 0xe4, 0xe9, \
                    0x99, 0xb7, 0xc8, 0x48, 0x3f, 0x44, 0x86, 0x73, 0x6e, 0xfa, 0xad, 0x26, 0xfd, 0xcd, 0x72, 0x7d, \
                    0xf3, 0x91, 0x6b, 0xa7, 0x93, 0xb4, 0xe5, 0x22, 0x91, 0xa3, 0xdd, 0x7f, 0x65, 0xd8, 0x6a, 0xcc, \
                    0xec, 0xfc, 0x92, 0x56, 0x7c, 0x5d, 0xc0, 0x05, 0xd4, 0x69, 0x4d, 0x82, 0x78, 0xf8, 0x85, 0x07, \
                },                                                                                                  \
        },                                                                                                          \
    }

#define RECIPE_STEP_DELETE_NXP_DIE_EXT_MK_SK                  \
    {                                                         \
        .operation = OP_KDELETE, .storage = STORAGE_TEMP_KEY, \
        .kdelete = {                                          \
            .target_key_slot = 0x0A,                          \
        },                                                    \
    }

#define RECIPE_STEP_CREATE_NXP_DIE_EL2GOSYM_MK_SK                                                                  \
    {                                                                                                              \
        .operation = OP_CKDF, .storage = STORAGE_TEMP_KEY,                                                         \
        .ckdf = {                                                                                                  \
            .source_key_slot           = 0x0A,                                                                     \
            .target_key_slot           = 0x0C,                                                                     \
            .key_properties.word.value = 0x80010021,                                                               \
            .derivation_data           = {0x00, 0x65, 0x32, 0x67, 0x73, 0x79, 0x6D, 0x5F, 0x6D, 0x6B, 0x00, 0x00}, \
        },                                                                                                         \
    }

#define RECIPE_STEP_DELETE_NXP_DIE_EL2GOSYM_MK_SK             \
    {                                                         \
        .operation = OP_KDELETE, .storage = STORAGE_TEMP_KEY, \
        .kdelete = {                                          \
            .target_key_slot = 0x0C,                          \
        },                                                    \
    }

#define RECIPE_STEP_CREATE_NXP_DIE_EL2GOOEM_MK_SK                                                                  \
    {                                                                                                              \
        .operation = OP_CKDF, .storage = STORAGE_TEMP_KEY,                                                         \
        .ckdf = {                                                                                                  \
            .source_key_slot           = 0x0C,                                                                     \
            .target_key_slot           = 0x0E,                                                                     \
            .key_properties.word.value = 0x80010021,                                                               \
            .derivation_data           = {0x00, 0x65, 0x32, 0x67, 0x6f, 0x65, 0x6D, 0x5F, 0x6D, 0x6B, 0x00, 0x00}, \
        },                                                                                                         \
    }

#define RECIPE_STEP_DELETE_NXP_DIE_EL2GOOEM_MK_SK             \
    {                                                         \
        .operation = OP_KDELETE, .storage = STORAGE_TEMP_KEY, \
        .kdelete = {                                          \
            .target_key_slot = 0x0E,                          \
        },                                                    \
    }

#define RECIPE_STEP_CREATE_NXP_DIE_EL2GOIMPORT_AUTH_SK                                                             \
    {                                                                                                              \
        .operation = OP_CKDF, .storage = STORAGE_FINAL_KEY,                                                        \
        .ckdf = {                                                                                                  \
            .source_key_slot           = 0x0E,                                                                     \
            .target_key_slot           = 0x08,                                                                     \
            .key_properties.word.value = 0x80002021,                                                               \
            .derivation_data           = {0x00, 0x65, 0x32, 0x67, 0x69, 0x61, 0x75, 0x74, 0x5f, 0x73, 0x6b, 0x00}, \
        },                                                                                                         \
    }

#define RECIPE_STEP_CREATE_NXP_DIE_EL2GOIMPORT_KEK_SK                                                              \
    {                                                                                                              \
        .operation = OP_CKDF, .storage = STORAGE_FINAL_KEY,                                                        \
        .ckdf = {                                                                                                  \
            .source_key_slot           = 0x0E,                                                                     \
            .target_key_slot           = 0x08,                                                                     \
            .key_properties.word.value = 0x80800021,                                                               \
            .derivation_data           = {0x00, 0x65, 0x32, 0x67, 0x69, 0x6b, 0x65, 0x6b, 0x5f, 0x73, 0x6b, 0x00}, \
        },                                                                                                         \
    }

#define RECIPE_STEP_CREATE_NXP_DIE_EL2GOIMPORTTFM_KEK_SK                                                           \
    {                                                                                                              \
        .operation = OP_CKDF, .storage = STORAGE_FINAL_KEY,                                                        \
        .ckdf = {                                                                                                  \
            .source_key_slot           = 0x0E,                                                                     \
            .target_key_slot           = 0x08,                                                                     \
            .key_properties.word.value = 0x80100021,                                                               \
            .derivation_data           = {0x00, 0x65, 0x32, 0x67, 0x69, 0x74, 0x66, 0x6d, 0x5f, 0x73, 0x6b, 0x00}, \
        },                                                                                                         \
    }

const key_recipe_t recipe_el2go_import_auth_key = {
#if defined(MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV)
    .number_of_steps = 7,
    .steps =
        {
            RECIPE_STEP_CREATE_NXP_DIE_EXT_MK_SK, // temporary, only for A0
#else
    .number_of_steps = 6,
    .steps =
        {
#endif /* MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV */
            RECIPE_STEP_CREATE_NXP_DIE_EL2GOSYM_MK_SK,
            RECIPE_STEP_DELETE_NXP_DIE_EXT_MK_SK,
            RECIPE_STEP_CREATE_NXP_DIE_EL2GOOEM_MK_SK,
            RECIPE_STEP_DELETE_NXP_DIE_EL2GOSYM_MK_SK,
            RECIPE_STEP_CREATE_NXP_DIE_EL2GOIMPORT_AUTH_SK,
            RECIPE_STEP_DELETE_NXP_DIE_EL2GOOEM_MK_SK,
        },
};

const key_recipe_t recipe_el2goimport_kek_sk = {
#if defined(MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV)
    .number_of_steps = 7,
    .steps =
        {
            RECIPE_STEP_CREATE_NXP_DIE_EXT_MK_SK, // temporary, only for A0
#else
    .number_of_steps = 6,
    .steps =
        {
#endif /* MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV */
            RECIPE_STEP_CREATE_NXP_DIE_EL2GOSYM_MK_SK,
            RECIPE_STEP_DELETE_NXP_DIE_EXT_MK_SK,
            RECIPE_STEP_CREATE_NXP_DIE_EL2GOOEM_MK_SK,
            RECIPE_STEP_DELETE_NXP_DIE_EL2GOSYM_MK_SK,
            RECIPE_STEP_CREATE_NXP_DIE_EL2GOIMPORT_KEK_SK,
            RECIPE_STEP_DELETE_NXP_DIE_EL2GOOEM_MK_SK,
        },
};

const key_recipe_t recipe_el2goimporttfm_kek_sk = {
#if defined(MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV)
    .number_of_steps = 7,
    .steps =
        {
            RECIPE_STEP_CREATE_NXP_DIE_EXT_MK_SK, // temporary, only for A0
#else
    .number_of_steps = 6,
    .steps =
        {
#endif /* MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV */
            RECIPE_STEP_CREATE_NXP_DIE_EL2GOSYM_MK_SK,
            RECIPE_STEP_DELETE_NXP_DIE_EXT_MK_SK,
            RECIPE_STEP_CREATE_NXP_DIE_EL2GOOEM_MK_SK,
            RECIPE_STEP_DELETE_NXP_DIE_EL2GOSYM_MK_SK,
            RECIPE_STEP_CREATE_NXP_DIE_EL2GOIMPORTTFM_KEK_SK,
            RECIPE_STEP_DELETE_NXP_DIE_EL2GOOEM_MK_SK,
        },
};

#define RECIPE_STEP_CREATE_NXP_DIE_EL2GO_ATTEST_AUTH_PRK_SEED                                                      \
    {                                                                                                              \
        .operation = OP_CKDF, .storage = STORAGE_TEMP_KEY,                                                         \
        .ckdf = {                                                                                                  \
            .source_key_slot           = 0x06,                                                                     \
            .target_key_slot           = 0x0E,                                                                     \
            .key_properties.word.value = 0x84000021,                                                               \
            .derivation_data           = {0x00, 0x65, 0x32, 0x67, 0x61, 0x74, 0x74, 0x5f, 0x73, 0x65, 0x00, 0x00}, \
        },                                                                                                         \
    }

#define RECIPE_STEP_CREATE_NXP_DIE_EL2GO_ATTEST_AUTH_PRK      \
    {                                                         \
        .operation = OP_KEYGEN, .storage = STORAGE_FINAL_KEY, \
        .keygen = {                                           \
            .target_key_slot           = 0x0E,                \
            .key_properties.word.value = 0x80040001,          \
        },                                                    \
    }

const key_recipe_t recipe_el2go_attest_key = {
    .number_of_steps = 2,
    .steps =
        {
            RECIPE_STEP_CREATE_NXP_DIE_EL2GO_ATTEST_AUTH_PRK_SEED,
            RECIPE_STEP_CREATE_NXP_DIE_EL2GO_ATTEST_AUTH_PRK,
        },
};

#else // if USE_A0_DEVELOPMENT_RECIPES

#define MAX_RECIPE_STEPS 5

#define RECIPE_STEP_CREATE_NXP_DIE_EL2GOIMPORT_AUTH_SK                                                             \
    {                                                                                                              \
        .operation = OP_CKDF, .storage = STORAGE_FINAL_KEY,                                                        \
        .ckdf = {                                                                                                  \
            .source_key_slot           = 0x04,                                                                     \
            .target_key_slot           = 0x08,                                                                     \
            .key_properties.word.value = 0x40002021,                                                               \
            .derivation_data           = {0x00, 0x65, 0x32, 0x67, 0x69, 0x61, 0x75, 0x74, 0x5f, 0x73, 0x6b, 0x00}, \
        },                                                                                                         \
    }

#define RECIPE_STEP_CREATE_NXP_DIE_EL2GOIMPORT_KEK_SK                                                              \
    {                                                                                                              \
        .operation = OP_CKDF, .storage = STORAGE_FINAL_KEY,                                                        \
        .ckdf = {                                                                                                  \
            .source_key_slot           = 0x04,                                                                     \
            .target_key_slot           = 0x08,                                                                     \
            .key_properties.word.value = 0x40800021,                                                               \
            .derivation_data           = {0x00, 0x65, 0x32, 0x67, 0x69, 0x6b, 0x65, 0x6b, 0x5f, 0x73, 0x6b, 0x00}, \
        },                                                                                                         \
    }

#define RECIPE_STEP_CREATE_NXP_DIE_EL2GOIMPORTTFM_KEK_SK                                                           \
    {                                                                                                              \
        .operation = OP_CKDF, .storage = STORAGE_FINAL_KEY,                                                        \
        .ckdf = {                                                                                                  \
            .source_key_slot           = 0x04,                                                                     \
            .target_key_slot           = 0x08,                                                                     \
            .key_properties.word.value = 0x40100021,                                                               \
            .derivation_data           = {0x00, 0x65, 0x32, 0x67, 0x69, 0x74, 0x66, 0x6d, 0x5f, 0x73, 0x6b, 0x00}, \
        },                                                                                                         \
    }

const key_recipe_t recipe_el2go_import_auth_key = {
    .number_of_steps = 1,
    .steps =
        {
            RECIPE_STEP_CREATE_NXP_DIE_EL2GOIMPORT_AUTH_SK,
        },
};

const key_recipe_t recipe_el2goimport_kek_sk = {
    .number_of_steps = 1,
    .steps =
        {
            RECIPE_STEP_CREATE_NXP_DIE_EL2GOIMPORT_KEK_SK,
        },
};

const key_recipe_t recipe_el2goimporttfm_kek_sk = {
    .number_of_steps = 1,
    .steps =
        {
            RECIPE_STEP_CREATE_NXP_DIE_EL2GOIMPORTTFM_KEK_SK,
        },
};

#define RECIPE_STEP_CREATE_NXP_DIE_EL2GO_ATTEST_AUTH_PRK_SEED                                                      \
    {                                                                                                              \
        .operation = OP_CKDF, .storage = STORAGE_TEMP_KEY,                                                         \
        .ckdf = {                                                                                                  \
            .source_key_slot           = 0x06,                                                                     \
            .target_key_slot           = 0x0E,                                                                     \
            .key_properties.word.value = 0x84000021,                                                               \
            .derivation_data           = {0x00, 0x65, 0x32, 0x67, 0x61, 0x74, 0x74, 0x5f, 0x73, 0x65, 0x00, 0x00}, \
        },                                                                                                         \
    }

#define RECIPE_STEP_CREATE_NXP_DIE_EL2GO_ATTEST_AUTH_PRK      \
    {                                                         \
        .operation = OP_KEYGEN, .storage = STORAGE_FINAL_KEY, \
        .keygen = {                                           \
            .target_key_slot           = 0x0E,                \
            .key_properties.word.value = 0x80040001,          \
        },                                                    \
    }

const key_recipe_t recipe_el2go_attest_key = {
    .number_of_steps = 2,
    .steps =
        {
            RECIPE_STEP_CREATE_NXP_DIE_EL2GO_ATTEST_AUTH_PRK_SEED,
            RECIPE_STEP_CREATE_NXP_DIE_EL2GO_ATTEST_AUTH_PRK,
        },
};


#define RECIPE_STEP_CREATE_NXP_DIE_EL2GO_CONN_AUTH_PRK_SEED                                                        \
    {                                                                                                              \
        .operation = OP_CKDF, .storage = STORAGE_TEMP_KEY,                                                         \
        .ckdf = {                                                                                                  \
            .source_key_slot           = 0x06,                                                                     \
            .target_key_slot           = 0x0E,                                                                     \
            .key_properties.word.value = 0x84000021,                                                               \
            .derivation_data           = {0x00, 0x65, 0x32, 0x67, 0x63, 0x6f, 0x6e, 0x5f, 0x73, 0x65, 0x00, 0x00}, \
        },                                                                                                         \
    }

#define RECIPE_STEP_CREATE_NXP_DIE_EL2GO_CONN_AUTH_PRK        \
    {                                                         \
        .operation = OP_KEYGEN, .storage = STORAGE_FINAL_KEY, \
        .keygen = {                                           \
            .target_key_slot           = 0x0E,                \
            .key_properties.word.value = 0x80040001,          \
        },                                                    \
    }

const key_recipe_t recipe_el2go_conn_key = {
    .number_of_steps = 2,
    .steps =
        {
            RECIPE_STEP_CREATE_NXP_DIE_EL2GO_CONN_AUTH_PRK_SEED,
            RECIPE_STEP_CREATE_NXP_DIE_EL2GO_CONN_AUTH_PRK,
        },
};
#endif

/*  For now assumes that when location is PSA_KEY_LOCATION_S50_TEMP_STORAGE the slot is passed
    in key_buffer (stored in pKey->container.pData) otherwise that pointer is considered to contain
    a plain key. All keys are considered to be alreay loaded into S50 or memory.

    To closer match the use case, the keys should be loaded here.
*/
psa_status_t mcuxClPsaDriver_Oracle_GetBuiltinKeyBufferSize(mbedtls_svc_key_id_t key_id, size_t *key_buffer_size)
{
    switch (MBEDTLS_SVC_KEY_ID_GET_KEY_ID(key_id))
    {
/* If TF-M Builtin keys are being used in project,
 then use rw61x specific plat builtin keys */
#if defined(PSA_CRYPTO_DRIVER_TFM_BUILTIN_KEY_LOADER)
        case TFM_BUILTIN_KEY_ID_EL2GO_CONN_AUTH:
            *key_buffer_size = mcuxClPsaDriver_Oracle_Utils_GetRecipeSize(&recipe_el2go_conn_key);
            return PSA_SUCCESS;
#endif /*PSA_CRYPTO_DRIVER_TFM_BUILTIN_KEY_LOADER*/
#ifdef TFM_PARTITION_INITIAL_ATTESTATION
        case TFM_BUILTIN_KEY_ID_IAK:
            *key_buffer_size = mcuxClPsaDriver_Oracle_Utils_GetRecipeSize(&recipe_el2go_attest_key);
            return PSA_SUCCESS;
#endif // TFM_PARTITION_INITIAL_ATTESTATION
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t mcuxClPsaDriver_Oracle_GetBuiltinKeyBuffer(psa_key_attributes_t *attributes,
                                                        uint8_t *key_buffer,
                                                        size_t key_buffer_size,
                                                        size_t *key_buffer_length)
{
    if (attributes == NULL)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    mbedtls_svc_key_id_t key_id     = psa_get_key_id(attributes);
    size_t required_key_buffer_size = 0;
    psa_status_t status = mcuxClPsaDriver_Oracle_GetBuiltinKeyBufferSize(key_id, &required_key_buffer_size);
    if (status != PSA_SUCCESS)
    {
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (key_buffer_size < required_key_buffer_size)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (key_buffer == NULL || key_buffer_length == NULL)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    psa_key_usage_t usage        = psa_get_key_usage_flags(attributes);

/* If TF-M Builtin keys are being used in project,
 then use rw61x specific plat builtin keys */
#if defined(PSA_CRYPTO_DRIVER_TFM_BUILTIN_KEY_LOADER)

    /* Retrieve the usage policy based on the key_id and the user of the key */
    const tfm_plat_builtin_key_policy_t *policy_table = NULL;
    size_t number_of_keys = tfm_plat_builtin_key_get_policy_table_ptr(&policy_table);

    for (size_t idx = 0; idx < number_of_keys; idx++) {
        if (policy_table[idx].key_id == MBEDTLS_SVC_KEY_ID_GET_KEY_ID(key_id)) {
            if (policy_table[idx].per_user_policy == 0) {
                usage = policy_table[idx].usage;
            } else {
                /* The policy depedends also on the user of the key */
                size_t num_users = policy_table[idx].per_user_policy;
                const tfm_plat_builtin_key_per_user_policy_t *p_policy = policy_table[idx].policy_ptr;

                for (size_t j = 0; j < num_users; j++) {
                    if (p_policy[j].user == MBEDTLS_SVC_KEY_ID_GET_OWNER_ID(key_id)) {
                        usage = p_policy[j].usage;
                        break;
                    }
                }
            }
            break;
        }
    }

#endif /* PSA_CRYPTO_DRIVER_TFM_BUILTIN_KEY_LOADER */
    psa_set_key_usage_flags(attributes, usage);

    switch (MBEDTLS_SVC_KEY_ID_GET_KEY_ID(key_id))
    {
/* If TF-M Builtin keys are being used in project,
 then use rw61x specific plat builtin keys */
#if defined(PSA_CRYPTO_DRIVER_TFM_BUILTIN_KEY_LOADER)
        case TFM_BUILTIN_KEY_ID_EL2GO_CONN_AUTH:
            memcpy(key_buffer, &recipe_el2go_conn_key, required_key_buffer_size);
            *key_buffer_length = required_key_buffer_size;
            psa_set_key_algorithm(attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
            psa_set_key_type(attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
            psa_set_key_bits(attributes, 256);
            return PSA_SUCCESS;
#endif /* PSA_CRYPTO_DRIVER_TFM_BUILTIN_KEY_LOADER */
#ifdef TFM_PARTITION_INITIAL_ATTESTATION
        case TFM_BUILTIN_KEY_ID_IAK:
            memcpy(key_buffer, &recipe_el2go_attest_key, required_key_buffer_size);
            *key_buffer_length = required_key_buffer_size;
            psa_set_key_algorithm(attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
            psa_set_key_type(attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
            psa_set_key_bits(attributes, 256);
            return PSA_SUCCESS;
#endif // TFM_PARTITION_INITIAL_ATTESTATION
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t mcuxClPsaDriver_Oracle_FillKeyDescriptorFromKeySlot(mcuxClEls_KeyIndex_t key_slot,
                                                                 mcuxClKey_Descriptor_t *out_key_descriptor)
{
    psa_status_t psa_status = PSA_SUCCESS;
    mcuxClEls_KeyProp_t key_properties;
    psa_status = mcuxClPsaDriver_Oracle_ElsUtils_GetKeyProperties(key_slot, &key_properties);
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("mcuxClPsaDriver_Oracle_ElsUtils_GetKeyProperties returned 0x%x", psa_status);
    mcuxClKey_setLoadedKeyData(out_key_descriptor, NULL);
    mcuxClKey_setLoadedKeyLength(out_key_descriptor, (key_properties.bits.ksize == MCUXCLELS_KEYPROPERTY_KEY_SIZE_128) ? 16u : 32u);
    mcuxClKey_setLoadedKeySlot(out_key_descriptor, key_slot);
    mcuxClKey_setLoadStatus(out_key_descriptor, MCUXCLKEY_LOADSTATUS_COPRO);

exit:
    return psa_status;
}

psa_status_t mcuxClPsaDriver_Oracle_LoadKey(mcuxClKey_Descriptor_t *pKey)
{
    // in pKey pointer pKey->container.pData is assigned to the key buffer loaded in the memory
    // which must not be modified; in this case is including the whole blob
    // pKey->location.pData is the output pointer, which should point to the key when
    // exiting the function
    psa_status_t psa_status          = PSA_SUCCESS;

    uint8_t *decrypted_key = NULL;
    size_t decrypted_key_length = 0;

    psa_key_attributes_t *attributes = (psa_key_attributes_t *)pKey->container.pAuxData;
    psa_key_location_t location =
        PSA_KEY_LIFETIME_GET_LOCATION(attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(lifetime));

    if (MCUXCLPSADRIVER_IS_S50_TEMP_STORAGE(location))
    {
        mcuxClEls_KeyIndex_t key_slot = *((mcuxClEls_KeyIndex_t *)pKey->container.pData);
        psa_status = mcuxClPsaDriver_Oracle_FillKeyDescriptorFromKeySlot(key_slot, pKey);
        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("mcuxClPsaDriver_Oracle_FillKeyDescriptorFromKeySlot failed: 0x%x", psa_status);
    }
    else if (MCUXCLPSADRIVER_IS_S50_KEY_GEN_STORAGE(location))
    {
        mcuxClEls_KeyIndex_t key_slot = 0;
        psa_status = mcuxClPsaDriver_Oracle_Utils_GetSlotFromKeyId(
            attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(id), &key_slot);
        if (psa_status == PSA_ERROR_DOES_NOT_EXIST)
        {
            key_recipe_t *recipe = (key_recipe_t *)pKey->container.pData;
            psa_status           = mcuxClPsaDriver_Oracle_Utils_ExecuteKeyRecipe(
                attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(id), // psa reference
                recipe, &key_slot);
            PSA_DRIVER_SUCCESS_OR_EXIT_MSG("mcuxClPsaDriver_Oracle_Utils_ExecuteKeyRecipe returned 0x%x",
                                           psa_status);
        }

        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error in getting the slot from the key ID");
        psa_status = mcuxClPsaDriver_Oracle_FillKeyDescriptorFromKeySlot(key_slot, pKey);
        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("mcuxClPsaDriver_Oracle_FillKeyDescriptorFromKeySlot failed: 0x%x", psa_status);
    }
    else if (MCUXCLPSADRIVER_IS_S50_BLOB_STORAGE(location))
    {
        mcuxClEls_KeyIndex_t key_slot = 0;
        psa_status = mcuxClPsaDriver_Oracle_Utils_GetSlotFromKeyId(
            attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(id), &key_slot);
        if (psa_status == PSA_ERROR_DOES_NOT_EXIST)
        {
            // derive the NXP_DIE_EL2GOIMPORT_KEK_SK key in the keyslot
            mcuxClEls_KeyIndex_t el2goimport_kek_sk_slot = 0;
            psa_status = mcuxClPsaDriver_Oracle_Utils_ExecuteKeyRecipe(el2goimport_kek_sk_id, // psa reference
                                                                       &recipe_el2goimport_kek_sk, &el2goimport_kek_sk_slot);
            PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error in dispatching the key command to ELS");

            // get free S50 slot
            key_slot = mcuxClPsaDriver_Oracle_ElsUtils_GetFreeKeySlot(1);
            PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(key_slot < MCUXCLELS_KEY_SLOTS, PSA_ERROR_BAD_STATE,
                                                 "No free keyslot available");

            // load blob on free S50 slot
            psa_status = mcuxClPsaDriver_Oracle_UtilsExecuteElsKeyIn(
                attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(id), // psa reference
                pKey->container.pData, pKey->container.length, el2goimport_kek_sk_slot, key_slot);

            //  regardless of the status of the KEYIN, we need to free the keyslot of the wrap key
            psa_status_t psa_status_remove_key = mcuxClPsaDriver_Oracle_Utils_RemoveKeyFromEls(el2goimport_kek_sk_id);
            if (PSA_SUCCESS != psa_status_remove_key)
            {
                PSA_DRIVER_ERROR("Error,  EL2GOIMPORT_KEK_SK key removal failed");
            }
            PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error,  KeyIn command failed");
        }

        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error in getting the slot from the key ID");
        psa_status = mcuxClPsaDriver_Oracle_FillKeyDescriptorFromKeySlot(key_slot, pKey);
        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("mcuxClPsaDriver_Oracle_FillKeyDescriptorFromKeySlot failed: 0x%x", psa_status);
    }
    else if (MCUXCLPSADRIVER_IS_S50_ENC_STORAGE(location))
    {
        psa_status = mcuxClPsaDriver_Oracle_Utils_GetSlotFromKeyId(
            attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(id), &pKey->location.slot);
        if (psa_status == PSA_ERROR_DOES_NOT_EXIST)
        {
            // derive the NXP_DIE_EL2GOIMPORTTFM_KEK_SK key in the keyslot
            mcuxClEls_KeyIndex_t el2goimporttfm_kek_sk_slot;
            psa_status = mcuxClPsaDriver_Oracle_Utils_ExecuteKeyRecipe(el2goimporttfm_kek_sk_id, // psa reference
                                                                       &recipe_el2goimporttfm_kek_sk, &el2goimporttfm_kek_sk_slot);
            PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error in dispatching the key command to ELS");

            // parse blob and decrypt data on S50 slot
            psa_status = mcuxClPsaDriver_Oracle_UtilsExecuteElsDecryptCbc(pKey->container.pData, pKey->container.length,
                                                                          &decrypted_key, &decrypted_key_length,
                                                                          el2goimporttfm_kek_sk_slot);

            //  regardless of the status of the decryption, we need to free the keyslot of the enc key
            psa_status_t psa_status_remove_key = mcuxClPsaDriver_Oracle_Utils_RemoveKeyFromEls(el2goimporttfm_kek_sk_id);
            if (PSA_SUCCESS != psa_status_remove_key)
            {
                PSA_DRIVER_ERROR("Error,  EL2GOIMPORTTFM_KEK_SK key removal failed");
            }
            PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error,  Els Decrypt command failed");

            // Hand over ownership of the decrypted key
            pKey->location.length = decrypted_key_length;
            pKey->location.pData = decrypted_key;
            decrypted_key = NULL;
        }

        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error in getting the slot from the key ID");
        pKey->location.status = MCUXCLKEY_LOADSTATUS_MEMORY;
    }
    else
    {
        pKey->location.status = MCUXCLKEY_LOADSTATUS_MEMORY;
    }

exit:
    if (decrypted_key != NULL) {
        mbedtls_platform_zeroize(decrypted_key, decrypted_key_length);
    }
    mbedtls_free(decrypted_key);
    return psa_status;
}

psa_status_t mcuxClPsaDriver_Oracle_ImportKey(
    mcuxClKey_Descriptor_t *pKey, const uint8_t *data, size_t data_length, size_t *key_buffer_length, size_t *bits)
{
    psa_status_t psa_status = PSA_ERROR_INVALID_ARGUMENT;

    uint16_t key_buffer_size               = pKey->container.length;
    const psa_key_attributes_t *attributes = (psa_key_attributes_t *)pKey->container.pAuxData;
    uint8_t *key_buffer                    = pKey->container.pData;

    psa_key_location_t location =
        PSA_KEY_LIFETIME_GET_LOCATION(attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(lifetime));
    if ((MCUXCLPSADRIVER_IS_S50_BLOB_STORAGE(location)) || (MCUXCLPSADRIVER_IS_S50_ENC_STORAGE(location)))
    {
        // derive the NXP_DIE_EL2GOIMPORT_AUTH_SK key in the keyslot
        mcuxClEls_KeyIndex_t el2goimport_auth_sk_slot;
        psa_status = mcuxClPsaDriver_Oracle_Utils_ExecuteKeyRecipe(el2goimport_auth_sk_id, // psa reference
                                                                   &recipe_el2go_import_auth_key, &el2goimport_auth_sk_slot);
        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error in dispatching the key command to ELS");

        // validate blob attributes
        psa_status = mcuxClPsaDriver_Oracle_UtilsValidateBlobAttributes(attributes, data, data_length, el2goimport_auth_sk_slot);

        // regardless of the status of the blob validation, we need to free the keyslot of the auth key
        psa_status_t psa_status_remove_key = mcuxClPsaDriver_Oracle_Utils_RemoveKeyFromEls(el2goimport_auth_sk_id);
        if (PSA_SUCCESS != psa_status_remove_key) 
        {
            PSA_DRIVER_ERROR("Error,  EL2GOIMPORT_AUTH_SK key removal failed");
        }
        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("Error in Validating Blob Attributes");

        // Store the blob as is in the PSA keystore.
        if (key_buffer_size < data_length)
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        memcpy(key_buffer, data, data_length);
        *key_buffer_length = data_length;

        return PSA_SUCCESS;
    }
#ifdef PSA_CRYPTO_MBEDTLS_STANDALONE
    else if (MCUXCLPSADRIVER_IS_S50_KEY_GEN_STORAGE(location)) {
        // Store the blob as is in the PSA keystore.
        if (key_buffer_size < data_length)
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        memcpy(key_buffer, data, data_length);
        *key_buffer_length = data_length;

        return PSA_SUCCESS;
    }
#endif
    // TODO: check which return code is better to use
    return PSA_ERROR_NOT_SUPPORTED;

exit:
    return psa_status;
}

psa_status_t mcuxClPsaDriver_Oracle_ExportPublicKey(mcuxClKey_Descriptor_t *pKey,
                                                    uint8_t *data,
                                                    size_t data_size,
                                                    size_t *data_length,
                                                    bool internal_representation)
{
    psa_status_t psa_status          = PSA_ERROR_NOT_SUPPORTED;
    uint8_t *public_key              = NULL;
    size_t public_key_size           = 0U;
    psa_key_attributes_t *attributes = (psa_key_attributes_t *)pKey->container.pAuxData;
    psa_key_location_t location =
        PSA_KEY_LIFETIME_GET_LOCATION(attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(lifetime));

    if ((MCUXCLPSADRIVER_IS_S50_BLOB_STORAGE(location)) || (MCUXCLPSADRIVER_IS_S50_KEY_GEN_STORAGE(location)))
    {
        psa_status = mcuxClPsaDriver_Oracle_Utils_GetPublicKeyFromHandler(
            attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(id), &public_key, &public_key_size);

        if (psa_status == PSA_SUCCESS)
        {
            if ((public_key == NULL) || (public_key_size == 0U))
            {
                return PSA_ERROR_DATA_INVALID;
            }
            if (data_size < (public_key_size + 1))
            {
                return PSA_ERROR_INSUFFICIENT_MEMORY;
            }
            if (internal_representation) {
                if (data_size < public_key_size)
                {
                    return PSA_ERROR_BUFFER_TOO_SMALL;
                }
                *data_length = public_key_size;
                memcpy(data, public_key, public_key_size);
            } else {
                if (data_size < (public_key_size + 1))
                {
                    return PSA_ERROR_BUFFER_TOO_SMALL;
                }
                *data_length = public_key_size + 1;
                *data        = 0x04;
                memcpy(data + 1, public_key, public_key_size);
             }
        }
    }

    return psa_status;
}

psa_status_t mcuxClPsaDriver_Oracle_SuspendKey(mcuxClKey_Descriptor_t *pKey)
{
    // TODO: We should be returning an error here for a with an unknown location. However, we get called also for non
    // "oracle keys" (cryptolib issue). Keep the return success for now. return PSA_ERROR_NOT_SUPPORTED;
    return PSA_SUCCESS;
}
psa_status_t mcuxClPsaDriver_Oracle_ResumeKey(mcuxClKey_Descriptor_t *pKey)
{
    // TODO: We should be returning an error here for a with an unknown location. However, we get called also for non
    // "oracle keys" (cryptolib issue). Keep the return success for now. return PSA_ERROR_NOT_SUPPORTED;
    return PSA_SUCCESS;
}
psa_status_t mcuxClPsaDriver_Oracle_UnloadKey(mcuxClKey_Descriptor_t *pKey)
{
    psa_key_attributes_t *attributes = (psa_key_attributes_t *)pKey->container.pAuxData;
    psa_key_location_t location =
        PSA_KEY_LIFETIME_GET_LOCATION(attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(lifetime));
    // PSA_KEY_LOCATION_S50_ENC_STORAGE :as key is in RAM, no operation is required on slot.

    // Perform remove key operation on location where slot is relevant.
    if ((MCUXCLPSADRIVER_IS_S50_BLOB_STORAGE(location)) || (MCUXCLPSADRIVER_IS_S50_KEY_GEN_STORAGE(location)))
    {
        return mcuxClPsaDriver_Oracle_Utils_RemoveKeyFromEls(attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(id));
    }
    else if (MCUXCLPSADRIVER_IS_S50_TEMP_STORAGE(location))
    {
        // Don't touch TEMP storage keys.
        // They are not owned by the oracle.
    }
    else if (MCUXCLPSADRIVER_IS_S50_ENC_STORAGE(location))
    {
        if (pKey->location.pData != NULL) {
            mbedtls_platform_zeroize(pKey->location.pData, pKey->location.length);
        }
        mbedtls_free(pKey->location.pData);
    }
    // TODO: We should be returning an error here for a with an unknown location. However, we get called also for non
    // "oracle keys" (cryptolib issue). Keep the return success for now. return PSA_ERROR_NOT_SUPPORTED;
    return PSA_SUCCESS;
}

psa_status_t mcuxClPsaDriver_Oracle_ReserveKey(mcuxClKey_Descriptor_t *pKey)
{
    // TODO: We should be returning an error here for a with an unknown location. However, we get called also for non
    // "oracle keys" (cryptolib issue). Keep the return success for now. return PSA_ERROR_NOT_SUPPORTED;
    return PSA_SUCCESS;
}

psa_status_t mcuxClPsaDriver_Oracle_StoreKey(mcuxClKey_Descriptor_t *pKey)
{
    // TODO: We should be returning an error here for a with an unknown location. However, we get called also for non
    // "oracle keys" (cryptolib issue). Keep the return success for now. return PSA_ERROR_NOT_SUPPORTED;
    return PSA_SUCCESS;
}

psa_status_t mcuxClPsaDriver_Oracle_GetKeyBufferSizeFromKeyData(const psa_key_attributes_t *attributes,
                                                                const uint8_t *data,
                                                                size_t data_length,
                                                                size_t *key_buffer_length)
{
    psa_status_t psa_status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_location_t location =
        PSA_KEY_LIFETIME_GET_LOCATION(attributes->MBEDTLS_PRIVATE(core).MBEDTLS_PRIVATE(lifetime));
    if ((MCUXCLPSADRIVER_IS_S50_BLOB_STORAGE(location)) || (MCUXCLPSADRIVER_IS_S50_ENC_STORAGE(location)) ||
        (MCUXCLPSADRIVER_IS_S50_TEMP_STORAGE(location)))
    {
        *key_buffer_length = data_length;
        return PSA_SUCCESS;
    }
    else if (MCUXCLPSADRIVER_IS_S50_KEY_GEN_STORAGE(location))
    {
#ifdef PSA_CRYPTO_MBEDTLS_STANDALONE
        *key_buffer_length = data_length;
        return PSA_SUCCESS;
#else
        psa_status = mcuxClPsaDriver_Oracle_Utils_GetKeyBufferSizeFromKeyData(data, data_length, key_buffer_length);
        PSA_DRIVER_SUCCESS_OR_EXIT_MSG("mcuxClPsaDriver_Oracle_Utils_GetKeyBufferSizeFromKeyData returned 0x%x",
                                       psa_status);
        return PSA_SUCCESS;
#endif
    }

    // TODO: check which return code is better to use
    return PSA_ERROR_NOT_SUPPORTED;

exit:
    return psa_status;
}
