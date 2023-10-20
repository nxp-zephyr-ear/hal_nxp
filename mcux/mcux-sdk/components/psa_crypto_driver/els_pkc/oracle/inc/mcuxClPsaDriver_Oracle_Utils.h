/*
 * Copyright 2022-2023 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file  mcuxClPsaDriver_Oracle_Utils.h
 *  @brief API definition of the Utils functions used in the Driver Wrapper */

#ifndef _MCUXCLPSADRIVER_ORACLE_UTILS_
#define _MCUXCLPSADRIVER_ORACLE_UTILS_

#include <common.h>
#include <crypto_types.h>
#include <crypto_values.h>
#include <crypto_struct.h>
#include <crypto.h>

#include <stdint.h>
#include <stddef.h>
#include "mcuxClEls_Ecc.h"
#include "mcuxClEls_Kdf.h"

#define CMD_ID_CKDF       0x00
#define CMD_ID_KEY_GEN    0x01
#define CMD_ID_KEY_PROV   0x02
#define CMD_ID_KEY_DELETE 0x03

// in case the key is derived as a process including several key derivation execution,
// the intermediate keys will have a temporary storage assigned to them and they will
// be deleted at the end of the derivation command
#define STORAGE_TEMP_KEY  0x00
#define STORAGE_FINAL_KEY 0x01

#define TAG_CMD         0x20
#define TAG_CMD_OPTIONS 0x21

// CKDF Parameters
#define TAG_PARAM_DERIVATION_KEY_ID 0x30
#define TAG_PARAM_TARGET_KEY_ID     0x31
#define TAG_PARAM_TARGET_KEY_PROP   0x32
#define TAG_PARAM_DERIVATION_DATA   0x33
#define TAG_PARAM_OPTION            0x34
#define TAG_PARAM_KEY_PART1         0x35
#define TAG_PARAM_KEY_PART2         0x36

// The keyid used on Oracle API level for unwrapping EdgeLock 2GO cloud service key blobs into Sentinel 50 slots.
#define NXP_DIE_EL2GOIMPORT_KEK_SK    0x7FFF816EU
#define NXP_DIE_EL2GOIMPORTTFM_KEK_SK 0x7FFF816FU
#define NXP_DIE_EL2GOIMPORT_AUTH_SK   0x7FFF8170U

typedef enum key_recipe_operation_t
{
    OP_KEYPROV,
    OP_CKDF,
    OP_KEYGEN,
    OP_KDELETE,
} key_recipe_operation_t;

typedef struct _key_recipe_step_keyprov_t
{
    // TODO: In order to achieve dynamic slot allocation, it is necessary to reference the key by an 'id', not by a
    // slotnumber. A mapping table from id -> slot gets the right key.. mbedtls_svc_key_id_t target_key_id;
    mcuxClEls_KeyIndex_t target_key_slot;
    mcuxClEls_KeyProp_t key_properties;
#if defined(MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV)
    mcuxClEls_KeyProvisionOption_t options;
    uint8_t key_part_1[MCUXCLELS_KEYPROV_KEY_PART_1_SIZE];
#endif /* MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV */
    size_t key_part_2_len;
    uint8_t key_part_2[64];
} key_recipe_step_keyprov_t;

typedef struct _key_recipe_step_ckdf_t
{
    // TODO: In order to achieve dynamic slot allocation, it is necessary to reference the key by an 'id', not by a
    // slotnumber. A mapping table from id -> slot gets the right key.. mbedtls_svc_key_id_t source_key_id;
    mcuxClEls_KeyIndex_t source_key_slot;
    // mbedtls_svc_key_id_t target_key_id;
    mcuxClEls_KeyIndex_t target_key_slot;
    mcuxClEls_KeyProp_t key_properties;
    uint8_t derivation_data[MCUXCLELS_CKDF_DERIVATIONDATA_SIZE];
} key_recipe_step_ckdf_t;

typedef struct _key_recipe_step_keygen_t
{
    // TODO: In order to achieve dynamic slot allocation, it is necessary to reference the key
    // by an 'id', not by a slotnumber. A mapping table from id -> slot gets the right key..
    // mbedtls_svc_key_id_t target_key_id;
    mcuxClEls_KeyIndex_t target_key_slot;
    mcuxClEls_KeyProp_t key_properties;
    mcuxClEls_EccKeyGenOption_t options;
} key_recipe_step_keygen_t;

typedef struct _key_recipe_step_kdelete_t
{
    // mbedtls_svc_key_id_t target_key_id;
    mcuxClEls_KeyIndex_t target_key_slot;
} key_recipe_step_kdelete_t;

typedef struct _key_recipe_step_t
{
    key_recipe_operation_t operation;
    uint32_t storage;
    union
    {
        key_recipe_step_keyprov_t keyprov;
        key_recipe_step_ckdf_t ckdf;
        key_recipe_step_keygen_t keygen;
        key_recipe_step_kdelete_t kdelete;
    };
} key_recipe_step_t;

typedef struct _key_recipe_t
{
    size_t number_of_steps;
    key_recipe_step_t steps[];
} key_recipe_t;

/**
 * @brief Calculate the size of a key recipe.
 * @param[in] recipe the recipe to determine the size of
 */
static inline size_t mcuxClPsaDriver_Oracle_Utils_GetRecipeSize(const key_recipe_t *recipe)
{
    return offsetof(key_recipe_t, steps) + recipe->number_of_steps * sizeof(key_recipe_step_t);
}

/**
 * @brief Gets the slot ID for the give key id
 *
 * @param[in] key_id the ID of the key from PSA view
 * @param[out] slot_id the ID of the key as stored in ELS
 *
 * @retval PSA_SUCCESS                 The operation was succesful
 * @retval PSA_ERROR_DOES_NOT_EXIST    There is no slot associated with key id
 */
psa_status_t mcuxClPsaDriver_Oracle_Utils_GetSlotFromKeyId(mbedtls_svc_key_id_t key_id, uint32_t *slot_id);

/**
 * @brief Gets the public key associated with key id
 *
 * @param[in] key_id the ID of the key from PSA view
 * @param[out] public key
 * @param[out] size of public key
 *
 * @retval PSA_SUCCESS                 The operation was succesful
 * @retval PSA_ERROR_DOES_NOT_EXIST    There is no public key associated with key id
 */
psa_status_t mcuxClPsaDriver_Oracle_Utils_GetPublicKeyFromHandler(mbedtls_svc_key_id_t key_id,
                                                                  uint8_t **public_key,
                                                                  size_t *public_key_size);

/**
 * @brief Parse a key recipe
 *
 * @param[in] key_id the key_id of the resulting key
 * @param[in] buffer buffer with instructions on how to derive the key
 * @param[in] buffer_size the length of the buffer
 * @param[in] max_number_of_steps the max number of steps that can fit into the memory allocated for recipe
 * @param[out] recipe parsed key recipe as c structure
 *
 * @retval PSA_SUCCESS                 The operation was succesful
 * @retval PSA_ERROR_INVALID_ARGUMENT  Derivation data doesn't include a valid command
 * @retval PSA_ERROR_HARDWARE_FAILURE  The ELS operation failed
 */
psa_status_t mcuxClPsaDriver_Oracle_Utils_ParseKeyRecipe(mbedtls_svc_key_id_t key_id,
                                                         const uint8_t *buffer,
                                                         size_t buffer_size,
                                                         size_t max_number_of_steps,
                                                         key_recipe_t *recipe);

/**
 * @brief Get the required size of the internal representation of a key from an imported a key buffer.
 *
 * @param[in] buffer buffer with instructions on how to derive the key
 * @param[in] buffer_size the length of the buffer
 * @param[out] key_buffer_length is the length of the recipe which will be stored for the blob
 *
 * @retval PSA_SUCCESS                 The operation was succesful
 * @retval PSA_ERROR_INVALID_ARGUMENT  Derivation data doesn't include a valid command
 * @retval PSA_ERROR_HARDWARE_FAILURE  The ELS operation failed
 */
psa_status_t mcuxClPsaDriver_Oracle_Utils_GetKeyBufferSizeFromKeyData(const uint8_t *buffer,
                                                                      size_t buffer_size,
                                                                      size_t *recipe_length);
/**
 * @brief Executes a parsed key recipe.
 *
 * No more input validation is done on the structured input data!
 *
 * @param[in] key_id the ID of the key from PSA view
 * @param[in] recipe a list of steps making up the recipe to get the key
 * @param[out] target_key_slot the ELS key slot that the final key is occupying
 *
 * @retval PSA_SUCCESS                 The operation was succesful
 * @retval PSA_ERROR_INVALID_ARGUMENT  Derivation data doesn't include a valid command
 * @retval PSA_ERROR_HARDWARE_FAILURE  The ELS operation failed
 */
psa_status_t mcuxClPsaDriver_Oracle_Utils_ExecuteKeyRecipe(mbedtls_svc_key_id_t key_id,
                                                           const key_recipe_t *recipes,
                                                           mcuxClEls_KeyIndex_t *target_key_slot);

/**
 * @brief Deletes the keys associated with the PSA key ID form ELS and internal handler
 *
 * @param[in] key_id the ID of the key from PSA view
 *
 * @retval PSA_SUCCESS                 The operation was succesful
 * @retval PSA_ERROR_DOES_NOT_EXIST    No key with the associated key_id found in ELS
 */
psa_status_t mcuxClPsaDriver_Oracle_Utils_RemoveKeyFromEls(mbedtls_svc_key_id_t key_id);

/**
 * @brief Parses psa_import_blob and executes the KEYIN command on the ELS
 *
 * @param[in] key_id psa key id reference
 * @param[in] psa_import_blob buffer holding psa import command
 * @param[in] psa_import_blob_size the length of the buffer
 * @param[in] unwrapKeyIdx The index of the unwrapping key.
 * @param[in] targetKeyIdx The index of the target key that will be loaded.
 *
 * @retval PSA_SUCCESS                 The operation was successful
 * @retval PSA_ERROR_HARDWARE_FAILURE  The ELS operation failed
 */
psa_status_t mcuxClPsaDriver_Oracle_UtilsExecuteElsKeyIn(mbedtls_svc_key_id_t key_id,
                                                         uint8_t *psa_import_blob,
                                                         size_t psa_import_blob_size,
                                                         uint32_t unwrapKeyIdx,
                                                         uint32_t targetKeyIdx);

/**
 * @brief Parses psa_import_blob, verifies blob integrity and validates provided attributes against attributes from psa
 * blob.
 *
 * @param[in] attributes provided key attributes
 * @param[in] psa_import_blob buffer holding psa import command
 * @param[in] psa_import_blob_size the length of the buffer
 * @param[in] authKeyIdx The index of the auth key that will be used for cmac.
 *
 * @retval PSA_SUCCESS                 The operation was successful
 * @retval PSA_ERROR_INVALID_ARGUMENT  Argument validation failed
 */
psa_status_t mcuxClPsaDriver_Oracle_UtilsValidateBlobAttributes(const psa_key_attributes_t *attributes,
                                                                const uint8_t *psa_import_blob,
                                                                size_t psa_import_blob_size,
                                                                uint32_t authKeyIdx);

/**
 * @brief Parses psa_import_external_blob and decrypts it.
 *
 * @param[in] psa_external_blob buffer holding psa import command
 * @param[in] psa_external_blob_size the length of the buffer
 * @param[in] key_data the decrypted key buffer
 * @param[in] key_size the length of the key buffer
 * @param[in] encKeyIdx The index of the enc key that will be used for decryption.
 *
 * @retval PSA_SUCCESS                 The operation was successful
 * @retval PSA_ERROR_INVALID_ARGUMENT  Argument validation failed
 */
psa_status_t mcuxClPsaDriver_Oracle_UtilsExecuteElsDecryptCbc(uint8_t *psa_external_blob,
                                                              size_t psa_external_blob_size,
                                                              uint8_t **key_data,
                                                              size_t *key_size,
                                                              uint32_t encKeyIdx);
#endif //_MCUXCLPSADRIVER_ORACLE_UTILS_
