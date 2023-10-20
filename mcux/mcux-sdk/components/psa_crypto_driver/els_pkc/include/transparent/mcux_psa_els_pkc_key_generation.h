/*
 * Copyright 2023 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MCUX_PSA_KEY_GENERATION_H
#define MCUX_PSA_KEY_GENERATION_H

/** \file mcux_psa_els_pkc_key_generation.h
 *
 * This file contains the declaration of the entry points associated to the
 * key generation (i.e. random generation and extraction of public keys) as
 * described by the PSA Cryptoprocessor Driver interface specification
 *
 */

#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \brief import transparent key
 */
psa_status_t els_pkc_transparent_import_key(const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length, uint8_t *key_buffer,
    size_t key_buffer_size, size_t *key_buffer_length,  size_t *bits);

/*!
 * \brief Generate a random key
 *
 * \param[in]  attributes        Attributes of the key to use
 * \param[out] key_buffer        Buffer to hold the generated key
 * \param[in]  key_buffer_size   Size in bytes of the key_buffer buffer
 * \param[out] key_buffer_length Size in bytes of the generated key
 *
 * \retval  PSA_SUCCESS on success. Error code from \ref psa_status_t on
 *          failure
 */
psa_status_t els_pkc_transparent_generate_key(const psa_key_attributes_t *attributes,
                                               uint8_t *key_buffer, size_t key_buffer_size,
                                               size_t *key_buffer_length);

/*!
 * \brief Destroy a random key
 *
 * \param[in]  attributes        Attributes of the key to destroy
 * \param[out] key_buffer        Buffer for the key
 * \param[in]  key_buffer_size   Size in bytes of the key_buffer buffer

 * \retval  PSA_SUCCESS on success. Error code from \ref psa_status_t on
 *          failure
 */
psa_status_t els_pkc_transparent_destroy_key(const psa_key_attributes_t *attributes,
                                         uint8_t *key_buffer, size_t key_buffer_size);

/*!
 * \brief Export the public key from a private key.
 *
 * \param[in]  attributes      Attributes of the key to use
 * \param[in]  key_buffer      Buffer to hold the generated key
 * \param[in]  key_buffer_size Size in bytes of the key_buffer buffer
 * \param[out] data            Buffer to hold the extracted public key
 * \param[in]  data_size       Size in bytes of the data buffer
 * \param[out] data_length     Size in bytes of the extracted public key
 *
 * \retval  PSA_SUCCESS on success. Error code from \ref psa_status_t on
 *          failure
 */
psa_status_t els_pkc_transparent_export_public_key(const psa_key_attributes_t *attributes,
                                               const uint8_t *key_buffer,
                                               size_t key_buffer_size, uint8_t *data,
                                               size_t data_size, size_t *data_length);
/*!
 * \brief Export the key from a private key.
 *
 * \param[in]  attributes      Attributes of the key to use
 * \param[in]  key_buffer      Buffer to hold the generated key
 * \param[in]  key_buffer_size Size in bytes of the key_buffer buffer
 * \param[out] data            Buffer to hold the extracted public key
 * \param[in]  data_size       Size in bytes of the data buffer
 * \param[out] data_length     Size in bytes of the extracted public key
 *
 * \retval  PSA_SUCCESS on success. Error code from \ref psa_status_t on
 *          failure
 */
 psa_status_t els_pkc_transparent_export_key(const psa_key_attributes_t *attributes,
                                               const uint8_t *key_buffer,
                                               size_t key_buffer_size, uint8_t *data,
                                               size_t data_size, size_t *data_length);

/*!
 * \brief Return the buffer size required by driver for storing key.
 *
 * \param[in] attributes defines the attributes associated with the input buffer
 * \param[in] data includes the input buffer as passed to the psa import function
 * \retval key_buffer_length is the required number of bytes required as 
 *         key_buffer. size_t on success. 0 on failure
 */
size_t els_pkc_transparent_size_function(const psa_key_attributes_t *attributes,
    const uint8_t *data,size_t data_length);

/*!
 * \brief Return the buffer size required by driver for storing key.
 *
 * \param[in] key_id the PSA key id of a built-in key
 * \retval key_buffer_length is the required number of bytes required as 
 *         key_buffer. size_t on success. 0 on failure
 */
size_t els_pkc_transparent_size_function_key_buff_size(mbedtls_svc_key_id_t key_id);

#ifdef __cplusplus
}
#endif
#endif /* MCUX_PSA_KEY_GENERATION_H */
