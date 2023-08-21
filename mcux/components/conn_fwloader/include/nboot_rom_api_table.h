/*
 *     Copyright 2020-2021 NXP
 *     All rights reserved.
 *
 *     SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __NBOOT_ROM_API_TABLE_H__
#define __NBOOT_ROM_API_TABLE_H__

typedef int romapi_status_t;

typedef struct
{
    romapi_status_t (*nboot_rsvd0)(void);
    nboot_status_t (*nboot_context_init)(nboot_context_t *context);
    nboot_status_t (*nboot_context_deinit)(nboot_context_t *context);
    nboot_status_protected_t (*nboot_sb3_load_manifest)(nboot_context_t *context,
                                                        uint32_t *manifest,
                                                        nboot_sb3_load_manifest_parms_t *parms);
    nboot_status_protected_t (*nboot_sb3_load_block)(nboot_context_t *context, uint32_t *block);
    nboot_status_protected_t (*nboot_rsvd1)(void);
    nboot_status_protected_t (*nboot_rsvd2)(void);
} nboot_interface_v0_t;

typedef struct
{
    romapi_status_t (*romapi_rng_generate_random)(uint8_t *output, size_t outputByteLen);
    nboot_status_t (*nboot_context_init)(nboot_context_t *context);
    nboot_status_t (*nboot_context_deinit)(nboot_context_t *context);
    nboot_status_protected_t (*nboot_sb3_load_manifest)(nboot_context_t *context,
                                                        uint32_t *manifest,
                                                        nboot_sb3_load_manifest_parms_t *parms);
    nboot_status_protected_t (*nboot_sb3_load_block)(nboot_context_t *context, uint32_t *block);
    nboot_status_protected_t (*nboot_img_authenticate_ecdsa)(nboot_context_t *context,
                                                             uint8_t imageStartAddress[],
                                                             nboot_bool_t *isSignatureVerified,
                                                             nboot_img_auth_ecdsa_parms_t *parms);
} nboot_interface_v1_t;

#endif /* _NBOOT_ROM_API_TABLE_H_ */
