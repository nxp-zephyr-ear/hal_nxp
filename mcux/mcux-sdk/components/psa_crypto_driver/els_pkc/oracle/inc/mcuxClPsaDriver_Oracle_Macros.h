/*
 * Copyright 2022-2023 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file  mcuxClPsaDriver_Oracle_Macros.h
 *  @brief Macros used by the Oracle and Utils functions */

#ifndef _MCUXCLPSADRIVER_ORACLE_MACROS_
#define _MCUXCLPSADRIVER_ORACLE_MACROS_

#include <common.h>

#ifdef TFM_SPM_LOG_LEVEL
#undef PRINTF
#define PRINTF printf
#endif /* TFM_SPM_LOG_LEVEL */

#define PSA_DRIVER_ERROR(...)                          \
    for (;;)                                           \
    {                                                  \
        PRINTF("ERROR: %s L#%d ", __func__, __LINE__); \
        PRINTF(__VA_ARGS__);                           \
        PRINTF("\r\n");                                \
        break;                                         \
    }

#define PSA_DRIVER_EXIT_STATUS_MSG(STATUS, ...) \
    psa_status = STATUS;                        \
    PSA_DRIVER_ERROR(__VA_ARGS__);              \
    goto exit;

#define PSA_DRIVER_SUCCESS_OR_EXIT_MSG(...) \
    if (PSA_SUCCESS != psa_status)          \
    {                                       \
        PSA_DRIVER_ERROR(__VA_ARGS__);      \
        goto exit;                          \
    }

#define PSA_DRIVER_SUCCESS_OR_EXIT() \
    PSA_DRIVER_SUCCESS_OR_EXIT_MSG("psa_status is not success but [0x%08x]", psa_status)

#define PSA_DRIVER_SET_STATUS_SUCCESS_AND_EXIT() \
    psa_status = PSA_SUCCESS;                    \
    goto exit;

#define PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(CONDITION, STATUS, ...) \
    if (!(CONDITION))                                                \
    {                                                                \
        PSA_DRIVER_EXIT_STATUS_MSG(STATUS, __VA_ARGS__);             \
    }

#define PSA_DRIVER_ASSERT_BUFFER_SIZE_OR_EXIT_STATUS_MSG(BASE, LENGTH, END, STATUS, ...) \
    PSA_DRIVER_ASSERT_OR_EXIT_STATUS_MSG(((BASE + LENGTH) > BASE) && ((BASE + LENGTH) <= END), STATUS, __VA_ARGS__)

// common flags
#define PSA_KEY_LOCATION_NXP_FLAG              0x400000U
#define PSA_KEY_LOCATION_EL2GO_FLAG            0x200000U
#define PSA_KEY_LOCATION_S50_FLAG              0x000001U
#define PSA_KEY_LOCATION_COMMON_FLAG           (PSA_KEY_LOCATION_VENDOR_FLAG | PSA_KEY_LOCATION_NXP_FLAG | PSA_KEY_LOCATION_EL2GO_FLAG | PSA_KEY_LOCATION_S50_FLAG)

// key/data
#define PSA_KEY_LOCATION_KEY_FLAG              0x000000
#define PSA_KEY_LOCATION_DATA_FLAG             0x008000

// blob/encrypted
#define PSA_KEY_LOCATION_BLOB_STORAGE_FLAG     0x000000
#define PSA_KEY_LOCATION_ENC_STORAGE_FLAG      0x000100
#define PSA_KEY_LOCATION_TEMP_STORAGE_FLAG     0x000200
#define PSA_KEY_LOCATION_KEY_GEN_STORAGE_FLAG  0x000300

#define PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY         ((psa_key_location_t)(PSA_KEY_LOCATION_COMMON_FLAG | PSA_KEY_LOCATION_ENC_STORAGE_FLAG | PSA_KEY_LOCATION_KEY_FLAG))
#define PSA_KEY_LOCATION_S50_ENC_STORAGE_DATA         ((psa_key_location_t)(PSA_KEY_LOCATION_COMMON_FLAG | PSA_KEY_LOCATION_ENC_STORAGE_FLAG | PSA_KEY_LOCATION_DATA_FLAG))
#define MCUXCLPSADRIVER_IS_S50_ENC_STORAGE(location) (((location) == PSA_KEY_LOCATION_S50_ENC_STORAGE_KEY) || ((location) == PSA_KEY_LOCATION_S50_ENC_STORAGE_DATA))

#define PSA_KEY_LOCATION_S50_BLOB_STORAGE             ((psa_key_location_t)(PSA_KEY_LOCATION_COMMON_FLAG | PSA_KEY_LOCATION_BLOB_STORAGE_FLAG | PSA_KEY_LOCATION_KEY_FLAG))
#define MCUXCLPSADRIVER_IS_S50_BLOB_STORAGE(location) ((location) == PSA_KEY_LOCATION_S50_BLOB_STORAGE)

#define PSA_KEY_LOCATION_S50_TEMP_STORAGE             ((psa_key_location_t)(PSA_KEY_LOCATION_COMMON_FLAG | PSA_KEY_LOCATION_TEMP_STORAGE_FLAG | PSA_KEY_LOCATION_KEY_FLAG))
#define MCUXCLPSADRIVER_IS_S50_TEMP_STORAGE(location) ((location) == PSA_KEY_LOCATION_S50_TEMP_STORAGE)

#define PSA_KEY_LOCATION_S50_KEY_GEN_STORAGE          ((psa_key_location_t)(PSA_KEY_LOCATION_COMMON_FLAG | PSA_KEY_LOCATION_KEY_GEN_STORAGE_FLAG | PSA_KEY_LOCATION_KEY_FLAG))
#define MCUXCLPSADRIVER_IS_S50_KEY_GEN_STORAGE(location) ((location) == PSA_KEY_LOCATION_S50_KEY_GEN_STORAGE)
#endif //_MCUXCLPSADRIVER_ORACLE_MACROS_
