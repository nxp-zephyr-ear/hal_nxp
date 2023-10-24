/*
 * Copyright 2022-2023 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <mcuxClPsaDriver.h>

#include <mcuxClPsaDriver_Oracle_Macros.h>
#include <mcuxClPsaDriver_Oracle_ElsUtils.h>

#if defined(MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV)
typedef struct
{
    __O uint32_t HARDENRING_FSM0_CTRL; /**< Hardenring FSM0 Ctrl, offset: 0x0 */
    __O uint32_t HARDENRING_FSM1_CTRL; /**< Hardenring FSM1 Ctrl, offset: 0x4 */
    __O uint32_t HARDENRING_FSM2_CTRL; /**< Hardenring FSM2 Ctrl, offset: 0x8 */
    __O uint32_t HARDENRING_FSM3_CTRL; /**< Hardenring FSM3 Ctrl, offset: 0xC */
    uint8_t RESERVED_0[24];
    __O uint32_t HARDENRING_FSM10_CTRL; /**< Hardenring FSM10 Ctrl, offset: 0x28 */
    __O uint32_t HARDENRING_FSM11_CTRL; /**< Hardenring FSM11 Ctrl, offset: 0x2C */
    __O uint32_t HARDENRING_FSM12_CTRL; /**< Hardenring FSM12 Ctrl, offset: 0x30 */
    __O uint32_t HARDENRING_FSM13_CTRL; /**< Hardenring FSM13 Ctrl, offset: 0x34 */
    uint8_t RESERVED_1[456];
    __IO uint32_t I_CUSTOM_31_0;       /**< ELS sideband ctrl - i_custom[31:0], offset: 0x200 */
    __IO uint32_t I_CUSTOM_63_32;      /**< ELS sideband ctrl - i_custom[63:32], offset: 0x204 */
    __IO uint32_t I_CUSTOM_95_64;      /**< ELS sideband ctrl - i_custom[95:64], offset: 0x208 */
    __IO uint32_t I_CUSTOM_127_96;     /**< ELS sideband ctrl - i_custom[127:96], offset: 0x20C */
    __IO uint32_t I_HW_DRV_DATA_31_0;  /**< ELS sideband ctrl - i_hw_drv_data[31:0], offset: 0x210 */
    __IO uint32_t I_HW_DRV_DATA_63_32; /**< ELS sideband ctrl - i_hw_drv_data[63:32], offset: 0x214 */
    uint8_t RESERVED_2[104];
    __IO uint32_t I_CSS_FEATURE0_31_0;     /**< CSS sideband ctrl - i_css_feature0[31:0], offset: 0x280 */
    __O uint32_t I_CSS_HW_EEM_EN_31_0;     /**< CSS sideband ctrl - i_css_hw_eem_en[31:0], offset: 0x284 */
    __IO uint32_t PUF_CONFIG;              /**< PUF sideband ctrl, offset: 0x288 */
    __IO uint32_t I_CSS_FEATURE0_DP_31_0;  /**< CSS sideband ctrl - i_css_feature0_dp[31:0] (Default Enable
                                              i_css_cmd_ena[31:0]), offset: 0x28C */
    __IO uint32_t I_CSS_FEATURE0_63_32;    /**< CSS sideband ctrl - i_css_feature0[63:32], offset: 0x290 */
    __IO uint32_t I_CSS_FEATURE0_DP_63_32; /**< CSS sideband ctrl - i_css_feature0_dp[63:32], offset: 0x294 */
    uint8_t RESERVED_3[360];
    __IO uint32_t WO_SCRATCH_REG0; /**< Write once scratch register 0, offset: 0x400 */
    __IO uint32_t WO_SCRATCH_REG1; /**< Write once scratch register 1, offset: 0x404 */
    __IO uint32_t WO_SCRATCH_REG2; /**< Write once scratch register 2, offset: 0x408 */
    __IO uint32_t WO_SCRATCH_REG3; /**< Write once scratch register 3, offset: 0x40C */
    __IO uint32_t WO_SCRATCH_REG4; /**< Write once scratch register 4, offset: 0x410 */
    __IO uint32_t WO_SCRATCH_REG5; /**< Write once scratch register 5, offset: 0x414 */
    __IO uint32_t WO_SCRATCH_REG6; /**< Write once scratch register 6, offset: 0x418 */
    __IO uint32_t WO_SCRATCH_REG7; /**< Write once scratch register 7, offset: 0x41C */
    uint8_t RESERVED_4[96];
    __IO uint32_t RW_SCRATCH_REG0; /**< Scratch register 0, offset: 0x480 */
    __IO uint32_t RW_SCRATCH_REG1; /**< Scratch register 1, offset: 0x484 */
    __IO uint32_t RW_SCRATCH_REG2; /**< Scratch register 2, offset: 0x488 */
    __IO uint32_t RW_SCRATCH_REG3; /**< Scratch register 3, offset: 0x48C */
    __IO uint32_t RW_SCRATCH_REG4; /**< Scratch register 4, offset: 0x490 */
    __IO uint32_t RW_SCRATCH_REG5; /**< Scratch register 5, offset: 0x494 */
    __IO uint32_t RW_SCRATCH_REG6; /**< Scratch register 6, offset: 0x498 */
    __IO uint32_t RW_SCRATCH_REG7; /**< Scratch register 7, offset: 0x49C */
    uint8_t RESERVED_5[32];
    __IO uint32_t PKC_RAM_SUBSYSTEM_CTRL; /**< PKC ram subsystem ctrl, offset: 0x4C0 */
    __I uint32_t CSS_STATUS;              /**< CSS status, offset: 0x4C4 */
    __IO uint32_t VTOR_CTRL;              /**< VTOR CTRL, offset: 0x4C8 */
    __IO uint32_t TESTBUS_CTRL;           /**< TESTBUS CTRL, offset: 0x4CC */
} RF_SYSCON_Type_Local;

#ifndef RF_SYSCON_BASE
/* RF_SYSCON - Peripheral instance base addresses */
#if (defined(__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE & 0x2))
/** Peripheral RF_SYSCON base address */
#define RF_SYSCON_BASE (0x5003B000u)
/** Peripheral RF_SYSCON base address */
#define RF_SYSCON_BASE_NS (0x4003B000u)
#endif
/** Peripheral RF_SYSCON base pointer */
#define RF_SYSCON_LOCAL ((RF_SYSCON_Type_Local *)RF_SYSCON_BASE)
/** Peripheral RF_SYSCON base pointer */
#define RF_SYSCON_NS_LOCAL ((RF_SYSCON_Type_Local *)RF_SYSCON_BASE_NS)
/** Array initializer of RF_SYSCON peripheral base addresses */
#define RF_SYSCON_BASE_ADDRS_LOCAL \
    {                        \
        RF_SYSCON_BASE       \
    }
/** Array initializer of RF_SYSCON peripheral base pointers */
#define RF_SYSCON_BASE_PTRS_LOCAL \
    {                       \
        RF_SYSCON_LOCAL           \
    }
/** Array initializer of RF_SYSCON peripheral base addresses */
#define RF_SYSCON_BASE_ADDRS_NS_LOCAL \
    {                           \
        RF_SYSCON_BASE_NS       \
    }
/** Array initializer of RF_SYSCON peripheral base pointers */
#define RF_SYSCON_BASE_PTRS_NS \
    {                          \
        RF_SYSCON_NS_LOCAL          \
    }
#else //(defined(__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE & 0x2))
/** Peripheral RF_SYSCON base address */
#ifndef RF_SYSCON_BASE
#define RF_SYSCON_BASE (0x4003B000u)
#endif

/** Peripheral RF_SYSCON base pointer */
#define RF_SYSCON_LOCAL      ((RF_SYSCON_Type_Local *)RF_SYSCON_BASE)
/** Array initializer of RF_SYSCON peripheral base addresses */
#define RF_SYSCON_BASE_ADDRS_LOCAL \
    {                        \
        RF_SYSCON_BASE       \
    }
/** Array initializer of RF_SYSCON peripheral base pointers */
#define RF_SYSCON_BASE_PTRS_LOCAL \
    {                       \
        RF_SYSCON_LOCAL           \
    }
#endif

static void nboot_set_icustom(const uint8_t *data)
{
    const uint32_t *tmp = (uint32_t *)data;
    // Do not set temporal state, skip first 32-bits
    tmp++;
    RF_SYSCON_LOCAL->I_CUSTOM_63_32  = *tmp++;
    RF_SYSCON_LOCAL->I_CUSTOM_95_64  = *tmp++;
    RF_SYSCON_LOCAL->I_CUSTOM_127_96 = *tmp++;
}
#endif /* MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV */

static bool mcuxClPsaDriver_Oracle_ElsUtils_IsActiveKeyslot(mcuxClEls_KeyIndex_t keyIdx)
{
    mcuxClEls_KeyProp_t key_properties;
    key_properties.word.value = ((const volatile uint32_t *)(&ELS->ELS_KS0))[keyIdx];
    return key_properties.bits.kactv;
}

psa_status_t mcuxClPsaDriver_Oracle_ElsUtils_GetKeyProperties(mcuxClEls_KeyIndex_t keyIdx,
                                                              mcuxClEls_KeyProp_t *keyProperties)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_GetKeyProperties(keyIdx, keyProperties));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_GetKeyProperties) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PRINTF("mcuxClEls_GetKeyProperties failed: 0x%x\r\n", result);
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();
    return PSA_SUCCESS;
}

bool mcuxClPsaDriver_Oracle_ElsUtils_IsFreeKeySlot(mcuxClEls_KeyIndex_t key_slot, uint32_t requiredKeyslots)
{
    for (uint32_t i = 0; i < requiredKeyslots; i++)
    {
        if (mcuxClPsaDriver_Oracle_ElsUtils_IsActiveKeyslot(key_slot + i))
        {
            return false;
        }
    }
    return true;
}

mcuxClEls_KeyIndex_t mcuxClPsaDriver_Oracle_ElsUtils_GetFreeKeySlot(uint32_t requiredKeyslots)
{
    for (mcuxClEls_KeyIndex_t keyIdx = 0; keyIdx <= (MCUXCLELS_KEY_SLOTS - requiredKeyslots); keyIdx++)
    {
        bool is_valid_keyslot = true;
        for (uint32_t i = 0; i < requiredKeyslots; i++)
        {
            if (mcuxClPsaDriver_Oracle_ElsUtils_IsActiveKeyslot(keyIdx + i))
            {
                is_valid_keyslot = false;
                break;
            }
        }

        if (is_valid_keyslot)
        {
            return keyIdx;
        }
    }
    return MCUXCLELS_KEY_SLOTS;
}

psa_status_t mcuxClPsaDriver_Oracle_ElsUtils_Ckdf(mcuxClEls_KeyIndex_t derivationKeyIdx,
                                                  mcuxClEls_KeyIndex_t targetKeyIdx,
                                                  mcuxClEls_KeyProp_t targetKeyProperties,
                                                  uint8_t const *pDerivationData)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result, token,
        mcuxClEls_Ckdf_Sp800108_Async(derivationKeyIdx, targetKeyIdx, targetKeyProperties, pDerivationData));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Ckdf_Sp800108_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PRINTF("Css_Ckdf_Sp800108_Async failed: 0x%x\r\n", result);
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PRINTF("Css_Ckdf_Sp800108_Asyn WaitForOperation failed: 0x%x\r\n", result);
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    return PSA_SUCCESS;
}

psa_status_t mcuxClPsaDriver_Oracle_ElsUtils_EccKeyGen(mcuxClEls_EccKeyGenOption_t options,
                                                       mcuxClEls_KeyIndex_t privateKeyIdx,
                                                       mcuxClEls_KeyProp_t generatedKeyProperties,
                                                       uint8_t *pPublicKey)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token,
                                     mcuxClEls_EccKeyGen_Async(options, (mcuxClEls_KeyIndex_t)0, privateKeyIdx,
                                                               generatedKeyProperties, NULL, pPublicKey));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_EccKeyGen_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PRINTF("Css_EccKeyGen_Async failed: 0x%x\r\n", result);
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PRINTF("Css_EccKeyGen_Async WaitForOperation failed: 0x%x\r\n", result);
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    return PSA_SUCCESS;
}

#if defined(MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV)
psa_status_t mcuxClPsaDriver_Oracle_ElsUtils_KeyProv(mcuxClEls_KeyProvisionOption_t options,
                                                     uint8_t const *pKeyPart1,
                                                     uint8_t const *pKeyPart2,
                                                     size_t part2Length,
                                                     mcuxClEls_KeyIndex_t targetKeyIdx,
                                                     mcuxClEls_KeyProp_t targetKeyProperties)
{
    uint8_t i_custom[] = {
        0x00, 0x00, 0x00, 0x00, 0x67, 0xd3, 0x7d, 0xdf, 0x8e, 0xd0, 0x5d, 0x66, 0x68, 0x40, 0x99, 0x23,
    };

    // Set icustom
    nboot_set_icustom(i_custom);

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result, token,
        mcuxClEls_KeyProvision_Async(options, pKeyPart1, pKeyPart2, part2Length, targetKeyIdx, targetKeyProperties));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_KeyProvision_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PRINTF("Css_KeyProvision_Async failed: 0x%x\r\n", result);
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PRINTF("Css_KeyProvision_Async WaitForOperation failed: 0x%x\r\n", result);
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    return PSA_SUCCESS;
}
#endif /* MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV */

psa_status_t mcuxClPsaDriver_Oracle_ElsUtils_KeyDelete(mcuxClEls_KeyIndex_t targetKeyIdx)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_KeyDelete_Async(targetKeyIdx));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_KeyDelete_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PRINTF("Css_KeyDelete_Async failed: 0x%x\r\n", result);
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PRINTF("Css_KeyDelete_Async WaitForOperation failed: 0x%x\r\n", result);
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    return PSA_SUCCESS;
}

psa_status_t mcuxClPsaDriver_Oracle_ElsUtils_KeyIn(const uint8_t *keyin_command_blob,
                                                   size_t keyin_command_blob_size,
                                                   mcuxClEls_KeyIndex_t unwrapKeyIdx,
                                                   mcuxClEls_KeyIndex_t targetKeyIdx)
{
    mcuxClEls_KeyImportOption_t options;
    options.bits.kfmt = MCUXCLELS_KEYIMPORT_KFMT_RFC3394;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result, token,
        mcuxClEls_KeyImport_Async(options, keyin_command_blob, keyin_command_blob_size, unwrapKeyIdx, targetKeyIdx));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_KeyImport_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PRINTF("mcuxClEls_KeyImport_Async failed: 0x%x\r\n", result);
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PRINTF("mcuxClEls_KeyImport_Async WaitForOperation failed: 0x%x", result);
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return PSA_SUCCESS;
}

psa_status_t mcuxClPsaDriver_Oracle_ElsUtils_Cmac(uint8_t *data,
                                                  size_t data_size,
                                                  mcuxClEls_KeyIndex_t authKeyIdx,
                                                  uint8_t *pCmac)
{
    mcuxClEls_CmacOption_t options;
    options.bits.initialize = MCUXCLELS_CMAC_INITIALIZE_ENABLE;
    options.bits.finalize   = MCUXCLELS_CMAC_FINALIZE_ENABLE;
    options.bits.extkey     = MCUXCLELS_CMAC_EXTERNAL_KEY_DISABLE;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token,
                                     mcuxClEls_Cmac_Async(options, authKeyIdx, NULL, 0, data, data_size, pCmac));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PRINTF("mcuxClEls_Cmac_Async failed: 0x%x\r\n", result);
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token,
                                     mcuxClEls_LimitedWaitForOperation(0x00100000U, MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_LimitedWaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PRINTF("mcuxClEls_Cmac_Async LimitedWaitForOperation failed: 0x%x", result);
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return PSA_SUCCESS;
}

psa_status_t mcuxClPsaDriver_Oracle_ElsUtils_Cipher_Decrypt(
    const uint8_t *data, size_t data_size, mcuxClEls_KeyIndex_t tfmKekKeyIdx, const uint8_t *iv, uint8_t *pOut)
{
    mcuxClEls_CipherOption_t cipher_options = {0U};
    cipher_options.bits.cphmde              = MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CBC;
    cipher_options.bits.dcrpt               = MCUXCLELS_CIPHER_DECRYPT;

    // We use CSS in a mode where it will not output its state, so casting away
    // the const is safe here.
    uint8_t *state = (uint8_t *)iv;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result, token,
        mcuxClEls_Cipher_Async(cipher_options, tfmKekKeyIdx, NULL, (size_t)0u, data, data_size, state, pOut));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cipher_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PRINTF("mcuxClEls_Cipher_Async failed: 0x%x\r\n", result);
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PRINTF("mcuxClEls_Cipher_Async LimitedWaitForOperation failed: 0x%x", result);
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return PSA_SUCCESS;
}
