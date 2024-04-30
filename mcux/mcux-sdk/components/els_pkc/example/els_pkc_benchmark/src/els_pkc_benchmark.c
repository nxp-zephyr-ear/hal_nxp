/*
 * Copyright 2023 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "app.h"
#include "els_pkc_bm_symmetric.h"
#include "els_pkc_bm_asymmetric.h"
#include "els_pkc_bm_hash.h"
#include "els_pkc_bm_mac.h"
#include "mcux_els.h" // Power Down Wake-up Init
#include "mcux_pkc.h" // Power Down Wake-up Init
#if defined(FSL_FEATURE_SOC_TRNG_COUNT) && (FSL_FEATURE_SOC_TRNG_COUNT > 0)
#include "fsl_trng.h"
#endif

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
static void CRYPTO_InitHardware(void)
{
    status_t status;

    status = ELS_PowerDownWakeupInit(ELS);
    if (status != kStatus_Success)
    {
        PRINTF("ELS_PowerDownWakeupInit(ELS) failed\r\n");
    }
    /* Enable PKC related clocks and RAM zeroize */
    status = PKC_PowerDownWakeupInit(PKC);
    if (status != kStatus_Success)
    {
        PRINTF("ELS_PowerDownWakeupInit(PKC) failed\r\n");
    }
#if defined(FSL_FEATURE_SOC_TRNG_COUNT) && (FSL_FEATURE_SOC_TRNG_COUNT > 0)
    /* Initilize the TRNG driver */
    {
        trng_config_t trngConfig;
        /* Get default TRNG configs*/
        TRNG_GetDefaultConfig(&trngConfig);
        /* Set sample mode of the TRNG ring oscillator to Von Neumann, for better random data.*/
        /* Initialize TRNG */
        TRNG_Init(TRNG, &trngConfig);
    }
#endif
}

/*!
 * @brief Main function
 */
int main(void)
{
    /* Init hardware */
    BOARD_InitHardware();
    CRYPTO_InitHardware();

    SysTick_Config(CLOCK_GetCoreSysClkFreq() / 1000U);
    /* Print BM information */
    PRINTF("#################################\r\n");
    PRINTF("#\r");
    PRINTF("\t\t\t\t#\r\n");
    PRINTF("#\r");
    PRINTF("#\tSTART OF BENCHMARK\t#\r\n");
    PRINTF("#\r");
    PRINTF("\t\t\t\t#\r\n");
    PRINTF("#################################\r\n");
    PRINTF("SYSTEM FREQUENCY: %d MHZ\r\n", CLOCK_GetCoreSysClkFreq() / 1000000U);
    PRINTF("BM INFORMATION:\r\n");
    PRINTF("   -EXPERIMENTAL CACHING (AES, AEAD, SHA, MAC) WITH MULTIPLE BLOCKS\r\n");
    PRINTF("   -SINGLE BLOCK: 1 * BLOCK_SIZE BLOCK\r\n");
    PRINTF("   -MULTIPLE BLOCKS: 1024 * BLOCK_SIZE BLOCKS\r\n");
    PRINTF("   -SMALL MESSAGE: 64 BYTE\r\n");
    PRINTF("   -LARGE MESSAGE: 2048 BYTE\r\n");
    PRINTF("   -AES BLOCK SIZE: 16 BYTE\r\n");
    PRINTF("   -SHA-256 BLOCK SIZE: 64 BYTE\r\n");
    PRINTF("   -SHA-384 BLOCK SIZE: 128 BYTE\r\n");
    PRINTF("   -SHA-512 BLOCK SIZE: 128 BYTE\r\n");
    PRINTF("   -FOR AES-CCM-192 DOING FIRST CBC AND THEN CTR, BECAUSE NO AES-CCM-192 SUPPORTED BY ELS_PKC\r\n");
    PRINTF("\r\n\n");

    /* Run tests for DSA asymmetric-key cryptographic algorithms */
    run_tests_asymmetric();

    /* Run tests for AES symmetric-key cryptographic algorithms */
    run_tests_symmetric();

    /* Run tests for SHA hash algorithms */
    run_tests_hashing();

    /* Run tests for MAC algorithms */
    run_tests_mac();

    while (1)
    {
        char ch = GETCHAR();
        PUTCHAR(ch);
    }
}
