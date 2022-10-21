/*
 * Copyright 2021-2022 NXP
 *
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fsl_device_registers.h"
#include "fsl_ocotp.h"
#include "fsl_reset.h"
#include "fsl_clock.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/* All error masks in STATUS1 register except for SEC (Single error correction)
   When new error masks are added this macro needs to be updated */
#define OTP_STATUS1_ERRORS_MASK                                                                                       \
    (OCOTP_OTP_NONMASK_STATUS1_NONMASK_PBRICK_ERR_MASK | OCOTP_OTP_NONMASK_STATUS1_NONMASK_OTP_STATE_ERR_MASK |       \
     OCOTP_OTP_NONMASK_STATUS1_NONMASK_DED_RELOAD_MASK | OCOTP_OTP_NONMASK_STATUS1_NONMASK_DED_MASK |                 \
     OCOTP_OTP_NONMASK_STATUS1_NONMASK_CRC_LUT_SEL_ERR_MASK |                                                         \
     OCOTP_OTP_NONMASK_STATUS1_NONMASK_CRC_ADDRESS_RANGE_ERR_MASK |                                                   \
     OCOTP_OTP_NONMASK_STATUS1_NONMASK_CRC_WRITE_PROTECT_ERR_MASK |                                                   \
     OCOTP_OTP_NONMASK_STATUS1_NONMASK_CRC_SECURTY_PROTECT_ERR_MASK |                                                 \
     OCOTP_OTP_NONMASK_STATUS1_NONMASK_WRITE_ERR_MASK | OCOTP_OTP_NONMASK_STATUS1_NONMASK_LOAD_ERR_MASK |             \
     OCOTP_OTP_NONMASK_STATUS1_NONMASK_COUNTER_ERR_MASK | OCOTP_OTP_NONMASK_STATUS1_NONMASK_BITPROTECT_ERR_MASK |     \
     OCOTP_OTP_NONMASK_STATUS1_NONMASK_PRNG_O_FAULT_MASK | OCOTP_OTP_NONMASK_STATUS1_NONMASK_ECC_ZEROIZED_ERR_MASK |  \
     OCOTP_OTP_NONMASK_STATUS1_NONMASK_FUSE_ACCESS_ERR_MASK | OCOTP_OTP_NONMASK_STATUS1_NONMASK_RELOAD_REQ_ERR_MASK | \
     OCOTP_OTP_NONMASK_STATUS1_NONMASK_WRITE_DURING_RELOAD_ERR_MASK |                                                 \
     OCOTP_OTP_NONMASK_STATUS1_NONMASK_SHADOW_HVF_READ_ERR_MASK |                                                     \
     OCOTP_OTP_NONMASK_STATUS1_NONMASK_SHADOW_HVF_WRITE_ERR_MASK |                                                    \
     OCOTP_OTP_NONMASK_STATUS1_NONMASK_SHADOW_SRAM_READ_ERR_MASK |                                                    \
     OCOTP_OTP_NONMASK_STATUS1_NONMASK_SHADOW_SRAM_WRITE_ERR_MASK |                                                   \
     OCOTP_OTP_NONMASK_STATUS1_NONMASK_FUSE_READ_ERR_MASK | OCOTP_OTP_NONMASK_STATUS1_NONMASK_FUSE_PROG_ERR_MASK |    \
     OCOTP_OTP_NONMASK_STATUS1_NONMASK_SHADOW_NO_ACCESS_MASK)

/*******************************************************************************
 * Prototypes
 *******************************************************************************/
/* @brief Wait until OTP controller is idle */
static status_t otp_wait_busy(void);

/* @brief Clear all error status */
static void otp_clear_status(void);

/* @brief Read nonmask_status1 register and returns precise result*/
static status_t otp_get_nonmask_status_result(void);

/*******************************************************************************
 * Code
 ******************************************************************************/
static status_t otp_get_nonmask_status_result(void)
{
    uint32_t status_register = OCOTP->OTP_NONMASK_STATUS1;
    status_t status;
    int32_t i;

    do
    {
        if ((status_register & OTP_STATUS1_ERRORS_MASK) != 0U)
        {
            for (i = 0; i < 32; i++)
            {
                if (((1UL << (uint32_t)i) & status_register) != 0U)
                {
                    status = MAKE_STATUS(kStatusGroup_OtpGroup, i);
                    break;
                }
            }
        }
        status = kStatus_Success;
    } while (false);

    return status;
}

static status_t otp_wait_busy(void)
{
    /*
     * Assume core clock is 300MHz, the general fuse operation should not exceed 100ms
     * Maximum allowed ticks is 300MHz / 10
     * The below loop needs at least 4 CPU cycles, so the timeout rounds for below loop is 300MHz / 10 / 4
     */
    uint32_t timeout = 300U * 1000U * 1000U / 10U / 4U;
    status_t status;

    while (((OCOTP->OTP_STATUS & OCOTP_OTP_STATUS_BUSY_MASK) != 0U) && (timeout > 0U))
    {
        timeout--;
    }

    if (timeout < 1U)
    {
        status = kStatus_OTP_Timeout;
    }
    else
    {
        status = kStatus_Success;
    }

    return status;
}

static void otp_clear_status(void)
{
    /* Write 1s to clear all error status */
    OCOTP->OTP_STATUS          = OCOTP_OTP_STATUS_PROGFAIL_MASK;
    OCOTP->OTP_NONMASK_STATUS1 = OTP_STATUS1_ERRORS_MASK;
}

status_t OCOTP_OtpInit(void)
{
    CLOCK_EnableClock(kCLOCK_Otp);
    RESET_PeripheralReset(kOTP_RST_SHIFT_RSTn);

    return kStatus_Success;
}

status_t OCOTP_OtpDeinit(void)
{
    CLOCK_DisableClock(kCLOCK_Otp);
    RESET_SetPeripheralReset(kOTP_RST_SHIFT_RSTn);

    return kStatus_Success;
}

status_t OCOTP_OtpFuseRead(uint32_t addr, uint32_t *data)
{
    status_t status  = kStatus_InvalidArgument;
    uint32_t saveReg = OCOTP->OTP_PDN;

    OCOTP->OTP_PDN = 0;
    do
    {
        if (data == NULL)
        {
            break;
        }

        status = otp_wait_busy();
        if (status != kStatus_Success)
        {
            break;
        }

        otp_clear_status();

        /* Start reading */
        OCOTP->OTP_CTRL      = OCOTP_OTP_CTRL_ADDR(addr);
        OCOTP->OTP_READ_CTRL = OCOTP_OTP_READ_CTRL_READ(1);

        /* Wait until read completes */
        status = otp_wait_busy();
        if (status != kStatus_Success)
        {
            break;
        }

        /* Check whether errors happened or not. */
        status = otp_get_nonmask_status_result();
        if (status == kStatus_Success)
        {
            *data = OCOTP->OTP_READ_DATA;
        }

    } while (false);
    OCOTP->OTP_PDN = saveReg;

    return status;
}

status_t OCOTP_ReadUniqueID(uint8_t *uid, uint32_t *idLen)
{
    status_t status = kStatus_InvalidArgument;
    uint32_t offset = 0;
    uint32_t leftByte;
    uint32_t cpyByte;
    uint32_t data;

    do
    {
        if ((uid == NULL) || (idLen == NULL))
        {
            break;
        }

        (void)OCOTP_OtpInit();

        if ((*idLen) != 0U)
        {
            leftByte = *idLen;
            do
            {
                status = OCOTP_OtpFuseRead((offset / 4U) + 46U, &data);
                if (status != kStatus_Success)
                {
                    break;
                }
                cpyByte = (leftByte > 4U) ? 4U : leftByte;
                (void)memcpy((void *)&uid[offset], (void *)(uint8_t *)&data, cpyByte);
                leftByte -= cpyByte;
                offset += cpyByte;
            } while ((leftByte > 0U) && (offset < FSL_OCOTP_UID_LENGTH));
            *idLen -= leftByte;
        }
    } while (false);

    return status;
}
