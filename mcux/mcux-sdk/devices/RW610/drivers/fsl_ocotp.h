/*
 * Copyright 2021-2022 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __FSL_OCOTP_H_
#define __FSL_OCOTP_H_

#include "fsl_common.h"
/*!
 * @addtogroup ocotp
 * @{
 */

/*! @file */

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*! @name Driver version */
/*@{*/
/*! @brief OCOTP driver version 2.0.1. */
#define FSL_OCOTP_DRIVER_VERSION (MAKE_VERSION(2, 0, 1))
/*@}*/

/*! @brief OCOTP unique ID length. */
#define FSL_OCOTP_UID_LENGTH 16U

/*! @brief OTP Status Group */
enum
{
    kStatusGroup_OtpGroup = 0x210,
};

/*! @brief OTP Error Status definitions */
enum
{
    kStatus_OTP_InvalidAddress = MAKE_STATUS(kStatusGroup_OtpGroup, 1), /*!< Invalid OTP address */
    kStatus_OTP_Timeout        = MAKE_STATUS(kStatusGroup_OtpGroup, 7), /*!< OTP operation time out */
};

/*******************************************************************************
 * API
 ******************************************************************************/
#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @brief Initialize OTP controller
 *
 * This function enables OTP Controller clock.
 *
 * @return kStatus_Success
 */
status_t OCOTP_OtpInit(void);

/*!
 * @brief De-Initialize OTP controller
 *
 * This functin disables OTP Controller Clock.
 * @return kStatus_Success
 */
status_t OCOTP_OtpDeinit(void);

/*!
 * @brief Read Fuse value from OTP Fuse Block
 *
 * This function read fuse data from OTP Fuse block to specified data buffer.
 *
 * @param addr Fuse address
 * @param data Buffer to hold the data read from OTP Fuse block
 * @return kStatus_Success - Data read from OTP Fuse block successfully
 *         kStatus_OTP_Timeout - OTP read timeout
 *         kStatus_InvalidArgument - data pointer is invalid
 */
status_t OCOTP_OtpFuseRead(uint32_t addr, uint32_t *data);

/*!
 * @brief Read unique ID from OTP Fuse Block
 *
 * This function read unique ID from OTP Fuse block to specified data buffer.
 *
 * @param uid The buffer to store unique ID, buffer byte length is FSL_OCOTP_UID_LENGTH.
 * @param idLen[in/out] The unique ID byte length. Set the length to read, return the length read out.
 * @return kStatus_Success - Data read from OTP Fuse block successfully
 *         kStatus_OTP_Timeout - OTP read timeout
 *         kStatus_InvalidArgument - data pointer is invalid
 */
status_t OCOTP_ReadUniqueID(uint8_t *uid, uint32_t *idLen);

#if defined(__cplusplus)
}
#endif

/*! @}*/

#endif /* __FSL_OCOTP_H_ */
