/*--------------------------------------------------------------------------*/
/* Copyright 2021-2023 NXP                                                  */
/*                                                                          */
/* NXP Confidential. This software is owned or controlled by NXP and may    */
/* only be used strictly in accordance with the applicable license terms.   */
/* By expressly accepting such terms or by downloading, installing,         */
/* activating and/or otherwise using the software, you are agreeing that    */
/* you have read, and that you agree to comply with and are bound by, such  */
/* license terms. If you do not agree to be bound by the applicable license */
/* terms, then you may not retain, install, activate or otherwise use the   */
/* software.                                                                */
/*--------------------------------------------------------------------------*/

/**
 *
 * @file:	size.c
 * @brief:	This file contains objects which will be used to measure size of particular types.
 *
 */

#include <mcuxClCore_Platform.h>
#include <mcuxCsslAnalysis.h>
#include <internal/mcuxClAeadModes_Internal.h>
/* *********************************************************** */
/* Work area and ctx sizes.                                    */
/* All work area size shall be a multiple of CPU wordsize.     */
/* *********************************************************** */




#include <internal/mcuxClAeadModes_Els_Types.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile uint8_t mcuxClAeadModes_WorkArea[MCUXCLAEADMODES_INTERNAL_ALIGN_SIZE_TO_CPUWORDS(1)];
volatile uint8_t mcuxClAead_OneShot[MCUXCLAEADMODES_INTERNAL_ALIGN_SIZE_TO_CPUWORDS(sizeof(mcuxClAeadModes_Context_t))];
MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()


MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile struct mcuxClAeadModes_Context mcuxClAeadModes_Context;
MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
