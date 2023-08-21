/*
 * Copyright 2022-2023 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _FWK_CONFIG_H_
#define _FWK_CONFIG_H_

#include "mflash_drv.h" /* TODO remove this dependency */

#ifndef gPlatformUseHwParameter_d
#define gPlatformUseHwParameter_d 0
#endif

#ifndef gPlatformDisableBleLowPower_d
#define gPlatformDisableBleLowPower_d 0
#endif

#ifndef gPlatformDisableSetBtCalData_d
#define gPlatformDisableSetBtCalData_d 0
#endif

#ifndef gPlatformDisableSetBtCalDataAnnex100_d
#define gPlatformDisableSetBtCalDataAnnex100_d 1
#endif

#ifndef gPlatformEnableTxPowerChangeWithCountry_d
#define gPlatformEnableTxPowerChangeWithCountry_d 0
#endif

/*
 * gPlatformSetAntDiversity_d
 * value is 0, enable ant1(share antenna with annex100),or enable ant2 with external FEM(ble only case)
 * value is 1, enable ant3(diversity with annex100)
 * value is 2, enable ant4(diversity with annex100)
 */
#ifndef gPlatformSetAntDiversity_d
#define gPlatformSetAntDiversity_d 0
#endif

#define PLATFORM_EXTFLASH_SECTOR_SIZE MFLASH_SECTOR_SIZE
#define PLATFORM_EXTFLASH_PAGE_SIZE   MFLASH_PAGE_SIZE
#define PLATFORM_EXTFLASH_TOTAL_SIZE  FLASH_SIZE /* SPI NOR Flash is an MX25U51245G (512Mb) */

#endif /* _FWK_CONFIG_H_ */
