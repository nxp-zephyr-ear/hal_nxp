/*
 * Copyright 2023 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */


#include <stdint.h>

__attribute__ ((__section__(".fw_cpu2_ble"), used))
const uint8_t fw_cpu2_ble[] = {
    #include <rw61x_ble_fw.bin.inc>
};

