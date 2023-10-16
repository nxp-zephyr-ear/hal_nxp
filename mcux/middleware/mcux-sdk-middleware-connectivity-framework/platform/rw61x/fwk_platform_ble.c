/* -------------------------------------------------------------------------- */
/*                           Copyright 2021-2023 NXP                          */
/*                            All rights reserved.                            */
/*                    SPDX-License-Identifier: BSD-3-Clause                   */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/*                                  Includes                                  */
/* -------------------------------------------------------------------------- */

#include <stdint.h>
#include <stdbool.h>

#ifdef __ZEPHYR__
#include <zephyr/kernel.h>
#else
#include "FreeRTOS.h"
#include "event_groups.h"
#include "semphr.h"
#include "fsl_debug_console.h"
#endif /* __ZEPHYR__ */

#include "fsl_loader.h"
#include "fsl_power.h"
#include "fsl_adapter_rpmsg.h"
#include "fsl_adapter_rfimu.h"
#include "fsl_os_abstraction.h"

#include "fwk_config.h"
#include "fwk_platform_ble.h"
#include "fwk_platform_ot.h"
#include "fwk_platform_coex.h"

#ifdef SERIAL_BTSNOOP
#include "sbtsnoop.h"
#endif

/* -------------------------------------------------------------------------- */
/*                               Private macros                               */
/* -------------------------------------------------------------------------- */
/* By default, wait maximum 1s for the controller to wake up */
#ifndef PLATFORM_BLE_WAKE_UP_TIMEOUT_TICKS

#ifdef __ZEPHYR__
#define PLATFORM_BLE_WAKE_UP_TIMEOUT_TICKS Z_TIMEOUT_MS(1000)
#else
#define PLATFORM_BLE_WAKE_UP_TIMEOUT_TICKS (1000U / portTICK_PERIOD_MS)
#endif/* __ZEPHYR__ */

#endif

#define HCI_COMMAND_PACKET              0x01U
#define HCI_EVENT_PACKET                0x04U
#define HCI_VENDOR_SPECIFIC_DEBUG_EVENT 0xFFU

#define HCI_CMD_PACKET_HEADER_LENGTH 3U
#define HCI_CMD_VENDOR_OCG           0x3FU

#define HCI_CMD_STORE_BT_CAL_DATA_OCF          0x61U
#define HCI_CMD_STORE_BT_CAL_DATA_PARAM_LENGTH 32U

#define HCI_CMD_STORE_BT_CAL_DATA_ANNEX100_OCF          0xFFU
#define HCI_CMD_STORE_BT_CAL_DATA_PARAM_ANNEX100_LENGTH 16U

#define HCI_CMD_SET_BT_SLEEP_MODE_OCF          0x23U
#define HCI_CMD_SET_BT_SLEEP_MODE_PARAM_LENGTH 3U

#define HCI_CMD_BT_HIU_HS_ENABLE_OCF 0x5A

#define HCI_CMD_BT_HOST_SLEEP_CONFIG_OCF          0x59U
#define HCI_CMD_BT_HOST_SLEEP_CONFIG_PARAM_LENGTH 2U

#define HCI_EVT_PS_SLEEP_OCF 0x20U

#define get_opcode(ocg, ocf) (((uint16_t)(ocg) & (uint16_t)0x3FU) << 10) | (uint16_t)((ocf)&0x3FFU)

/* The wake up done interrupt doesn't make any call to FreeRTOS API so it should
 * be safe to make it higher priority than configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY
 * so it is not masked in FreeRTOS critical sections */
#define MCI_WAKEUP_DONE_PRIORITY (1)

#define BLE_POWER_STATUS() (SOCCTRL->BLE_POWER_STATUS & 0x3U)
#define BLE_POWER_ON       (0U)
#define BLE_POWER_SLP      (2U)
#define BLE_POWER_OFF      (3U)

#define BLE_SMU_POWER_STATUS() (*((volatile uint32_t *)0x443C0000U))
#define BLE_SMU_POWER_OFF      (0x3131312AU)

/* Can change the macro BLE_VENDOR_EVENT_HANDLE to false to let HOST handle the Vendor Event,
 * like PowerSave Vendor Event */
#define BLE_VENDOR_EVENT_HANDLE (true)

#ifdef __ZEPHYR__

#ifndef PRINTF
#define PRINTF printk
#endif

#endif /* __ZEPHYR__ */

#define BLE_PS_DBG(...)      \
    do                       \
    {                        \
        PRINTF("[BLE_PS] "); \
        PRINTF(__VA_ARGS__); \
    } while (false);

/*
 * a.The following parameters are used in three cases,
 *    1.For share antenna case or ant2 with external FEM(ble only case).
 *    2.divesity case(enanble ant3)
 *    3.divesity case(enanble ant4)
 */
#if defined(gPlatformSetAntDiversity_d) && (gPlatformSetAntDiversity_d == 0)
// For share antenna case or ant2 with external FEM(ble only case)
#define BT_CAL_DATA_ANNEX_100_EPA_FEM_MASK_LOW_BYTE 0x02U
#define BT_CAL_DATA_ANNEX_100_LNA_FEM_MASK_LOW_BYTE 0x02U
#elif defined(gPlatformSetAntDiversity_d) && (gPlatformSetAntDiversity_d == 1)
// divesity case(enanble ant3)
#define BT_CAL_DATA_ANNEX_100_EPA_FEM_MASK_LOW_BYTE 0x0AU
#define BT_CAL_DATA_ANNEX_100_LNA_FEM_MASK_LOW_BYTE 0x0AU
#elif defined(gPlatformSetAntDiversity_d) && (gPlatformSetAntDiversity_d == 2)
// divesity case(enanble ant4)
#define BT_CAL_DATA_ANNEX_100_EPA_FEM_MASK_LOW_BYTE 0x06U
#define BT_CAL_DATA_ANNEX_100_LNA_FEM_MASK_LOW_BYTE 0x06U
#endif

/*
 * The following parameters are used in two cases
 */
#if defined(gPlatformDisableSetBtCalDataAnnex100_d) && (gPlatformDisableSetBtCalDataAnnex100_d == 1)
// For dual ant case
#define BT_CAL_DATA_ANNEX_FRONT_END_LOSS 0x02U
#elif defined(gPlatformDisableSetBtCalDataAnnex100_d) && (gPlatformDisableSetBtCalDataAnnex100_d == 0)
// For share antenna case or diversty case(ble only case)
#define BT_CAL_DATA_ANNEX_FRONT_END_LOSS 0x03U
#endif

/*
 *  After send annex55 to CPU2, CPU2 need reset,
 *a delay of at least 20ms is required to continue sending annex100
 */
#if defined(gPlatformDisableSetBtCalDataAnnex100_d) && (gPlatformDisableSetBtCalDataAnnex100_d == 0)
#ifdef __ZEPHYR__
#define BLE_RESET_DELAY_TICKS Z_TIMEOUT_MS(20)
#else
#define BLE_RESET_DELAY_TICKS (20U / portTICK_PERIOD_MS)
#endif /* __ZEPHYR__ */
#endif

/* -------------------------------------------------------------------------- */
/*                                Private types                               */
/* -------------------------------------------------------------------------- */

/*!
 * \brief Controller power states enum
 *
 */
typedef enum
{
    ble_awake_state,
    ble_asleep_state
} ble_ps_t;

/*!
 * \brief Controller power state HCI vendor events
 *
 */
typedef enum
{
    ble_asleep_event = 0x1U,
    ble_awake_event  = 0x2U
} ble_ps_event_t;

/* -------------------------------------------------------------------------- */
/*                             Private prototypes                             */
/* -------------------------------------------------------------------------- */

/*!
 * \brief Init HCI link with BLE controller
 *
 * \return int return status: >=0 for success, <0 for errors
 */
static int PLATFORM_InitHciLink(void);

/*!
 * \brief Terminate HCI link with BLE controller
 *
 * \return int return status: >=0 for success, <0 for errors
 */
static int PLATFORM_TerminateHciLink(void);

/*!
 * \brief Return HCI link status
 *
 * \return true Link is ready
 * \return false Link is not ready yet
 */
static bool PLATFORM_IsHciLinkReady(void);

/*!
 * \brief Checks if the BLE controller is awake or asleep
 *
 * \return true BLE Controller is awake
 * \return false BLE Controller is asleep
 */
static bool PLATFORM_IsBleAwake(void);

/*!
 * \brief RPMSG Rx callback used to receive HCI messages from Controller
 *
 * \param[in] param Usually NULL
 * \param[in] data pointer to data buffer
 * \param[in] len size of the data
 * \return hal_rpmsg_return_status_t tells RPMSG to free or hold the buffer
 */
static hal_rpmsg_return_status_t PLATFORM_HciRpmsgRxCallback(void *param, uint8_t *data, uint32_t len);

#ifndef __ZEPHYR__
/*!
 * \brief Set BT Cal Data to Controller
 *
 * \return int return status: >=0 for success, <0 for errors
 */
static int PLATFORM_SetBtCalData(void);

#if !defined(gPlatformDisableSetBtCalDataAnnex100_d) || (gPlatformDisableSetBtCalDataAnnex100_d == 0)
/*!
 * \brief Set BT Cal Data Annex100 to Controller
 *
 * \return int return status: >=0 for success, <0 for errors
 */
static int PLATFORM_SetBtCalDataAnnex100(void);
#endif /* gPlatformDisableSetBtCalDataAnnex100_d */

/*!
 * \brief Send Host sleep config to Controller
 *
 * \return int return status: >=0 for success, <0 for errors
 */
static int PLATFORM_BleSetHostSleepConfig(void);
#endif /* __ZEPHYR__ */

/*!
 * \brief Handles supported Vendor Specific events received from Controller
 *        If the received event is not supported, it will return false, so the
 *        called can send the packet to upper layers (host stack or application)
 *
 * \param[in] eventData Pointer to event data buffer
 * \param[in] len size of the data
 * \return true The event has been handled
 * \return false The event has NOT been handled
 */
static bool PLATFORM_HandleHciVendorEvent(uint8_t *eventData, uint32_t len);

/*!
 * \brief Handle power state event from BLE Controller
 *
 * \param[in] psEvent event type received
 * \return int return status: >=0 for success, <0 for errors
 */
static int PLATFORM_HandleBlePowerStateEvent(ble_ps_event_t psEvent);

void BLE_MCI_WAKEUP_DONE0_DriverIRQHandler(void);

static void PLATFORM_FillInHciCmdMsg(uint8_t *pbuf, uint16_t opcode, uint8_t msg_sz, const uint8_t *msg_payload);

/* -------------------------------------------------------------------------- */
/*                               Private memory                               */
/* -------------------------------------------------------------------------- */

static RPMSG_HANDLE_DEFINE(hci_rpmsg_handle);
static hal_rpmsg_config_t hci_rpmsg_config = {
    .local_addr  = 30,
    .remote_addr = 40,
    .imuLink     = (uint8_t)kIMU_LinkCpu2Cpu3,
    .callback    = PLATFORM_HciRpmsgRxCallback,
    .param       = NULL,
};

static bool               initialized    = false;
static bool               hciInitialized = false;
static volatile ble_ps_t  blePowerState  = ble_awake_state;
#ifdef __ZEPHYR__
static struct k_event wakeUpEventGroup;
static struct k_mutex  bleMutexHandle;
#else
static EventGroupHandle_t wakeUpEventGroup;
static SemaphoreHandle_t  bleMutexHandle;
#endif /* __ZEPHYR__ */
static void (*hci_rx_callback)(uint8_t packetType, uint8_t *data, uint16_t len);

/* -------------------------------------------------------------------------- */
/*                                Public memory                               */
/* -------------------------------------------------------------------------- */

const uint8_t hci_cal_data_params[HCI_CMD_STORE_BT_CAL_DATA_PARAM_LENGTH] = {
    0x00U,                            //  Sequence Number : 0x00
    0x00U,                            //  Action : 0x00
    0x01U,                            //  Type : Not use CheckSum
    0x1CU,                            //  File Length : 0x1C
    0x37U,                            //  BT Annex Type : BT CFG
    0x71U,                            //  Checksum : 0x71
    0x1CU,                            //  Annex Length LSB: 0x001C
    0x00U,                            //  Annex Length MSB: 0x001C
    0xFFU,                            //  Pointer For Next Annex[0] : 0xFFFFFFFF
    0xFFU,                            //  Pointer For Next Annex[1] : 0xFFFFFFFF
    0xFFU,                            //  Pointer For Next Annex[2] : 0xFFFFFFFF
    0xFFU,                            //  Pointer For Next Annex[3] : 0xFFFFFFFF
    0x01U,                            //  Annex Version : 0x01
    0x7CU,                            //  External Xtal Calibration Value : 0x7C
    0x04U,                            //  Initial TX Power : 0x04
    BT_CAL_DATA_ANNEX_FRONT_END_LOSS, //  Front End Loss : 0x02 or 0x03
    0x28U,                            //  BT Options :
                                        //              BIT[0] Force Class 2 operation = 0
                                        //              BIT[1] Disable Pwr Control for class 2= 0
                                        //              BIT[2] MiscFlag(to indicagte external XTAL) = 0
                                        //              BIT[3] Used Internal Sleep Clock = 1
                                        //              BIT[4] BT AOA localtion support = 0
                                        //              BIT[5] Force Class 1 mode = 1
                                        //              BIT[7:6] Reserved
    0x00U,                            //  AOANumberOfAntennas: 0x00
    0x00U,                            //  RSSI Golden Low : 0
    0x00U,                            //  RSSI Golden High : 0
    0xC0U,                            //  UART Baud Rate[0] : 0x002DC6C0(3000000)
    0xC6U,                            //  UART Baud Rate[1] : 0x002DC6C0(3000000)
    0x2DU,                            //  UART Baud Rate[2] : 0x002DC6C0(3000000)
    0x00U,                            //  UART Baud Rate[3] : 0x002DC6C0(3000000)
    0x00U,                            //  BdAddress[0] : 0x000000000000
    0x00U,                            //  BdAddress[1] : 0x000000000000
    0x00U,                            //  BdAddress[2] : 0x000000000000
    0x00U,                            //  BdAddress[3] : 0x000000000000
    0x00U,                            //  BdAddress[4] : 0x000000000000
    0x00U,                            //  BdAddress[5] : 0x000000000000
    0xF0U,                            //  Encr_Key_Len[3:0]: MinEncrKeyLen = 0x0
                                        //  Encr_Key_Len[7:4]: MaxEncrKeyLen = 0xF
#if defined(gPlatformEnableTxPowerChangeWithCountry_d) && (gPlatformEnableTxPowerChangeWithCountry_d == 0)
    0x00U, //  RegionCode : 0x00
#else
    0x00U, //  Reserved : 0x00
#endif /* gPlatformEnableTxPowerChangeWithCountry_d */
};

/*
 * a.The following parameters are used in three cases,
 *    1.For share antenna case or ant2 with external FEM(ble only case).
 *    2.divesity case(enanble ant3)
 *    3.divesity case(enanble ant4)
 */
uint8_t hci_cal_data_annex100_params[HCI_CMD_STORE_BT_CAL_DATA_PARAM_ANNEX100_LENGTH] = {
    /*                   BT_HW_INFO   START              */
    0x64U, //  Annex Type : 0x64
    0x00U, //  CheckSum: Annex100 ignores checksum
    0x10U, //  Length-In-Byte : 0x0010
    0x00U, //  Length-In-Byte : 0x0010
    0xFFU, // Pointer for next annex structure : 0xFFFFFFFF
    0xFFU, // Pointer for next annex structure : 0xFFFFFFFF
    0xFFU, // Pointer for next annex structure : 0xFFFFFFFF
    0xFFU, // Pointer for next annex structure : 0xFFFFFFFF
    0x01U, // Ext_PA Gain : Bit[7:1]   Ext_PA Present : Bit[0]
#if defined(gPlatformEnableTxPowerChangeWithCountry_d) && (gPlatformEnableTxPowerChangeWithCountry_d == 0)
    0x00U, // Ext_Ant Gain : Bit[7:1]   Ext_Ant Present : Bit[0]
#else
    0x00U, // Reserved
#endif                                               /* gPlatformEnableTxPowerChangeWithCountry_d */
    BT_CAL_DATA_ANNEX_100_EPA_FEM_MASK_LOW_BYTE, // BT_HW_INFO_EPA_FEM_Mask
    0x00U,                                       // BT_HW_INFO_EPA_FEM_Mask
    0x00U,                                       // Ext_LNA Present : Bit[0]   Ext_LNA Gain : Bit[7:1]
    0x00U,                                       // Reserved
    BT_CAL_DATA_ANNEX_100_LNA_FEM_MASK_LOW_BYTE, // BT / LE ext LNA FEM BITMASK
    0x00U,                                       // BT / LE ext LNA FEM BITMASK
    /*                   BT_HW_INFO   END              */
};

/* -------------------------------------------------------------------------- */
/*                              Public functions                              */
/* -------------------------------------------------------------------------- */

int PLATFORM_InitBle(void)
{
    int ret = 0;

    /* PLATFORM_InitBle can be called from OT or Ethermind context in multi mode applications
     * The 'initialized' variable will be set to true only when the initialization is complete
     * We have to protect the initialization flow with a mutex to make sure the first task completes the initialization
     * before the second reads 'initialized' */
#ifdef __ZEPHYR__
    int status = 0;

    k_mutex_init(&bleMutexHandle);
    status = k_mutex_lock(&bleMutexHandle, K_FOREVER);
    assert(status == 0);
#else
    BaseType_t status;

    if (bleMutexHandle == NULL)
    {
        bleMutexHandle = xSemaphoreCreateMutex();
        assert(bleMutexHandle != NULL);
    }

    status = xSemaphoreTake(bleMutexHandle, portMAX_DELAY);
    assert(status == pdTRUE);
#endif /* __ZEPHYR__ */

    do
    {
        if (initialized == true)
        {
            break;
        }
#ifdef __ZEPHYR__
        k_event_init(&wakeUpEventGroup);
#else
        wakeUpEventGroup = xEventGroupCreate();
        assert(wakeUpEventGroup != NULL);
#endif /* __ZEPHYR__ */

        /* Initialize BLE controller */
        ret = PLATFORM_InitControllers(connBle_c);
        if (ret != 0)
        {
            ret = -1;
            break;
        }

        /* Initialize HCI link with BLE CPU */
        ret = PLATFORM_InitHciLink();
        if (ret != 0)
        {
            ret = -2;
            break;
        }

        /* Configure BLE Wakeup done interrupt */
        NVIC_SetPriority(BLE_MCI_WAKEUP_DONE0_IRQn, MCI_WAKEUP_DONE_PRIORITY);

        initialized = true;
    } while (false);
#ifdef __ZEPHYR__
    status = k_mutex_unlock(&bleMutexHandle);
    assert(status == 0);
#else
    status = xSemaphoreGive(bleMutexHandle);
    assert(status == pdTRUE);
#endif /* __ZEPHYR__ */
    (void)status;

    return ret;
}

int PLATFORM_TerminateBle(void)
{
    int ret = 0;

    do
    {
        if (initialized == false)
        {
            break;
        }

        if (PLATFORM_TerminateHciLink() != 0)
        {
            ret = -1;
            break;
        }

        if (PLATFORM_TerminateControllers((uint8_t)connBle_c) != 0) /* MISRA CID 26829044 */
        {
            ret = -2;
            break;
        }

#ifndef __ZEPHYR__
        vEventGroupDelete(wakeUpEventGroup);
#endif

        initialized = false;
    } while (false);

    return ret;
}

int PLATFORM_ResetBle(void)
{
    int ret = 0;

    do
    {
        if ((PLATFORM_GetRunningControllers() & conn802_15_4_c) != 0U)
        {
            /* Currently the CPU2 is running the combo firmware, so we should reset using this firmware */
            PLATFORM_ResetOt();
        }
        else
        {
            if (PLATFORM_TerminateBle() != 0)
            {
                ret = -1;
                break;
            }

            if (PLATFORM_InitBle() != 0)
            {
                ret = -2;
                break;
            }
        }

        /* after re-init cpu2, Reset blePowerState to ble_awake_state. */
        blePowerState = ble_awake_state;

    } while (false);

    return ret;
}

int PLATFORM_StartHci(void)
{
    int ret = 0;

    do
    {
        if (hciInitialized == true)
        {
            break;
        }

        while (PLATFORM_IsHciLinkReady() != true)
        {
        }

#ifndef __ZEPHYR__
#if !defined(gPlatformDisableSetBtCalData_d) || (gPlatformDisableSetBtCalData_d == 0)
        /* Send the BT Cal Data to Controller */
        (void)PLATFORM_SetBtCalData();
#if !defined(gPlatformDisableSetBtCalDataAnnex100_d) || (gPlatformDisableSetBtCalDataAnnex100_d == 0)
        /* After send annex55 to CPU2, CPU2 need reset,
           a delay of at least 20ms is required to continue sending annex100*/
#ifdef __ZEPHYR__
        k_sleep(BLE_RESET_DELAY_TICKS);
#else
        vTaskDelay(BLE_RESET_DELAY_TICKS);
#endif /* __ZEPHYR__ */
        /* Send the BT Cal Data annex100 to Controller */
        (void)PLATFORM_SetBtCalDataAnnex100();
#endif
#endif

        (void)PLATFORM_BleSetHostSleepConfig();

#if !defined(gPlatformDisableBleLowPower_d) || (gPlatformDisableBleLowPower_d == 0)
        /* Allow Controller to enter low power */
        (void)PLATFORM_EnableBleLowPower();
#endif
#endif /* __ZEPHYR__ */

        hciInitialized = true;
    } while (false);

    return ret;
}

int PLATFORM_SetHciRxCallback(void (*callback)(uint8_t packetType, uint8_t *data, uint16_t len))
{
    int ret = 0;

    hci_rx_callback = callback;

    return ret;
}

int PLATFORM_SendHciMessage(uint8_t *msg, uint32_t len)
{
    int ret = 0;

#ifdef SERIAL_BTSNOOP
    sbtsnoop_write_hci_pkt(msg[0U], 0U, &msg[1], (len - 1U));
#endif

    do
    {
        /* Before sending a HCI message, we have to make sure the Controller is
         * awake */
        ret = PLATFORM_RequestBleWakeUp();
        if (ret != 0)
        {
            ret = -1;
            break;
        }

        /* Send HCI Packet through RPMSG channel */
        if (HAL_RpmsgSend(hci_rpmsg_handle, msg, len) != kStatus_HAL_RpmsgSuccess)
        {
            ret = -2;
            break;
        }

        /* Release the wake up request now */
        ret = PLATFORM_ReleaseBleWakeUp();
        if (ret != 0)
        {
            ret = -3;
            break;
        }
    } while (false);

    return ret;
}

int PLATFORM_EnableBleLowPower(void)
{
    int           ret = 0;
    uint8_t       buffer[1 + HCI_CMD_PACKET_HEADER_LENGTH + HCI_CMD_SET_BT_SLEEP_MODE_PARAM_LENGTH];
    uint16_t      opcode = get_opcode(HCI_CMD_VENDOR_OCG, HCI_CMD_SET_BT_SLEEP_MODE_OCF);
    const uint8_t params[HCI_CMD_SET_BT_SLEEP_MODE_PARAM_LENGTH] = {
        0x02U, // Auto sleep enable
        0x00U, // Idle timeout LSB
        0x00U  // Idle timeout MSB
    };

    PLATFORM_FillInHciCmdMsg(&buffer[0], opcode, (uint8_t)sizeof(params), params);

    ret = PLATFORM_SendHciMessage(buffer, sizeof(buffer));
    if (ret != 0)
    {
        ret = -1;
    }

    return ret;
}

int PLATFORM_DisableBleLowPower(void)
{
    int           ret = 0;
    uint8_t       buffer[1 + HCI_CMD_PACKET_HEADER_LENGTH + HCI_CMD_SET_BT_SLEEP_MODE_PARAM_LENGTH];
    uint16_t      opcode = get_opcode(HCI_CMD_VENDOR_OCG, HCI_CMD_SET_BT_SLEEP_MODE_OCF);
    const uint8_t params[HCI_CMD_SET_BT_SLEEP_MODE_PARAM_LENGTH] = {
        0x03U, // Auto sleep disable
        0x00U, // Idle timeout LSB
        0x00U  // Idle timeout MSB
    };

    PLATFORM_FillInHciCmdMsg(buffer, opcode, (uint8_t)sizeof(params), params);

    ret = PLATFORM_SendHciMessage(buffer, sizeof(buffer));
    if (ret != 0)
    {
        ret = -1;
    }

    return ret;
}

int PLATFORM_RequestBleWakeUp(void)
{
    int         ret = 0;

    /* The request can come from different tasks (BLE or OT), but only one request should be performed at the same
     * time. The mutex ensures only one task is waking up the CPU2 at a time. */
#ifdef __ZEPHYR__
    uint32_t events = 0;
    if (k_mutex_lock(&bleMutexHandle, K_FOREVER) != 0)
    {
        /* shouldn't happen */
        assert(0);
    }
#else
    EventBits_t eventBits;
    if (xSemaphoreTake(bleMutexHandle, portMAX_DELAY) != pdTRUE)
    {
        /* shouldn't happen */
        assert(0);
    }
#endif /* __ZEPHYR__ */
    if (PLATFORM_IsBleAwake() == false)
    {
        /* Controller is in low power, we need to wake it up with PMU
         * and wait for the wake up done interrupt to make sure it is
         * completely awake and ready to receive a message */
        NVIC_EnableIRQ(BLE_MCI_WAKEUP_DONE0_IRQn);

        /* Wake up BLE core with PMU BLE_WAKEUP bit
         * This bit is maintained until we receive a BLE_MCI_WAKEUP_DONE0
         * interrupt */
        PMU_EnableBleWakeup(0x1U);

        /* Suspend the current task waiting for the Controller to be awake */
#ifdef __ZEPHYR__
        events = k_event_wait(&wakeUpEventGroup, ble_awake_event, 1, PLATFORM_BLE_WAKE_UP_TIMEOUT_TICKS);
        if ((events & (uint32_t)ble_awake_event) == 0)
        {
            ret = -1;
        }
#else
        eventBits = xEventGroupWaitBits(wakeUpEventGroup, (EventBits_t)ble_awake_event, pdTRUE, pdFALSE,
                                        PLATFORM_BLE_WAKE_UP_TIMEOUT_TICKS);
        if ((eventBits & (EventBits_t)ble_awake_event) == 0)
        {
            ret = -1;
        }
#endif /* __ZEPHYR__ */
    }

#ifdef __ZEPHYR__
    k_mutex_unlock(&bleMutexHandle);
#else
    xSemaphoreGive(bleMutexHandle);
#endif /* __ZEPHYR__ */

    return ret;
}

int PLATFORM_ReleaseBleWakeUp(void)
{
    int ret = 0;
    /* Nothing to do, the BLE controller awakes with a one shot interrupt from PMU
     * For now, there's no mechanism to force it active for a defined period of time
     * The only concern is if the CPU2 has time to re-enter sleep while CPU3 still
     * needs CPU2 power domain ressources such as IMU/SMU
     * TODO: Use GPIO output from CPU2 to track sleep/active periods and measure
     * the minimal time before CPU2 re-enters sleep after a wake up */
    return ret;
}

void BLE_MCI_WAKEUP_DONE0_DriverIRQHandler(void)
{
    /* The Controller is awake, we can clear BLE wake up interrupt */
    PMU_DisableBleWakeup(0x1U);
    NVIC_DisableIRQ(BLE_MCI_WAKEUP_DONE0_IRQn);
}

int PLATFORM_HandleControllerPowerState(void)
{
    int ret = 0;

    /* Controller can send data or event directly to Host without
     * PS_AWAKE indication, the host needs to update the power state */
    ret = PLATFORM_HandleBlePowerStateEvent(ble_awake_event);

    /* Unblock any sending task waiting for wake up */
#ifdef __ZEPHYR__
    k_event_post(&wakeUpEventGroup, ble_awake_event);
#else
    (void)xEventGroupSetBits(wakeUpEventGroup, (EventBits_t)ble_awake_event);
#endif /* __ZEPHYR__ */

    return ret;
}

/* -------------------------------------------------------------------------- */
/*                              Private functions                             */
/* -------------------------------------------------------------------------- */

static int PLATFORM_InitHciLink(void)
{
    int ret = 0;

    do
    {
        /* Init RPMSG/IMU Channel */
        if (HAL_RpmsgInit((hal_rpmsg_handle_t)hci_rpmsg_handle, &hci_rpmsg_config) != kStatus_HAL_RpmsgSuccess)
        {
            ret = -1;
            break;
        }
    } while (false);

    return ret;
}

static int PLATFORM_TerminateHciLink(void)
{
    int ret = 0;

    do
    {
        /* Deinitialize IMU first
         * Ignoring return value because kStatus_HAL_RpmsgError means it was already deinitialize */
        (void)HAL_ImuDeinit(kIMU_LinkCpu2Cpu3, 0);

        /* Deinitialize RPMSG first */
        if (HAL_RpmsgDeinit(hci_rpmsg_handle) != kStatus_HAL_RpmsgSuccess)
        {
            ret = -2;
            break;
        }
    } while (false);

    return ret;
}

static bool PLATFORM_IsHciLinkReady(void)
{
    return (HAL_ImuLinkIsUp(hci_rpmsg_config.imuLink) == kStatus_HAL_RpmsgSuccess);
}

static bool PLATFORM_IsBleAwake(void)
{
    return (blePowerState != ble_asleep_state);
}

static hal_rpmsg_return_status_t PLATFORM_HciRpmsgRxCallback(void *param, uint8_t *data, uint32_t len)
{
    bool    handled    = false;
    uint8_t packetType = data[0];

    (void)param;

    (void)PLATFORM_HandleControllerPowerState();

    /* If the macro BLE_VENDOR_EVENT_HANDLE is set to true, PLATFORM module will check if it can handle Vendor Specific
     * Events without going through Ethermind's HCI tasks If the packet is not handled, then it is sent to upper layers
     * This is likely used to handle Controller low power state, so this is
     * completely transparent to the application. If the macro BLE_VENDOR_EVENT_HANDLE is set false, the Ethermind's HCI
     * tasks will handle vendor event */
    if (packetType == HCI_EVENT_PACKET)
    {
        uint8_t eventType = data[1];

        if (eventType == HCI_VENDOR_SPECIFIC_DEBUG_EVENT)
        {
            /* Received packet is a Vendor Specific event, check if PLATFORM
             * can process it, if not, it will be sent to Ethermind */
            handled = PLATFORM_HandleHciVendorEvent(&data[3], data[2]);
        }
    }

    if ((handled == false) && (hci_rx_callback != NULL))
    {
        hci_rx_callback(packetType, &data[1], (uint16_t)(len - 1U));
    }

#ifdef SERIAL_BTSNOOP
    sbtsnoop_write_hci_pkt(data[0U], 1U, &data[1], len - 1);
#endif

    return kStatus_HAL_RL_RELEASE;
}

#ifndef __ZEPHYR__
static int PLATFORM_SetBtCalData(void)
{
    int           ret = 0;
    uint8_t       buffer[1 + HCI_CMD_PACKET_HEADER_LENGTH + HCI_CMD_STORE_BT_CAL_DATA_PARAM_LENGTH];
    uint16_t      opcode = get_opcode(HCI_CMD_VENDOR_OCG, HCI_CMD_STORE_BT_CAL_DATA_OCF);

    PLATFORM_FillInHciCmdMsg(buffer, opcode, (uint8_t)sizeof(hci_cal_data_params), hci_cal_data_params);

    ret = PLATFORM_SendHciMessage(buffer, sizeof(buffer));
    if (ret != 0)
    {
        ret = -1;
    }

    return ret;
}

#if !defined(gPlatformDisableSetBtCalDataAnnex100_d) || (gPlatformDisableSetBtCalDataAnnex100_d == 0)
static int PLATFORM_SetBtCalDataAnnex100(void)
{
    int      ret = 0;
    uint8_t  bufferAnnex100[1 + HCI_CMD_PACKET_HEADER_LENGTH + HCI_CMD_STORE_BT_CAL_DATA_PARAM_ANNEX100_LENGTH];
    uint16_t opcodeAnnex100 = get_opcode(HCI_CMD_VENDOR_OCG, HCI_CMD_STORE_BT_CAL_DATA_ANNEX100_OCF);

    PLATFORM_FillInHciCmdMsg(bufferAnnex100, opcodeAnnex100, (uint8_t)sizeof(hci_cal_data_annex100_params), hci_cal_data_annex100_params);

    ret = PLATFORM_SendHciMessage(bufferAnnex100, sizeof(bufferAnnex100));
    if (ret != 0)
    {
        ret = -1;
    }

    return ret;
}
#endif /* gPlatformDisableSetBtCalDataAnnex100_d */

static int PLATFORM_BleSetHostSleepConfig(void)
{
    int ret = 0;
    /* This command must be sent before sending any power commands, likely
     * after HCI init  */
    uint8_t       buffer[1 + HCI_CMD_PACKET_HEADER_LENGTH + HCI_CMD_BT_HOST_SLEEP_CONFIG_PARAM_LENGTH];
    uint16_t      opcode = get_opcode(HCI_CMD_VENDOR_OCG, HCI_CMD_BT_HOST_SLEEP_CONFIG_OCF);
    const uint8_t params[HCI_CMD_BT_HOST_SLEEP_CONFIG_PARAM_LENGTH] = {
        0xFFU, // BT_HIU_WAKEUP_INBAND
        0xFFU, // BT_HIU_WAKE_GAP_WAIT_FOR_IRQ
    };

    PLATFORM_FillInHciCmdMsg(buffer, opcode, (uint8_t)sizeof(params), params);

    ret = PLATFORM_SendHciMessage(buffer, sizeof(buffer));
    if (ret != 0)
    {
        ret = -1;
    }

    return ret;
}
#endif /* __ZEPHYR__ */

static bool PLATFORM_HandleHciVendorEvent(uint8_t *eventData, uint32_t len)
{
    uint8_t vEventType = eventData[0];
    bool    handled    = BLE_VENDOR_EVENT_HANDLE;

    assert(eventData != NULL);
    assert(len > 0U);

    switch (vEventType)
    {
        case HCI_CMD_SET_BT_SLEEP_MODE_OCF:
            break;

        case HCI_EVT_PS_SLEEP_OCF:
            (void)PLATFORM_HandleBlePowerStateEvent((ble_ps_event_t)eventData[1]);
            break;

        case HCI_CMD_BT_HIU_HS_ENABLE_OCF:
            break;

        default:
            handled = false;
            break;
    }

    return handled;
}

static int PLATFORM_HandleBlePowerStateEvent(ble_ps_event_t psEvent)
{
    int ret = 0;

    switch (blePowerState)
    {
        case ble_awake_state:
        {
            switch (psEvent)
            {
                case ble_asleep_event:
                    blePowerState = ble_asleep_state;
                    /* Make sure to clear wake up event */
#ifdef __ZEPHYR__
                    k_event_clear(&wakeUpEventGroup, ble_awake_event);
#else
                    (void)xEventGroupClearBits(wakeUpEventGroup, (EventBits_t)ble_awake_event);
#endif /* __ZEPHYR__ */
                    break;

                default:
                    break;
            }
        }
        break;

        case ble_asleep_state:
        {
            switch (psEvent)
            {
                case ble_awake_event:
                    blePowerState = ble_awake_state;
                    break;

                default:
                    break;
            }
        }
        break;

        default:
            ret = -1;
            break;
    }

    return ret;
}

static void PLATFORM_FillInHciCmdMsg(uint8_t *pbuf, uint16_t opcode, uint8_t msg_sz, const uint8_t *msg_payload)
{
    pbuf[0] = HCI_COMMAND_PACKET;
    pbuf[1] = (uint8_t)(opcode & 0xff);
    pbuf[2] = (uint8_t)((uint32_t)(opcode >> 8) & 0xff);
    pbuf[3] = msg_sz;
    (void)memcpy(&pbuf[4], msg_payload, msg_sz);
}
