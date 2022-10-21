/*
 * Copyright 2020-2022 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fsl_power.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/* Component ID definition, used by tools. */
#ifndef FSL_COMPONENT_ID
#define FSL_COMPONENT_ID "platform.drivers.power"
#endif

#define IS_XIP_FLEXSPI()                                                                                \
    ((((uint32_t)POWER_EnableWakeup >= 0x08000000U) && ((uint32_t)POWER_EnableWakeup < 0x10000000U)) || \
     (((uint32_t)POWER_EnableWakeup >= 0x18000000U) && ((uint32_t)POWER_EnableWakeup < 0x20000000U)))

#define FLEXSPI_DLL_LOCK_RETRY (10U)

/* Wait some PMU cycles */
#define POWER_WAIT_PMU()              \
    do                                \
    {                                 \
        volatile uint32_t dummy;      \
        dummy = PMU->PWR_MODE_STATUS; \
        dummy = PMU->PWR_MODE_STATUS; \
        dummy = PMU->PWR_MODE_STATUS; \
        dummy = PMU->PWR_MODE_STATUS; \
        dummy = PMU->PWR_MODE_STATUS; \
        (void)dummy;                  \
    } while (false)

#define POWER_WLAN_POWER_STATUS() (SOCCTRL->WLAN_POWER_STATUS & 0x3U)
#define POWER_BLE_POWER_STATUS()  (SOCCTRL->BLE_POWER_STATUS & 0x3U)
#define POWER_WLAN_BLE_POWER_ON   (0U)
#define POWER_WLAN_BLE_POWER_SLP  (2U)
#define POWER_WLAN_BLE_POWER_OFF  (3U)

typedef struct _power_nvic_context
{
    uint32_t PriorityGroup;
    uint32_t ISER[5];
    uint8_t IPR[160];
    uint8_t SHPR[12];
    uint32_t ICSR;
    uint32_t VTOR;
    uint32_t AIRCR;
    uint32_t SCR;
    uint32_t CCR;
    uint32_t SHCSR;
    uint32_t MMFAR;
    uint32_t BFAR;
    uint32_t CPACR;
    uint32_t NSACR;
} power_nvic_context_t;

typedef struct _power_systick_context
{
    uint32_t CTRL;
    uint32_t LOAD;
} power_systick_context_t;

typedef struct _power_clock_context
{
    uint32_t SOURCE_CLK_GATE;
} power_clock_context_t;

/*******************************************************************************
 * Variables
 ******************************************************************************/
static power_nvic_context_t s_nvicContext;
static power_systick_context_t s_systickContext;
static power_clock_context_t s_clockContext;
static capt_pulse_timer_callback_t s_captPulseCb;
static void *s_captPulseCbParam;

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
static void POWER_Delay(uint32_t loop)
{
    if (loop > 0U)
    {
        __ASM volatile("MOV    R0, %0" : : "r"(loop));
        __ASM volatile(
            "1:                             \n"
            "    SUBS   R0, R0, #1          \n"
            "    CMP    R0, #0              \n"
            "    BNE    1b                  \n");
    }
}

static void POWER_DelayUs(uint32_t us)
{
    uint32_t instNum;

    instNum = ((SystemCoreClock + 999999UL) / 1000000UL) * us;
    POWER_Delay((instNum + 2U) / 3U);
}

static void POWER_SaveNvicState(void)
{
    uint32_t i;
    uint32_t irqRegs;
    uint32_t irqNum;

    irqRegs = (SCnSCB->ICTR & SCnSCB_ICTR_INTLINESNUM_Msk) + 1U;
    irqNum  = irqRegs * 32U;

    assert(irqRegs <= ARRAY_SIZE(s_nvicContext.ISER));
    assert(irqNum <= ARRAY_SIZE(s_nvicContext.IPR));

    s_nvicContext.PriorityGroup = NVIC_GetPriorityGrouping();

    for (i = 0U; i < irqRegs; i++)
    {
        s_nvicContext.ISER[i] = NVIC->ISER[i];
    }

    for (i = 0U; i < irqNum; i++)
    {
        s_nvicContext.IPR[i] = NVIC->IPR[i];
    }

    /* Save SCB configuration */
    s_nvicContext.ICSR  = SCB->ICSR;
    s_nvicContext.VTOR  = SCB->VTOR;
    s_nvicContext.AIRCR = SCB->AIRCR;
    s_nvicContext.SCR   = SCB->SCR;
    s_nvicContext.CCR   = SCB->CCR;

    s_nvicContext.SHCSR = SCB->SHCSR;
    s_nvicContext.MMFAR = SCB->MMFAR;
    s_nvicContext.BFAR  = SCB->BFAR;
    s_nvicContext.CPACR = SCB->CPACR;
    s_nvicContext.NSACR = SCB->NSACR;

    for (i = 0U; i < ARRAY_SIZE(s_nvicContext.SHPR); i++)
    {
        s_nvicContext.SHPR[i] = SCB->SHPR[i];
    }
}

static void POWER_RestoreNvicState(void)
{
    uint32_t i;
    uint32_t irqRegs;
    uint32_t irqNum;

    irqRegs = (SCnSCB->ICTR & SCnSCB_ICTR_INTLINESNUM_Msk) + 1U;
    irqNum  = irqRegs * 32U;

    NVIC_SetPriorityGrouping(s_nvicContext.PriorityGroup);

    for (i = 0U; i < irqRegs; i++)
    {
        NVIC->ISER[i] = s_nvicContext.ISER[i];
    }

    for (i = 0U; i < irqNum; i++)
    {
        NVIC->IPR[i] = s_nvicContext.IPR[i];
    }

    /* Restore SCB configuration */
    SCB->ICSR  = s_nvicContext.ICSR;
    SCB->VTOR  = s_nvicContext.VTOR;
    SCB->AIRCR = s_nvicContext.AIRCR;
    SCB->SCR   = s_nvicContext.SCR;
    SCB->CCR   = s_nvicContext.CCR;

    SCB->SHCSR = s_nvicContext.SHCSR;
    SCB->MMFAR = s_nvicContext.MMFAR;
    SCB->BFAR  = s_nvicContext.BFAR;
    SCB->CPACR = s_nvicContext.CPACR;
    SCB->NSACR = s_nvicContext.NSACR;

    for (i = 0U; i < ARRAY_SIZE(s_nvicContext.SHPR); i++)
    {
        SCB->SHPR[i] = s_nvicContext.SHPR[i];
    }
}

void CAPT_PULSE_DriverIRQHandler(void);
void CAPT_PULSE_DriverIRQHandler(void)
{
    /* Clear IRQ status */
    PMU->CAPT_PULSE |= PMU_CAPT_PULSE_IRQ_CLR_MASK;
    /* Call user callback */
    if (s_captPulseCb != NULL)
    {
        s_captPulseCb(s_captPulseCbParam);
    }
}

/**
 * @brief   Check if IRQ is the wakeup source
 * @param   irq   : IRQ number
 * @return  true if IRQ is the wakeup source, false otherwise.
 */
bool POWER_GetWakeupStatus(IRQn_Type irq)
{
    uint32_t status;
    uint32_t irqNum = (uint32_t)irq;

    assert((int32_t)irq >= 0);

    if (irq <= HWVAD0_IRQn)
    {
        status = PMU->WAKEUP_PM2_STATUS0 & (1UL << irqNum);
    }
    else if (irq <= POWERQUAD_IRQn)
    {
        status = PMU->WAKEUP_PM2_STATUS1 & (1UL << (irqNum - 32U));
    }
    else if ((irq <= ITRC_IRQn) && (irq >= GAU_GPDAC_INT_FUNC11_IRQn))
    {
        status = PMU->WAKEUP_PM2_STATUS3 & (1UL << (irqNum - 96U));
    }
    else
    {
        status = 0U;
    }

    switch (irq)
    {
        case PIN0_INT_IRQn:
            status = PMU->WAKEUP_STATUS & PMU_WAKEUP_STATUS_PIN0_MASK;
            break;
        case PIN1_INT_IRQn:
            status = PMU->WAKEUP_STATUS & PMU_WAKEUP_STATUS_PIN1_MASK;
            break;
        case RTC_IRQn:
            /* PM2 wakeup status is at WAKEUP_PM2_STATUS1, PM3/PM4 wakeup status is at WAKEUP_STATUS */
            status |= PMU->WAKEUP_STATUS & PMU_WAKEUP_STATUS_RTC_MASK;
            break;
        case CAPT_PULSE_IRQn:
            status = PMU->WAKEUP_STATUS & PMU_WAKEUP_STATUS_CAPT_MASK;
            break;
        case WL_MCI_WAKEUP0_IRQn:
            status = PMU->WAKEUP_STATUS & (1UL << PMU_WAKEUP_STATUS_WL_SHIFT);
            break;
        case WL_MCI_WAKEUP1_IRQn:
            status = PMU->WAKEUP_STATUS & (2UL << PMU_WAKEUP_STATUS_WL_SHIFT);
            break;
        case BLE_MCI_WAKEUP0_IRQn:
            status = PMU->WAKEUP_STATUS & (1UL << PMU_WAKEUP_STATUS_BLE_SHIFT);
            break;
        case BLE_MCI_WAKEUP1_IRQn:
            status = PMU->WAKEUP_STATUS & (2UL << PMU_WAKEUP_STATUS_BLE_SHIFT);
            break;
        default:
            /* Do nothing */
            break;
    }

    return (status != 0U);
}

/**
 * @brief   Clear wakeup status
 * @param   irq   : IRQ number
 */
void POWER_ClearWakeupStatus(IRQn_Type irq)
{
    uint32_t irqNum = (uint32_t)irq;

    assert((int32_t)irq >= 0);

    if (irq <= HWVAD0_IRQn)
    {
        PMU->WAKEUP_PM2_SRC_CLR0 = (1UL << irqNum);
    }
    else if (irq <= POWERQUAD_IRQn)
    {
        PMU->WAKEUP_PM2_SRC_CLR1 = (1UL << (irqNum - 32U));
    }
    else if ((irq <= ITRC_IRQn) && (irq >= GAU_GPDAC_INT_FUNC11_IRQn))
    {
        PMU->WAKEUP_PM2_SRC_CLR3 = (1UL << (irqNum - 96U));
    }
    else
    {
        /* Do nothing */
    }

    switch (irq)
    {
        case PIN0_INT_IRQn:
            PMU->WAKE_SRC_CLR = PMU_WAKE_SRC_CLR_PIN0_CLR_MASK;
            break;
        case PIN1_INT_IRQn:
            PMU->WAKE_SRC_CLR = PMU_WAKE_SRC_CLR_PIN1_CLR_MASK;
            break;
        case RTC_IRQn:
            PMU->WAKE_SRC_CLR = PMU_WAKE_SRC_CLR_RTC_CLR_MASK;
            break;
        case CAPT_PULSE_IRQn:
            PMU->WAKE_SRC_CLR = PMU_WAKE_SRC_CLR_CAPT_CLR_MASK;
            break;
        case WL_MCI_WAKEUP0_IRQn:
            PMU->WAKE_SRC_CLR = (1UL << PMU_WAKE_SRC_CLR_WL_CLR_SHIFT);
            break;
        case WL_MCI_WAKEUP1_IRQn:
            PMU->WAKE_SRC_CLR = (2UL << PMU_WAKE_SRC_CLR_WL_CLR_SHIFT);
            break;
        case BLE_MCI_WAKEUP0_IRQn:
            PMU->WAKE_SRC_CLR = (1UL << PMU_WAKE_SRC_CLR_BLE_CLR_SHIFT);
            break;
        case BLE_MCI_WAKEUP1_IRQn:
            PMU->WAKE_SRC_CLR = (2UL << PMU_WAKE_SRC_CLR_BLE_CLR_SHIFT);
            break;
        default:
            /* Do nothing */
            break;
    }
}

/**
 * @brief   Enable the Wakeup interrupt.
 * @param   irq   : IRQ number
 */
void POWER_EnableWakeup(IRQn_Type irq)
{
    uint32_t irqNum = (uint32_t)irq;

    assert((int32_t)irq >= 0);

    if (irq <= HWVAD0_IRQn)
    {
        PMU->WAKEUP_PM2_MASK0 |= (1UL << irqNum);
    }
    else if (irq <= POWERQUAD_IRQn)
    {
        PMU->WAKEUP_PM2_MASK1 |= (1UL << (irqNum - 32U));
    }
    else if ((irq <= ITRC_IRQn) && (irq >= GAU_GPDAC_INT_FUNC11_IRQn))
    {
        PMU->WAKEUP_PM2_MASK3 |= (1UL << (irqNum - 96U));
    }
    else
    {
        /* Do nothing */
    }

    switch (irq)
    {
        case PIN0_INT_IRQn:
            PMU->WAKEUP_MASK |= PMU_WAKEUP_MASK_PIN0_MASK_MASK;
            break;
        case PIN1_INT_IRQn:
            PMU->WAKEUP_MASK |= PMU_WAKEUP_MASK_PIN1_MASK_MASK;
            break;
        case RTC_IRQn:
            PMU->WAKEUP_MASK |= PMU_WAKEUP_MASK_RTC_MASK_MASK;
            break;
        case CAPT_PULSE_IRQn:
            PMU->WAKEUP_MASK |= PMU_WAKEUP_MASK_CAPT_MASK_MASK;
            break;
        case WL_MCI_WAKEUP0_IRQn:
            PMU->WAKEUP_MASK |= (1UL << PMU_WAKEUP_MASK_WL_MASK_SHIFT);
            break;
        case WL_MCI_WAKEUP1_IRQn:
            PMU->WAKEUP_MASK |= (2UL << PMU_WAKEUP_MASK_WL_MASK_SHIFT);
            break;
        case BLE_MCI_WAKEUP0_IRQn:
            PMU->WAKEUP_MASK |= (1UL << PMU_WAKEUP_MASK_BLE_MASK_SHIFT);
            break;
        case BLE_MCI_WAKEUP1_IRQn:
            PMU->WAKEUP_MASK |= (2UL << PMU_WAKEUP_MASK_BLE_MASK_SHIFT);
            break;
        default:
            /* Do nothing */
            break;
    }
}

/**
 * @brief   Disable the Wakeup interrupts.
 * @param   irq   : IRQ number
 */
void POWER_DisableWakeup(IRQn_Type irq)
{
    uint32_t irqNum = (uint32_t)irq;

    assert((int32_t)irq >= 0);

    if (irq <= HWVAD0_IRQn)
    {
        PMU->WAKEUP_PM2_MASK0 &= ~(1UL << irqNum);
    }
    else if (irq <= POWERQUAD_IRQn)
    {
        PMU->WAKEUP_PM2_MASK1 &= ~(1UL << (irqNum - 32U));
    }
    else if ((irq <= ITRC_IRQn) && (irq >= GAU_GPDAC_INT_FUNC11_IRQn))
    {
        PMU->WAKEUP_PM2_MASK3 &= ~(1UL << (irqNum - 96U));
    }
    else
    {
        /* Do nothing */
    }

    switch (irq)
    {
        case PIN0_INT_IRQn:
            PMU->WAKEUP_MASK &= ~PMU_WAKEUP_MASK_PIN0_MASK_MASK;
            break;
        case PIN1_INT_IRQn:
            PMU->WAKEUP_MASK &= ~PMU_WAKEUP_MASK_PIN1_MASK_MASK;
            break;
        case RTC_IRQn:
            PMU->WAKEUP_MASK &= ~PMU_WAKEUP_MASK_RTC_MASK_MASK;
            break;
        case CAPT_PULSE_IRQn:
            PMU->WAKEUP_MASK &= ~PMU_WAKEUP_MASK_CAPT_MASK_MASK;
            break;
        case WL_MCI_WAKEUP0_IRQn:
            PMU->WAKEUP_MASK &= ~(1UL << PMU_WAKEUP_MASK_WL_MASK_SHIFT);
            break;
        case WL_MCI_WAKEUP1_IRQn:
            PMU->WAKEUP_MASK &= ~(2UL << PMU_WAKEUP_MASK_WL_MASK_SHIFT);
            break;
        case BLE_MCI_WAKEUP0_IRQn:
            PMU->WAKEUP_MASK &= ~(1UL << PMU_WAKEUP_MASK_BLE_MASK_SHIFT);
            break;
        case BLE_MCI_WAKEUP1_IRQn:
            PMU->WAKEUP_MASK &= ~(2UL << PMU_WAKEUP_MASK_BLE_MASK_SHIFT);
            break;
        default:
            /* Do nothing */
            break;
    }
}

/**
 * @brief   Set sleep mode on idle.
 * @param   mode : 0 ~ 4 stands for PM0 ~ PM4.
 */
void POWER_SetSleepMode(uint32_t mode)
{
    assert(mode <= 4U);

    if (mode == 0U)
    {
        mode = 1U; /* PM0/PM1 is same */
    }
    /* set PMU basic mode */
    PMU->PWR_MODE = PMU_PWR_MODE_PWR_MODE(mode - 1U);

    /* select deepsleep or not */
    if (mode == 1U)
    {
        SCB->SCR &= ~SCB_SCR_SLEEPDEEP_Msk;
    }
    else
    {
        SCB->SCR |= SCB_SCR_SLEEPDEEP_Msk;
    }
}

AT_QUICKACCESS_SECTION_CODE(static void Power_ConfigClkGate(const power_sleep_config_t *config))
{
    uint32_t pm2AnaPdCfg = (config->pm2AnaPuCfg ^ (uint32_t)kPOWER_Pm2AnaPuAll) & (uint32_t)kPOWER_Pm2AnaPuAll;
    uint32_t clkGate     = config->clkGate & (uint32_t)kPOWER_ClkGateAll;

    /* If ENET clock is enabled, TDDR power must be on. */
    if ((clkGate & SYSCTL2_SOURCE_CLK_GATE_TDDR_MCI_ENET_CLK_CG_MASK) == 0U)
    {
        pm2AnaPdCfg &= ~SYSCTL2_ANA_PDWN_PM2_TDDR_TOP_ANA_PDWN_PM2_MASK;
    }

    SYSCTL2->SOURCE_CLK_GATE = (SYSCTL2->SOURCE_CLK_GATE & (~((uint32_t)kPOWER_ClkGateAll))) | clkGate;
    SYSCTL2->ANA_PDWN_PM2    = pm2AnaPdCfg;
}

AT_QUICKACCESS_SECTION_CODE(static void deinitXip(void))
{
    if (IS_XIP_FLEXSPI())
    { /* FlexSPI */
        /* Wait until FLEXSPI is not busy */
        while (!(((FLEXSPI->STS0 & FLEXSPI_STS0_ARBIDLE_MASK) != 0U) &&
                 ((FLEXSPI->STS0 & FLEXSPI_STS0_SEQIDLE_MASK) != 0U)))
        {
        }
        /* Disable module. */
        FLEXSPI->MCR0 |= FLEXSPI_MCR0_MDIS_MASK;
        /* Disable clock. */
        CLKCTL0->PSCCTL0_CLR = CLKCTL0_PSCCTL0_CLR_FLEXSPI0_MASK;
    }
}

AT_QUICKACCESS_SECTION_CODE(static void initFlexSPI(FLEXSPI_Type *base))
{
    uint32_t status;
    uint32_t lastStatus;
    uint32_t retry;
    uint32_t mask = 0;

    /* Enable FLEXSPI module */
    base->MCR0 &= ~FLEXSPI_MCR0_MDIS_MASK;

    base->MCR0 |= FLEXSPI_MCR0_SWRESET_MASK;
    while ((base->MCR0 & FLEXSPI_MCR0_SWRESET_MASK) != 0U)
    {
    }

    /* Need to wait DLL locked if DLL enabled */
    if (0U != (base->DLLCR[0] & FLEXSPI_DLLCR_DLLEN_MASK))
    {
        lastStatus = base->STS2;
        retry      = FLEXSPI_DLL_LOCK_RETRY;
        /* Flash on port A */
        if (((base->FLSHCR0[0] & FLEXSPI_FLSHCR0_FLSHSZ_MASK) > 0U) ||
            ((base->FLSHCR0[1] & FLEXSPI_FLSHCR0_FLSHSZ_MASK) > 0U))
        {
            mask |= FLEXSPI_STS2_AREFLOCK_MASK | FLEXSPI_STS2_ASLVLOCK_MASK;
        }
        /* Flash on port B */
        if (((base->FLSHCR0[2] & FLEXSPI_FLSHCR0_FLSHSZ_MASK) > 0U) ||
            ((base->FLSHCR0[3] & FLEXSPI_FLSHCR0_FLSHSZ_MASK) > 0U))
        {
            mask |= FLEXSPI_STS2_BREFLOCK_MASK | FLEXSPI_STS2_BSLVLOCK_MASK;
        }
        /* Wait slave delay line locked and slave reference delay line locked. */
        do
        {
            status = base->STS2;
            if ((status & mask) == mask)
            {
                /* Locked */
                retry = 100;
                break;
            }
            else if (status == lastStatus)
            {
                /* Same delay cell number in calibration */
                retry--;
            }
            else
            {
                retry      = FLEXSPI_DLL_LOCK_RETRY;
                lastStatus = status;
            }
        } while (retry > 0U);
        /* According to ERR011377, need to delay at least 100 NOPs to ensure the DLL is locked. */
        for (; retry > 0U; retry--)
        {
            __NOP();
        }
    }
}

AT_QUICKACCESS_SECTION_CODE(static void initXip(void))
{
    if (IS_XIP_FLEXSPI())
    { /* FlexSPI */
        /* Enable FLEXSPI clock again */
        CLKCTL0->PSCCTL0_SET = CLKCTL0_PSCCTL0_SET_FLEXSPI0_MASK;
        /* Re-enable FLEXSPI module */
        initFlexSPI(FLEXSPI);
    }
}

void POWER_ConfigCauInSleep(bool pdCau)
{
    if (pdCau) /* xtal / cau full pd */
    {
        CAU->PD_CTRL_ONE_REG |= 0x4U;
        CAU->SLP_CTRL_ONE_REG = 0xCU;
    }
    else
    {
        CAU->PD_CTRL_ONE_REG &= 0xFBU;
        CAU->SLP_CTRL_ONE_REG = 0x9EU;
        CAU->SLP_CTRL_TWO_REG = 0x6AU;
    }
}

/* Prepare to go to low power
 *  Change clock source to RC32M
 *   Switch off PLLs, XTAL
 *  Set Deep sleep bit in SRC register
 *  Initiate state change
 */
AT_QUICKACCESS_SECTION_CODE(static void POWER_PrePowerMode(uint32_t mode, const power_sleep_config_t *config))
{
    uint32_t wlanPowerStatus, blePowerStatus;

    assert((mode >= 1U) && (mode <= 4U));
    /* Turn off Systick to avoid interrupt
     *  when entering low power state
     */
    s_systickContext.CTRL = SysTick->CTRL;
    s_systickContext.LOAD = SysTick->LOAD;
    SysTick->CTRL         = 0;
    SysTick->LOAD         = 0;

    POWER_SetSleepMode(mode);

    s_clockContext.SOURCE_CLK_GATE = SYSCTL2->SOURCE_CLK_GATE;

    if (mode == 2U)
    {
        /* Deinit FlexSPI in case XIP */
        deinitXip();
        /* Keep all modules power on in SW controlled CFG */
        SYSCTL2->MEM_PD_CFG = 0U;
        /* Enable SW control for modules need be powered on, the others are powered down by HW */
        SYSCTL2->MEM_PD_CTRL = config->pm2MemPuCfg & (uint32_t)kPOWER_Pm2MemPuAll;
        Power_ConfigClkGate(config);
    }
    else if (mode >= 3U)
    {
        /* Turn off the short switch between C18/C11 and V18/V11.
           In sleep mode, V11 drops to 0.8V */
        BUCK18->BUCK_CTRL_TWENTY_REG = 0x75U;

        if (mode == 3U)
        {
            POWER_SaveNvicState();

            PMU->MEM_CFG = (PMU->MEM_CFG & ~PMU_MEM_CFG_MEM_RET_MASK) | (config->memPdCfg & PMU_MEM_CFG_MEM_RET_MASK);
            PMU->PMIP_BUCK_CTRL = (PMU->PMIP_BUCK_CTRL & ~((uint32_t)kPOWER_Pm3BuckAll)) |
                                  (config->pm3BuckCfg & (uint32_t)kPOWER_Pm3BuckAll);
            /* Clear reset status */
            PMU->SYS_RST_CLR = 0x7FU;
        }
        else if (mode == 4U)
        {
            wlanPowerStatus = POWER_WLAN_POWER_STATUS();
            blePowerStatus  = POWER_BLE_POWER_STATUS();

            PMU->MEM_CFG =
                (PMU->MEM_CFG & ~PMU_MEM_CFG_AON_MEM_RET_MASK) | (config->memPdCfg & PMU_MEM_CFG_AON_MEM_RET_MASK);
            if ((wlanPowerStatus == POWER_WLAN_BLE_POWER_OFF) && (blePowerStatus == POWER_WLAN_BLE_POWER_OFF))
            {
                /* pm422, LDO 0.8V, 1.8V */
                PMU->PMIP_LDO_LVL = PMU_PMIP_LDO_LVL_LDO18_SEL(4) | PMU_PMIP_LDO_LVL_LDO11_SEL(1);
            }
            /* Clear reset status */
            PMU->SYS_RST_CLR = 0x7FU;
        }
        else
        {
            assert(false);
        }
    }
    else
    {
        /* PM1: Do nothing */
    }
}

AT_QUICKACCESS_SECTION_CODE(static bool POWER_PostPowerMode(uint32_t mode))
{
    assert((mode >= 1U) && (mode <= 3U));

    POWER_SetSleepMode(1U);

    SYSCTL2->SOURCE_CLK_GATE = s_clockContext.SOURCE_CLK_GATE;

    if (mode == 2U)
    {
        initXip();
    }
    else if (mode == 3U)
    {
        POWER_RestoreNvicState();
    }
    else
    {
        /* PM1: Do nothing */
    }

    SysTick->CTRL = s_systickContext.CTRL;
    SysTick->LOAD = s_systickContext.LOAD;

    return (mode == 1U) || (PMU->PWR_MODE_STATUS == (mode - 1U)); /* PM1 doesn't update PWR_MODE_STATUS */
}

static void POWER_EnterPm3Asm(void)
{
    uint32_t clk = CLKCTL0->PSCCTL0;
    uint32_t rst = RSTCTL0->PRSTCTL0;

    /* Enable AON MEM clock/reset. */
    CLKCTL0->PSCCTL0_SET  = CLKCTL0_PSCCTL0_SET_AON_MEM_MASK;
    RSTCTL0->PRSTCTL0_CLR = RSTCTL0_PRSTCTL0_CLR_AON_MEM_MASK;

    /* Address: 0x4015C000 is the address in NVRAM which holds address
     * where control returns after exit from PM3.
     * All general purpose registers and special registers
     * are saved by pushing them on current thread's stack
     * and finally SP is saved in NVRAM address 0x4015C004. */
    __ASM volatile(
        "push {r0-r12, lr}\n"
        "mrs r1, basepri\n"
        "push {r1}\n"
        "mrs r1, primask\n"
        "push {r1}\n"
        "mrs r1, faultmask\n"
        "push {r1}\n"
        "mrs r1, control\n"
        "bic r2, r1, #2\n"
        "msr control, r2\n" /* Use MSP */
        "push {r1}\n"       /* CONTROL */
        "mrs r1, psp\n"
        "push {r1}\n" /* PSP */
        "mrs r1, psplim\n"
        "push {r1}\n" /* PSPLIM */
        "mrs r1, msplim\n"
        "push {r1}\n" /* MSPLIM */
        "ldr r0, =0x4015C004\n"
        "str sp, [r0]\n" /* MSP */
        "ldr r0, =0x4015C000\n"
        "mov r1, pc\n"
        "add r1, r1 , #20\n"
        "str r1, [r0]\n");
    /*
     * Execute WFI to generate a state change
     * and system is in an unresponsive state
     * press wakeup key to get it out of standby
     * If time_to_standby is set to valid value
     * RTC is programmed and RTC generates
     * a wakeup signal.
     */
    __WFI();

    __NOP();
    __NOP();
    __NOP();
    __NOP();
    __NOP();
    __NOP();
    __NOP();
    __NOP();
    __NOP();

    /* When system exits PM3 all registers need to be
     * restored as they are lost. */

    /*
     * When MCU enters PM3 all Core registers
     * r0-r12
     * lr
     * basepri
     * primask
     * faultmask
     * control
     * psp
     * psplim
     * msplim
     * are lost (ZERO) as MCU power is tuned off
     * On wakeup from PM3, this piece of code restores
     * these registers which were saved before entry.
     * The location of saving this register was on stack
     */
    __ASM volatile(
        "ldr r0, =0x4015C004\n"
        "ldr sp, [r0]\n"
        "pop {r4}\n"   /* MSPLIM */
        "pop {r5}\n"   /* PSPLIM */
        "pop {r1}\n"   /* PSP */
        "pop {r2}\n"   /* CONTROL */
        "mov r3, sp\n" /* MSP */
        "msr msplim, r4\n"
        "msr psplim, r5\n"
        "msr msp, r3\n"
        "msr psp, r1\n"
        "msr control, r2\n"
        "pop {r1}\n"
        "msr faultmask, r1\n"
        "pop {r1}\n"
        "msr primask, r1\n"
        "pop {r1}\n"
        "msr basepri, r1\n"
        "pop {r0-r12, lr}\n");
    /* Restore AON MEM clock/reset */
    CLKCTL0->PSCCTL0  = clk;
    RSTCTL0->PRSTCTL0 = rst;
}

void POWER_GetCurrentSleepConfig(power_sleep_config_t *config)
{
    assert(config != NULL);

    config->pm2MemPuCfg = (~SYSCTL2->MEM_PD_CFG) & (SYSCTL2->MEM_PD_CTRL);
    config->pm2AnaPuCfg = (~SYSCTL2->ANA_PDWN_PM2) & (uint32_t)kPOWER_Pm2AnaPuAll;
    config->clkGate     = SYSCTL2->SOURCE_CLK_GATE;
    config->memPdCfg    = PMU->MEM_CFG;
    config->pm3BuckCfg  = PMU->PMIP_BUCK_CTRL & (uint32_t)kPOWER_Pm3BuckAll;
}

void POWER_InitPowerConfig(const power_init_config_t *config)
{
    uint32_t reg;
    bool iBuck, gateCauRefClk;

    assert(config != NULL);

    iBuck         = config->iBuck;
    gateCauRefClk = config->gateCauRefClk;

    BUCK11->BUCK_CTRL_THREE_REG  = 0x10U;
    BUCK18->BUCK_CTRL_THREE_REG  = 0x10U;
    BUCK18->BUCK_CTRL_TWENTY_REG = 0x55U;

    SYSCTL0->AUTOCLKGATEOVERRIDE0 = 0U;
    /* Enable RAM dynamic clk gate */
    SYSCTL0->AUTOCLKGATEOVERRIDE1 = 0U;
    /* Enable ROM dynamic clk gate */
    SYSCTL2->ROM_DYN_CLK_EN = SYSCTL2_ROM_DYN_CLK_EN_ROM_DYN_CLK_EN_MASK;

    PMU->PMIP_BUCK_LVL = PMU_PMIP_BUCK_LVL_SLEEP_BUCK18_SEL(0x60U) |  /* 1.8V */
                         PMU_PMIP_BUCK_LVL_SLEEP_BUCK11_SEL(0x22U) |  /* 0.8V */
                         PMU_PMIP_BUCK_LVL_NORMAL_BUCK18_SEL(0x60U) | /* 1.8V */
                         PMU_PMIP_BUCK_LVL_NORMAL_BUCK11_SEL(0x54U);  /* 1.05V */

    PMU->PMIP_LDO_LVL = 0U;
    if (iBuck)
    {
        /* No timeout with internal supply. */
        PMU->TIME_OUT_CTRL = PMU_TIME_OUT_CTRL_V11_RDY_NO_TMT_MASK | PMU_TIME_OUT_CTRL_V18_RDY_NO_TMT_MASK |
                             PMU_TIME_OUT_CTRL_PSW_MCI_RDY_NO_TMT_MASK;
    }
    else
    {
        /* Use timeout mode with external supply for VCORE and AVDD18. */
        PMU->TIME_OUT_CTRL      = PMU_TIME_OUT_CTRL_PSW_MCI_RDY_NO_TMT_MASK;
        PMU->TIME_OUT_CFG_VALUE = 0x3FFFFFFFU;
    }

    PMU->SOC_MEM_PDWN &= ~(PMU_SOC_MEM_PDWN_MSC_MEM_PDWN_CTRL_MASK | PMU_SOC_MEM_PDWN_SOCTOP_OTP_PDWN_CTRL_MASK);
    PMU->CAU_SLP_CTRL = gateCauRefClk ? PMU_CAU_SLP_CTRL_CAU_SOC_SLP_CG_MASK : 0U;

    /* USB SW WR in A0, will fix in A1 eco */
    /* Open usb clock and release reset */
    reg                   = CLKCTL0->PSCCTL0;
    CLKCTL0->PSCCTL0_SET  = CLKCTL0_PSCCTL0_SET_USB_MASK;
    RSTCTL0->PRSTCTL0_CLR = RSTCTL0_PRSTCTL0_CLR_USB_MASK;
    POWER_DelayUs(1U);
    /* Restore usb clk. */
    CLKCTL0->PSCCTL0 = reg;

    /* Disable G2BIST CLK */
    CLKCTL0->G2BIST_CLK_EN = 0U;
}

bool POWER_EnterPowerMode(uint32_t mode, const power_sleep_config_t *config)
{
    uint32_t primask;
    bool ret = true;

    assert(mode <= 4U);

    if (mode >= 1U)
    {
        primask = DisableGlobalIRQ();
        POWER_PrePowerMode(mode, config);
        if (mode == 3U)
        {
            POWER_EnterPm3Asm();
        }
        else
        {
            __WFI();
        }
        ret = POWER_PostPowerMode(mode);
        EnableGlobalIRQ(primask);
    }

    return ret;
}

void POWER_PowerOnWlan(void)
{
    if (POWER_WLAN_POWER_STATUS() == POWER_WLAN_BLE_POWER_OFF)
    {
        /* Enable SW control */
        PMU->SW_CTRL_WL |= PMU_SW_CTRL_WL_WL_EN_MASK;
        /* WLan request buck on, then need wait 5 fast clk_pmu cycles, do psw on, then iso release */
        PMU->SW_CTRL_WL |= PMU_SW_CTRL_WL_WL_BUCK_ON_REQ_MASK;
        /* Wait buck on */
        POWER_WAIT_PMU();

        PMU->SW_CTRL_WL &= ~PMU_SW_CTRL_WL_PSW_WL_PD_MASK;
        /* Wait PSW ready */
        SystemCoreClockUpdate();
        POWER_DelayUs(50U);
        /* Disable ISO */
        PMU->SW_CTRL_WL |= PMU_SW_CTRL_WL_MCI_ISO_WL_N_MASK;
        /* Wait about 125us */
        POWER_DelayUs(125U);
        /* Release WLan */
        PMU->SW_CTRL_WL &= ~PMU_SW_CTRL_WL_MCI_WL_PU_RST_MASK;
    }
}

void POWER_PowerOffWlan(void)
{
    if (POWER_WLAN_POWER_STATUS() != POWER_WLAN_BLE_POWER_OFF)
    {
        /* Enable SW control */
        PMU->SW_CTRL_WL |= PMU_SW_CTRL_WL_WL_EN_MASK;
        /* Enable ISO before PSW off */
        PMU->SW_CTRL_WL &= ~PMU_SW_CTRL_WL_MCI_ISO_WL_N_MASK;
        POWER_WAIT_PMU();
        PMU->SW_CTRL_WL |= PMU_SW_CTRL_WL_PSW_WL_PD_MASK;
        /* Wait PSW off */
        while ((SOCCTRL->PSW_VD2_RDY0 & (1UL << 1)) == 0U)
        {
        }
        /* Reset WLan */
        PMU->SW_CTRL_WL |= PMU_SW_CTRL_WL_MCI_WL_PU_RST_MASK;
        /* Request buck off */
        PMU->SW_CTRL_WL |= PMU_SW_CTRL_WL_WL_BUCK_OFF_REQ_MASK;
    }
}

void POWER_PowerOnBle(void)
{
    if (POWER_BLE_POWER_STATUS() == POWER_WLAN_BLE_POWER_OFF)
    {
        /* Enable SW control */
        PMU->SW_CTRL_BLE |= PMU_SW_CTRL_BLE_BLE_EN_MASK;
        /* BLE request buck on, then need wait 5 fast clk_pmu cycles(about 96ns),do psw on, then iso release */
        PMU->SW_CTRL_BLE |= PMU_SW_CTRL_BLE_BLE_BUCK_ON_REQ_MASK;
        /* Wait buck on */
        POWER_WAIT_PMU();
        PMU->SW_CTRL_BLE &= ~PMU_SW_CTRL_BLE_PSW_BLE_PD_MASK;
        /* Wait PSW ready */
        SystemCoreClockUpdate();
        POWER_DelayUs(50U);
        /* Disable ISO */
        PMU->SW_CTRL_BLE |= PMU_SW_CTRL_BLE_MCI_ISO_BLE_N_MASK;
        /* Wait about 125us */
        POWER_DelayUs(125U);
        /* Release BLE */
        PMU->SW_CTRL_BLE &= ~PMU_SW_CTRL_BLE_MCI_BLE_PU_RST_MASK;
    }
}

void POWER_PowerOffBle(void)
{
    if (POWER_BLE_POWER_STATUS() != POWER_WLAN_BLE_POWER_OFF)
    {
        /* Enable SW control */
        PMU->SW_CTRL_BLE |= PMU_SW_CTRL_BLE_BLE_EN_MASK;
        /* Enable ISO before PSW off */
        PMU->SW_CTRL_BLE &= ~PMU_SW_CTRL_BLE_MCI_ISO_BLE_N_MASK;
        POWER_WAIT_PMU();
        PMU->SW_CTRL_BLE |= PMU_SW_CTRL_BLE_PSW_BLE_PD_MASK;
        /* Wait PSW off */
        while ((SOCCTRL->PSW_VD2_RDY0 & (1UL << 9)) == 0U)
        {
        }
        /* Reset BLE */
        PMU->SW_CTRL_BLE |= PMU_SW_CTRL_BLE_MCI_BLE_PU_RST_MASK;
        /* Request buck off */
        PMU->SW_CTRL_BLE |= PMU_SW_CTRL_BLE_BLE_BUCK_OFF_REQ_MASK;
    }
}

void POWER_PowerOnGau(void)
{
    GAU_BG->CTRL &= ~BG_CTRL_PD_MASK;
    while ((GAU_BG->STATUS & BG_STATUS_RDY_MASK) == 0U)
    {
    }
}

void POWER_PowerOffGau(void)
{
    GAU_BG->CTRL |= BG_CTRL_PD_MASK;
}

void POWER_EnableCaptSlowPulseTimer(capt_slow_pulse_width_t width,
                                    capt_slow_pulse_edge_t edge,
                                    uint32_t timeout,
                                    capt_pulse_timer_callback_t cb,
                                    void *param)
{
    s_captPulseCb            = cb;
    s_captPulseCbParam       = param;
    PMU->CAPT_PULSE          = PMU_CAPT_PULSE_IRQ_CLR_MASK | PMU_CAPT_PULSE_IRQ_MSK_MASK;
    PMU->CAPT_PULSE_BASE_VAL = timeout;
    PMU->CAPT_PULSE          = PMU_CAPT_PULSE_IC_WIDTH_CLK_CNT(width) | PMU_CAPT_PULSE_IC_EDGE_CLK_CNT(edge);
    PMU->CAPT_PULSE |= PMU_CAPT_PULSE_CAPTURE_SLOW_PULSE_CNT_EN_MASK;
}

void POWER_EnableCaptFastPulseTimer(uint32_t timeout, capt_pulse_timer_callback_t cb, void *param)
{
    s_captPulseCb            = cb;
    s_captPulseCbParam       = param;
    PMU->CAPT_PULSE          = PMU_CAPT_PULSE_IRQ_CLR_MASK | PMU_CAPT_PULSE_IRQ_MSK_MASK;
    PMU->CAPT_PULSE_BASE_VAL = timeout;
    PMU->CAPT_PULSE          = PMU_CAPT_PULSE_CLK_SEL_MASK;
    PMU->CAPT_PULSE |= PMU_CAPT_PULSE_CAPTURE_FAST_PULSE_CNT_EN_MASK;
}

void POWER_DisableCaptPulseTimer(void)
{
    PMU->CAPT_PULSE = PMU_CAPT_PULSE_IRQ_CLR_MASK | PMU_CAPT_PULSE_IRQ_MSK_MASK;
}
