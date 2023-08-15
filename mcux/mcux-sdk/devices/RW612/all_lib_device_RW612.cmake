list(APPEND CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/.
    ${CMAKE_CURRENT_LIST_DIR}/../../CMSIS/Core/Include
    ${CMAKE_CURRENT_LIST_DIR}/../../CMSIS/DSP
    ${CMAKE_CURRENT_LIST_DIR}/../../CMSIS/Driver/Include
    ${CMAKE_CURRENT_LIST_DIR}/../../CMSIS/RTOS2
    ${CMAKE_CURRENT_LIST_DIR}/../../CMSIS/RTOS2/Include
    ${CMAKE_CURRENT_LIST_DIR}/../../CMSIS/RTOS2/RTX/Library
    ${CMAKE_CURRENT_LIST_DIR}/../../boards/rdrw612bga/flash_config
    ${CMAKE_CURRENT_LIST_DIR}/../../cmsis_drivers/flexcomm
    ${CMAKE_CURRENT_LIST_DIR}/../../components/audio
    ${CMAKE_CURRENT_LIST_DIR}/../../components/button
    ${CMAKE_CURRENT_LIST_DIR}/../../components/codec
    ${CMAKE_CURRENT_LIST_DIR}/../../components/codec/i2c
    ${CMAKE_CURRENT_LIST_DIR}/../../components/codec/wm8904
    ${CMAKE_CURRENT_LIST_DIR}/../../components/common_task
    ${CMAKE_CURRENT_LIST_DIR}/../../components/conn_fwloader
    ${CMAKE_CURRENT_LIST_DIR}/../../components/els_pkc
    ${CMAKE_CURRENT_LIST_DIR}/../../components/flash/mflash
    ${CMAKE_CURRENT_LIST_DIR}/../../components/flash/mflash/rdrw612bga
    ${CMAKE_CURRENT_LIST_DIR}/../../components/flash/nor
    ${CMAKE_CURRENT_LIST_DIR}/../../components/flash/nor/flexspi
    ${CMAKE_CURRENT_LIST_DIR}/../../components/ft6x06
    ${CMAKE_CURRENT_LIST_DIR}/../../components/gpio
    ${CMAKE_CURRENT_LIST_DIR}/../../components/i2c
    ${CMAKE_CURRENT_LIST_DIR}/../../components/ili9341
    ${CMAKE_CURRENT_LIST_DIR}/../../components/lists
    ${CMAKE_CURRENT_LIST_DIR}/../../components/log
    ${CMAKE_CURRENT_LIST_DIR}/../../components/mem_manager
    ${CMAKE_CURRENT_LIST_DIR}/../../components/messaging
    ${CMAKE_CURRENT_LIST_DIR}/../../components/osa
    ${CMAKE_CURRENT_LIST_DIR}/../../components/phy
    ${CMAKE_CURRENT_LIST_DIR}/../../components/phy/device/phyksz8081
    ${CMAKE_CURRENT_LIST_DIR}/../../components/power_manager/core
    ${CMAKE_CURRENT_LIST_DIR}/../../components/power_manager/devices/RW612
    ${CMAKE_CURRENT_LIST_DIR}/../../components/rng
    ${CMAKE_CURRENT_LIST_DIR}/../../components/rpmsg
    ${CMAKE_CURRENT_LIST_DIR}/../../components/rtt
    ${CMAKE_CURRENT_LIST_DIR}/../../components/serial_manager
    ${CMAKE_CURRENT_LIST_DIR}/../../components/silicon_id
    ${CMAKE_CURRENT_LIST_DIR}/../../components/silicon_id/socs/rw610
    ${CMAKE_CURRENT_LIST_DIR}/../../components/time_stamp
    ${CMAKE_CURRENT_LIST_DIR}/../../components/timer
    ${CMAKE_CURRENT_LIST_DIR}/../../components/timer_manager
    ${CMAKE_CURRENT_LIST_DIR}/../../components/uart
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/cache/cache64
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/cdog
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/cns_acomp
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/cns_adc
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/cns_dac
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/common
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/ctimer
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/dmic
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/enet
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/flexcomm
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/flexspi
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/fmeas
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/gdma
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/imu
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/inputmux
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/itrc_1
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/lcdic
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/lpc_crc
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/lpc_dma
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/lpc_gpio
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/lpc_rtc
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/mrt
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/ostimer
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/pint
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/powerquad
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/sctimer
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/smartcard
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/trng
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/utick
    ${CMAKE_CURRENT_LIST_DIR}/../../drivers/wwdt
    ${CMAKE_CURRENT_LIST_DIR}/../../../middleware
    ${CMAKE_CURRENT_LIST_DIR}/../../utilities
    ${CMAKE_CURRENT_LIST_DIR}/../../utilities/assert
    ${CMAKE_CURRENT_LIST_DIR}/../../utilities/misc_utilities
    ${CMAKE_CURRENT_LIST_DIR}/../../utilities/shell
    ${CMAKE_CURRENT_LIST_DIR}/drivers
    ${CMAKE_CURRENT_LIST_DIR}/drivers/romapi
)


# Copy the cmake components into projects
#    include(component_els_pkc_platform_rw61x_standalone_clib_gdet_sensor)
#    include(component_els_pkc_standalone_keyManagement)
#    include(driver_flexcomm_usart_dma)
#    include(component_wm8904_adapter)
#    include(driver_gdma)
#    include(device_startup)
#    include(CMSIS_DSP_Source)
#    include(component_els_pkc_els_header_only)
#    include(driver_cmsis_flexcomm_spi)
#    include(driver_codec)
#    include(driver_wm8904)
#    include(driver_pint)
#    include(component_els_pkc_cipher)
#    include(driver_cmsis_flexcomm_i2c)
#    include(component_power_manager_rdrw610)
#    include(driver_cmsis_flexcomm_usart)
#    include(component_els_pkc_random)
#    include(component_els_pkc_cipher_modes)
#    include(middleware_baremetal)
#    include(component_software_rng_adapter)
#    include(component_timer_manager)
#    include(component_els_pkc_param_integrity)
#    include(driver_sctimer)
#    include(driver_nor_flash-common)
#    include(CMSIS_Driver_Include_USART)
#    include(CMSIS_Device_API_RTOS2)
#    include(driver_conn_fwloader)
#    include(component_mflash_file_RW612)
#    include(component_els_pkc_random_modes)
#    include(driver_imu)
#    include(CMSIS_Driver_Include_Common)
#    include(driver_ctimer)
#    include(device_CMSIS)
#    include(driver_trng)
#    include(component_common_task)
#    include(driver_common)
#    include(component_els_pkc_mac)
#    include(driver_flash_config_rdrw612bga)
#    include(component_els_pkc_session)
#    include(driver_wwdt)
#    include(component_els_pkc_flow_protection)
#    include(component_serial_manager_uart)
#    include(component_els_pkc_secure_counter)
#    include(component_power_manager_core)
#    include(component_silicon_id_rw610)
#    include(component_codec_i2c_RW612)
#    include(component_els_pkc_hmac)
#    include(component_els_pkc_els_common)
#    include(utility_debug_console)
#    include(component_flexcomm_i2c_adapter)
#    include(driver_cns_acomp)
#    include(driver_cdog)
#    include(driver_smartcard_phy_usim)
#    include(component_els_pkc_standalone_gdet)
#    include(driver_power)
#    include(component_els_pkc_trng_type_rng4)
#    include(utility_assert)
#    include(driver_flexcomm_spi)
#    include(driver_reset)
#    include(component_els_pkc_platform_rw61x_interface_files)
#    include(component_els_pkc_hash)
#    include(utility_str)
#    include(component_osa_RW612)
#    include(driver_cns_dac)
#    include(driver_utick)
#    include(driver_lpc_rtc)
#    include(driver_ft6x06)
#    include(CMSIS_Device_API_OSTick)
#    include(driver_inputmux_connections)
#    include(component_els_pkc_psa_driver)
#    include(component_ostimer_time_stamp_adapter)
#    include(driver_flexspi_dma)
#    include(component_mem_manager_light)
#    include(driver_fmeas)
#    include(CMSIS_RTOS2_Common)
#    include(component_els_pkc_math)
#    include(driver_phy-device-ksz8081)
#    include(driver_mrt)
#    include(utility_shell)
#    include(driver_powerquad_cmsis)
#    include(component_els_pkc_aead)
#    include(driver_cns_io_mux)
#    include(component_els_pkc)
#    include(component_silicon_id_RW612)
#    include(driver_ocotp)
#    include(driver_cns_adc)
#    include(driver_iped)
#    include(driver_itrc_1)
#    include(driver_flexcomm_usart)
#    include(driver_smartcard_usim)
#    include(component_els_pkc_prng)
#    include(component_log_backend_debugconsole_RW612)
#    include(driver_flexcomm_i2c_dma)
#    include(CMSIS_Driver_Include_SPI)
#    include(component_els_pkc_data_integrity)
#    include(component_serial_manager)
#    include(component_osa_bm)
#    include(driver_lpc_crc)
#    include(component_audio_flexcomm_i2s_dma_adapter)
#    include(component_els_pkc_aead_modes)
#    include(driver_rtt_RW612)
#    include(component_els_pkc_pre_processor)
#    include(utility_assert_lite)
#    include(driver_memory)
#    include(CMSIS_RTOS2_NonSecure)
#    include(utilities_misc_utilities_RW612)
#    include(component_els_pkc_rsa)
#    include(driver_flexcomm_i2s)
#    include(driver_nor_flash-controller-flexspi)
#    include(component_els_pkc_aes)
#    include(component_els_pkc_els)
#    include(CMSIS_Driver_Include_I2C)
#    include(component_els_pkc_ecc)
#    include(driver_powerquad)
#    include(component_mrt_adapter)
#    include(driver_dmic)
#    include(driver_enet)
#    include(driver_flexcomm)
#    include(component_els_pkc_padding)
#    include(component_log)
#    include(driver_cache_cache64)
#    include(driver_flexcomm_spi_dma)
#    include(driver_flexcomm_i2c)
#    include(CMSIS_DSP_Include)
#    include(component_els_pkc_core)
#    include(component_lists)
#    include(component_els_pkc_key)
#    include(driver_dmic_dma)
#    include(driver_lpc_dma)
#    include(component_els_pkc_trng)
#    include(component_els_pkc_platform_rw61x)
#    include(component_els_pkc_memory)
#    include(driver_phy-common_RW612)
#    include(utility_debug_console_lite)
#    include(component_els_pkc_pkc)
#    include(component_els_pkc_mac_modes)
#    include(CMSIS_Include_core_cm)
#    include(driver_ostimer)
#    include(component_lpc_gpio_adapter)
#    include(component_trng_adapter)
#    include(component_els_pkc_toolchain)
#    include(component_mflash_rdrw610)
#    include(component_button_RW612)
#    include(driver_lcdic_dma)
#    include(component_osa_interface)
#    include(component_mem_manager)
#    include(driver_inputmux)
#    include(driver_clock)
#    include(component_wireless_imu_adapter)
#    include(component_usart_adapter)
#    include(component_mflash_common)
#    include(driver_ili9341)
#    include(driver_flexcomm_i2s_dma)
#    include(driver_lpc_gpio)
#    include(driver_lcdic)
#    include(driver_romapi)
#    include(component_messaging)
#    include(driver_flexspi)
