message("connectivity_framework middleware is included.")
if(CONFIG_SOC_SERIES_RW6XX)
    target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/platform/rw61x/fwk_platform_ble.c
        ${CMAKE_CURRENT_LIST_DIR}/platform/rw61x/fwk_platform_coex.c
        ${CMAKE_CURRENT_LIST_DIR}/platform/rw61x/fwk_platform_hdlc.c
        ${CMAKE_CURRENT_LIST_DIR}/platform/rw61x/fwk_platform_ot.c
    )

    zephyr_include_directories(
        ${CMAKE_CURRENT_LIST_DIR}/platform/include
        ${CMAKE_CURRENT_LIST_DIR}/platform/rw61x
        ${CMAKE_CURRENT_LIST_DIR}/platform/rw61x/configs
    )
endif()
