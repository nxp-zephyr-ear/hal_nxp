include_guard()
message("driver_conn_fwloader component is included.")

# To be migrated to use the hal_nxp release path of conn_fwloader
if(NOT CONFIG_BUILD_WITH_TFM)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/fsl_loader.c
    ${CMAKE_CURRENT_LIST_DIR}/nboot_hal.c
    ${CMAKE_CURRENT_LIST_DIR}/life_cycle.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
)
endif()