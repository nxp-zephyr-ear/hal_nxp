#Description: Driver conn_fwloader; user_visible: True
include_guard(GLOBAL)
message("driver_conn_fwloader component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/fsl_loader.c
    ${CMAKE_CURRENT_LIST_DIR}/nboot_hal.c
    ${CMAKE_CURRENT_LIST_DIR}/life_cycle.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
)


include(component_osa_bm)
include(driver_ocotp)
