include_guard()
message("component_wireless_imu_adapter component is included.")

zephyr_compile_definitions(IMU_TASK_PRIORITY=3)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/fsl_adapter_rfimu.c
)


target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/.
)
