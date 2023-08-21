if(CONFIG_IEEE802154_MCR20A)
  zephyr_include_directories(mcr20a)
endif()
add_subdirectory_ifdef(CONFIG_WIFI_NXP wifi_bt_module)

if(CONFIG_NXP_FW_LOADER)
    list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/conn_fwloader)
    include(driver_conn_fwloader)
endif()

if(CONFIG_NXP_RF_IMU)
    list(APPEND CMAKE_MODULE_PATH
        ${CMAKE_CURRENT_LIST_DIR}/rpmsg
    )
    include(component_wireless_imu_adapter)
endif()

