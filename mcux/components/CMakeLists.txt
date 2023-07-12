if(CONFIG_IEEE802154_MCR20A)
  zephyr_include_directories(mcr20a)
endif()
add_subdirectory_ifdef(CONFIG_WIFI_NXP wifi_bt_module)
