if(CONFIG_NXP_FW_LOADER_MONOLITHIC)
	# TODO: currently, the binary blobs are not public so we can't fetch them with west blob
	# So, when the firmwares will be published to a public repo, we'll be able to fetch them
	# and update this path to the fetch path
	set(hal_blobs_dir ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/components/fw_bin)

	set(signed_binary_blobs_list)
	set(raw_binary_blobs_list)
	set(binary_blobs_list)
	set(output_includes_list)

	if(CONFIG_WIFI)
		list(APPEND output_includes_list ${ZEPHYR_BINARY_DIR}/include/generated/rw61x_wifi_fw.bin.inc)

		if(CONFIG_SOC_SERIES_RW6XX_REVISION_A1)
			set(signed_binary_blob_name rw61x_sb_wifi_a1.bin)
			set(raw_binary_blob_name rw61xw_raw_cpu1_a1.bin)
		elseif(CONFIG_SOC_SERIES_RW6XX_REVISION_A2)
			set(signed_binary_blob_name rw61x_sb_wifi_a2.bin)
			set(raw_binary_blob_name rw61xw_raw_cpu1_a2.bin)
		else()
			message(FATAL_ERROR "Couldn't determine soc revision, check SOC_SERIES_RW6XX_REVISION")
		endif()

		list(APPEND signed_binary_blobs_list ${hal_blobs_dir}/${signed_binary_blob_name})
		list(APPEND raw_binary_blobs_list ${hal_blobs_dir}/${raw_binary_blob_name})

		zephyr_library_sources(${CMAKE_CURRENT_LIST_DIR}/rw61x_cpu1.c)
	endif()
	if(CONFIG_BT)
		list(APPEND output_includes_list ${ZEPHYR_BINARY_DIR}/include/generated/rw61x_ble_fw.bin.inc)

		if(CONFIG_SOC_SERIES_RW6XX_REVISION_A1)
			set(signed_binary_blob_name rw61x_sb_ble_a1.bin)
			set(raw_binary_blob_name rw61xn_raw_cpu2_ble_a1.bin)
		elseif(CONFIG_SOC_SERIES_RW6XX_REVISION_A2)
			set(signed_binary_blob_name rw61x_sb_ble_a2.bin)
			set(raw_binary_blob_name rw61xn_raw_cpu2_ble_a2.bin)
		else()
			message(FATAL_ERROR "Couldn't determine soc revision, check SOC_SERIES_RW6XX_REVISION")
		endif()

		list(APPEND signed_binary_blobs_list ${hal_blobs_dir}/${signed_binary_blob_name})
		list(APPEND raw_binary_blobs_list ${hal_blobs_dir}/${raw_binary_blob_name})

		zephyr_library_sources(${CMAKE_CURRENT_LIST_DIR}/rw61x_cpu2.c)
	endif()

	list(LENGTH signed_binary_blobs_list count)
	math(EXPR count "${count}-1")
	foreach(i RANGE ${count})
		list(GET signed_binary_blobs_list ${i} signed_binary_blob)
		list(GET raw_binary_blobs_list ${i} raw_binary_blob)
		if(EXISTS ${signed_binary_blob})
			set(binary_blob ${signed_binary_blob})
		elseif(EXISTS ${raw_binary_blob})
			set(binary_blob ${raw_binary_blob})
		else()
			message(FATAL_ERROR "Couldn't find signed nor raw firmware ! ${signed_binary_blob} ${raw_binary_blob}")
		endif()

		list(APPEND binary_blobs_list ${binary_blob})
	endforeach()

	list(LENGTH binary_blobs_list count)
	math(EXPR count "${count}-1")
	foreach(i RANGE ${count})
		list(GET binary_blobs_list ${i} binary_blob)
		list(GET output_includes_list ${i} output_include)
		message(STATUS " generate include of binary blob: ${binary_blob}")
		generate_inc_file_for_target(${ZEPHYR_CURRENT_LIBRARY} ${binary_blob} ${output_include})
	endforeach()
endif()
