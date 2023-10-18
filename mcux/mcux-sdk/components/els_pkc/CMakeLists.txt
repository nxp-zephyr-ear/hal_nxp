
add_library(McuxElsPkc) 

target_compile_options(
    McuxElsPkc
    PUBLIC
        ${TOOLCHAIN_C_FLAGS}
        -mcmse  # Why is this not even part of the default zephyr build options?
)

target_link_options(
    McuxElsPkc
    PUBLIC
        ${TOOLCHAIN_LD_FLAGS}
)

target_include_directories(McuxElsPkc
    PUBLIC
        # SDK driver header files
        ../../drivers/common
        # psa/crypto.h and psa/crypto_types.h
        ../../../../../../crypto/mbedtls/include
        ../../../../../../crypto/mbedtls/include/psa
        # for psa driver wrapper
        ../../../../../../crypto/mbedtls/library
)

if(CONFIG_SOC_SERIES_RW6XX)

    target_compile_definitions(
        McuxElsPkc 
        PUBLIC
            CPU_RW612ETA1I
    ) 

    target_include_directories(McuxElsPkc
        PUBLIC
            src/platforms/rw61x/
            src/platforms/rw61x/cmsis_cortex_m_5_5_1/inc
            src/platforms/rw61x/inc
            ../../devices/RW612
            ../../devices/RW612/drivers
    )

    target_sources(McuxElsPkc
        PRIVATE
            src/platforms/rw61x/mcux_els.c
            src/platforms/rw61x/mcux_pkc.c
    )
endif()


install(TARGETS McuxElsPkc
        EXPORT McuxElsPkcTargets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT McuxElsPkcTargets
        FILE McuxElsPkcTargets.cmake
        NAMESPACE McuxElsPkc::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/McuxElsPkcTargets
)

export(EXPORT McuxElsPkcTargets
    FILE "${CMAKE_CURRENT_BINARY_DIR}/McuxElsPkcTargets.cmake"
    NAMESPACE McuxElsPkc::
)

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/src)
