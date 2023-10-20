#-------------------------------------------------------------------------------
# Copyright (c) 2023, NXP Semiconductors. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

add_library(McuxPsaCryptoDriverElsPkc) 

target_compile_options(
    McuxPsaCryptoDriverElsPkc
    PUBLIC
        ${TOOLCHAIN_C_FLAGS}
        -mcmse  # Why is this not even part of the default zephyr build options?
)

target_link_options(
    McuxPsaCryptoDriverElsPkc
    PUBLIC
        ${TOOLCHAIN_LD_FLAGS}
)

target_include_directories(McuxPsaCryptoDriverElsPkc
    PRIVATE
        # SDK driver header files
        ../../drivers/common
        
        # psa/crypto.h and psa/crypto_types.h
        ../../../../../../crypto/mbedtls/include
        ../../../../../../crypto/mbedtls/include/psa
        # for psa driver wrapper
        ../../../../../../crypto/mbedtls/library
)

target_include_directories(McuxPsaCryptoDriverElsPkc
    PUBLIC

        #psa-crypto-driver for els_pkc include paths
        els_pkc/.
        els_pkc/include/common
        els_pkc/include/opaque
        els_pkc/include/transparent
        osal/.
        els_pkc/oracle
        els_pkc/oracle/inc
            
        #include the psa-driver inlcude path from clib
        ../els_pkc/src/comps/mcuxClPsaDriver/inc
        ../els_pkc/src/comps/mcuxClPsaDriver/inc/internal

        #include McuxElsPkc include directories
        "$<TARGET_PROPERTY:McuxElsPkc,INTERFACE_INCLUDE_DIRECTORIES>"
)


if(CONFIG_SOC_SERIES_RW6XX)

    target_compile_definitions(
        McuxPsaCryptoDriverElsPkc 
        PUBLIC
            CPU_RW612ETA1I
    ) 

    target_include_directories(McuxPsaCryptoDriverElsPkc
        PRIVATE
            # cmsis required to build els_pkc
            ../els_pkc/src/platforms/rw61x/cmsis_cortex_m_5_5_1/inc
    )

    target_sources(
        McuxPsaCryptoDriverElsPkc 
        PRIVATE
            els_pkc/oracle/src/mcuxClPsaDriver_Oracle.c
            els_pkc/oracle/src/mcuxClPsaDriver_Oracle_ElsUtils.c
            els_pkc/oracle/src/mcuxClPsaDriver_Oracle_Utils.c
            els_pkc/src/common/mcux_psa_els_pkc_common_init.c
            els_pkc/src/common/mcux_psa_els_pkc_entropy.c
            els_pkc/src/opaque/mcux_psa_els_pkc_opaque_aead.c
            els_pkc/src/opaque/mcux_psa_els_pkc_opaque_asymmetric_signature.c
            els_pkc/src/opaque/mcux_psa_els_pkc_opaque_cipher.c
            els_pkc/src/opaque/mcux_psa_els_pkc_opaque_init.c
            els_pkc/src/opaque/mcux_psa_els_pkc_opaque_key_generation.c
            els_pkc/src/opaque/mcux_psa_els_pkc_opaque_mac.c
            els_pkc/src/transparent/mcux_psa_els_pkc_aead.c
            els_pkc/src/transparent/mcux_psa_els_pkc_asymmetric_signature.c
            els_pkc/src/transparent/mcux_psa_els_pkc_cipher.c
            els_pkc/src/transparent/mcux_psa_els_pkc_hash.c
            els_pkc/src/transparent/mcux_psa_els_pkc_init.c
            els_pkc/src/transparent/mcux_psa_els_pkc_key_generation.c
            els_pkc/src/transparent/mcux_psa_els_pkc_mac.c
            
            # add psa-driver source files from els_pkc(clib) in this (psa_crypto_driver)lib
            ../els_pkc/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Aead.c
            ../els_pkc/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Cipher.c
            ../els_pkc/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_DER_functions.c
            ../els_pkc/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Hash.c
            ../els_pkc/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Key.c
            ../els_pkc/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Mac.c
            ../els_pkc/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Rsa.c
            ../els_pkc/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Sign.c
            ../els_pkc/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_UpdateKeyStatus.c
            ../els_pkc/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Verify.c
            ../els_pkc/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_export_public_key.c
            ../els_pkc/src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_generate_ecp_key.c
    )
endif()


export(TARGETS McuxPsaCryptoDriverElsPkc
    FILE "${CMAKE_CURRENT_BINARY_DIR}/McuxPsaCryptoDriverElsPkcTargets.cmake"
    NAMESPACE McuxPsaCryptoDriverElsPkc::
)

#link McuxElsPkc lib as psa-crypto-driver functions eventually calls els_pkc functions.
target_link_libraries(McuxPsaCryptoDriverElsPkc
    PRIVATE
        McuxElsPkc
)

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/osal)
