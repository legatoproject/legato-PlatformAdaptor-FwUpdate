#*******************************************************************************
# Copyright (C) Sierra Wireless Inc.
#*******************************************************************************
if ($ENV{TARGET} MATCHES "localhost")
    set(LEGATO_FRAMEWORK_SRC "${LEGATO_ROOT}/framework/liblegato")
    set(LEGATO_FRAMEWORK_INC "${LEGATO_ROOT}/framework/include")
    set(TEST_EXEC fwupdateSinglesysUnitTest)
    set(LEGATO_FWUPDATE "${LEGATO_ROOT}/platformAdaptor/fwupdate/mdm9x07/le_pa_fwupdate_singlesys")
    set(LEGATO_CFG_ENTRIES "${LEGATO_ROOT}/components/cfgEntries")
    set(LEGATO_CFG_TREE "${LEGATO_FRAMEWORK_SRC}/configTree")
    set(TEST_SOURCE "${LEGATO_ROOT}/apps/test/fwupdate/fwupdateSinglesysUnitTest")
    set(MKEXE_CFLAGS "-fvisibility=default -g $ENV{CFLAGS}")

    if(TEST_COVERAGE EQUAL 1)
       set(CFLAGS "--cflags=\"--coverage\"")
       set(LFLAGS "--ldflags=\"--coverage\"")
    endif()

    mkexe(${TEST_EXEC}
       ${LEGATO_ROOT}/platformAdaptor/fwupdate/apps/test/sys_flash
       fwupdateSinglesys
       fwupdateSinglesysInitComponent
       .
       -i ${LEGATO_ROOT}/platformAdaptor/fwupdate/apps/test/sys_flash
       -i ${LEGATO_ROOT}/platformAdaptor/fwupdate/common
       -i ${LEGATO_FWUPDATE}
       -i ${LEGATO_FRAMEWORK_SRC}
       -i ${LEGATO_FRAMEWORK_INC}
       -i ${LEGATO_CFG_TREE}
       -i ${LEGATO_CFG_ENTRIES}
       -i ${LEGATO_ROOT}/components/fwupdate/platformAdaptor/inc
       -i ${LEGATO_ROOT}/components/fwupdate/fwupdateDaemon
       -i ${LEGATO_ROOT}/3rdParty/include
       ${CFLAGS}
       ${LFLAGS}
       -C ${MKEXE_CFLAGS}
    )
    file(COPY cp.cwe DESTINATION ${EXECUTABLE_OUTPUT_PATH}/../data)
    file(COPY ls.cwe DESTINATION ${EXECUTABLE_OUTPUT_PATH}/../data)
    file(COPY ls2cp.cwe DESTINATION ${EXECUTABLE_OUTPUT_PATH}/../data)
    file(COPY cp2ls.cwe DESTINATION ${EXECUTABLE_OUTPUT_PATH}/../data)
    file(COPY cp_ubi.cwe DESTINATION ${EXECUTABLE_OUTPUT_PATH}/../data)
    file(COPY ls_ubi.cwe DESTINATION ${EXECUTABLE_OUTPUT_PATH}/../data)
    file(COPY ls2cp_ubi.cwe DESTINATION ${EXECUTABLE_OUTPUT_PATH}/../data)
    file(COPY cp2ls_ubi.cwe DESTINATION ${EXECUTABLE_OUTPUT_PATH}/../data)
    file(COPY keystore.cwe DESTINATION ${EXECUTABLE_OUTPUT_PATH}/../data)
    add_test(${TEST_EXEC} ${EXECUTABLE_OUTPUT_PATH}/${TEST_EXEC})

    # This is a C test
    add_dependencies(tests_c ${TEST_EXEC})
endif()
