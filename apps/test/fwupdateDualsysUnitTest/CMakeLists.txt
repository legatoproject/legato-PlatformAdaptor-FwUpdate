#*******************************************************************************
# Copyright (C) Sierra Wireless Inc.
#*******************************************************************************
if ($ENV{TARGET} MATCHES "localhost")
    set(LEGATO_FRAMEWORK_SRC "${LEGATO_ROOT}/framework/liblegato")
    set(LEGATO_FRAMEWORK_INC "${LEGATO_ROOT}/framework/include")
    set(TEST_EXEC fwupdateDualsysUnitTest)
    set(LEGATO_FWUPDATE "${LEGATO_ROOT}/platformAdaptor/fwupdate/mdm9x40/le_pa_fwupdate_dualsys")
    set(LEGATO_CFG_ENTRIES "${LEGATO_ROOT}/components/cfgEntries")
    set(LEGATO_CFG_TREE "${LEGATO_FRAMEWORK_SRC}/configTree")
    set(TEST_SOURCE "${LEGATO_ROOT}/apps/test/fwupdate/fwupdateDualsysUnitTest")
    set(MKEXE_CFLAGS "-fvisibility=default -g $ENV{CFLAGS}")

    if(TEST_COVERAGE EQUAL 1)
       set(CFLAGS "--cflags=\"--coverage\"")
       set(LFLAGS "--ldflags=\"--coverage\"")
    endif()

    mkexe(${TEST_EXEC}
       fwupdateInitComponent
       fwupdateDualsys
       .
       -i ${LEGATO_ROOT}/platformAdaptor/fwupdate/pa_flash/inc
       -i ${LEGATO_ROOT}/platformAdaptor/fwupdate/pa_patch/inc
       -i ${LEGATO_ROOT}/platformAdaptor/fwupdate/common
       -i ${LEGATO_FWUPDATE}
       -i ${LEGATO_FRAMEWORK_SRC}
       -i ${LEGATO_FRAMEWORK_INC}
       -i ${LEGATO_CFG_TREE}
       -i ${LEGATO_CFG_ENTRIES}
       -i ${LEGATO_ROOT}/components/fwupdate/platformAdaptor/inc
       -i ${LEGATO_ROOT}/components/fwupdate/fwupdateDaemon
       -i ${LEGATO_ROOT}/3rdParty/bsdiff-4.3
       -i ${LEGATO_ROOT}/3rdParty/include
       ${CFLAGS}
       ${LFLAGS}
       -C ${MKEXE_CFLAGS}
    )
    add_test(${TEST_EXEC} ${EXECUTABLE_OUTPUT_PATH}/${TEST_EXEC})

    # This is a C test
    add_dependencies(tests_c ${TEST_EXEC})
endif()
