#*******************************************************************************
# Copyright (C) Sierra Wireless Inc.
#*******************************************************************************

# Tests
enable_testing()

# Output
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/tests/bin)
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/tests/lib)
set(APP_OUTPUT_PATH ${CMAKE_BINARY_DIR}/tests/apps)
set(DATA_OUTPUT_PATH ${CMAKE_BINARY_DIR}/tests/data)

file(MAKE_DIRECTORY ${EXECUTABLE_OUTPUT_PATH})
file(MAKE_DIRECTORY ${LIBRARY_OUTPUT_PATH})
file(MAKE_DIRECTORY ${APP_OUTPUT_PATH})

# fwupdateDualSys unitary test
add_subdirectory(fwupdateDualsysUnitTest)

# fwupdateSingleSys unitary test
add_subdirectory(fwupdateSinglesysUnitTest)

# pa_flash unitary test
add_subdirectory(pa_flashUnitTest)

# Single system Suspend/Resume unitary test
add_subdirectory(fwupdateSuspendResumeUnitTest)
