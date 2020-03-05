#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020, Intel Corporation
#

include(${SRC_DIR}/../cmake/helpers.cmake)

setup()

set(ADDRESS "10.91.124.124")
set(PORT "8000")
set(SERVER "s")
set(CLIENT "c")
set(FILE "./file")

set(CTRLD "ctrld/ctrld")
set(PID_FILE "./pid.txt")
set(SIGNAL "SIGTERM")
set(TIMEOUT 60)

execute(${CTRLD} ${PID_FILE} run ${TIMEOUT} ${TEST_EXECUTABLE} ${SERVER} ${ADDRESS} ${PORT} ${FILE})
execute(${TEST_EXECUTABLE} ${CLIENT} ${ADDRESS} ${PORT})
execute(${TEST_EXECUTABLE} ${CLIENT} ${ADDRESS} ${PORT})
execute(${TEST_EXECUTABLE} ${CLIENT} ${ADDRESS} ${PORT})
execute(${TEST_EXECUTABLE} ${CLIENT} ${ADDRESS} ${PORT})
execute(${CTRLD} ${PID_FILE} kill "SIGTERM")
execute(${CTRLD} ${PID_FILE} kill "SIGKILL")

finish()
