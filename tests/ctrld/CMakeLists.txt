#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2020, Intel Corporation
#

include_directories(.
	${CMAKE_SOURCE_DIR}/src/common/
	${CMAKE_SOURCE_DIR}/src/valgrind/)

add_cstyle(ctrld)
add_check_whitespace(ctrld)

set(COMMON ${CMAKE_SOURCE_DIR}/src/common)

set(SOURCES
	${COMMON}/alloc.c
	${COMMON}/os_posix.c
	${COMMON}/util.c
	ctrld.c)

add_executable(ctrld ${SOURCES})
