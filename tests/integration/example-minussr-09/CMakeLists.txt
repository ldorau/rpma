#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020-2021, Intel Corporation
#

include(../../cmake/ctest_helpers.cmake)

set(TARGET "example-minussr-09")

if(NOT LIBPROTOBUFC_FOUND)
	message(STATUS "${TARGET} skipped - no libprotobuf-c found")
	return()
endif()

build_test_src(NAME ${TARGET} SRCS
	${CMAKE_SOURCE_DIR}/examples/09-flush-to-persistent-GPSPM/server.c
	${CMAKE_SOURCE_DIR}/examples/09-flush-to-persistent-GPSPM/client.c
	${CMAKE_SOURCE_DIR}/examples/09-flush-to-persistent-GPSPM/GPSPM_flush.pb-c.c
	${CMAKE_SOURCE_DIR}/examples/09-flush-to-persistent-GPSPM/GPSPM_flush.pb-c.h
	${CMAKE_SOURCE_DIR}/examples/common/common-conn.c
	${CMAKE_SOURCE_DIR}/examples/common/common-epoll.c
	${CMAKE_SOURCE_DIR}/tests/integration/minussr/minussr-main.c
	${CMAKE_SOURCE_DIR}/tests/integration/minussr/minussr-mocks.c
	${CMAKE_SOURCE_DIR}/tests/integration/minussr/minussr-trace.c
	${LIBRPMA_SOURCE_DIR}/conn.c
	${LIBRPMA_SOURCE_DIR}/conn_cfg.c
	${LIBRPMA_SOURCE_DIR}/conn_req.c
	${LIBRPMA_SOURCE_DIR}/flush.c
	${LIBRPMA_SOURCE_DIR}/ep.c
	${LIBRPMA_SOURCE_DIR}/info.c
	${LIBRPMA_SOURCE_DIR}/librpma.c
	${LIBRPMA_SOURCE_DIR}/log.c
	${LIBRPMA_SOURCE_DIR}/log_default.c
	${LIBRPMA_SOURCE_DIR}/mr.c
	${LIBRPMA_SOURCE_DIR}/peer.c
	${LIBRPMA_SOURCE_DIR}/peer_cfg.c
	${LIBRPMA_SOURCE_DIR}/private_data.c
	${LIBRPMA_SOURCE_DIR}/rpma.c
	${LIBRPMA_SOURCE_DIR}/rpma_err.c)

target_include_directories(${TARGET}
	PRIVATE ${CMAKE_SOURCE_DIR}/examples/common
	PRIVATE ${LIBPROTOBUFC_INCLUDE_DIRS})

target_compile_definitions(${TARGET}
       PUBLIC TEST_MOCK_MAIN
       PRIVATE SRCVERSION="0.0")

target_link_libraries(${TARGET} pthread ${LIBPROTOBUFC_LIBRARIES})

add_test_generic(NAME ${TARGET} TRACERS none)
