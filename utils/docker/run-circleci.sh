#!/usr/bin/env bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2022, Intel Corporation
#

#
# run-circleci.sh - is called inside a Docker container,
#                   starts rpma build with tests.
#

set -ex

cd $WORKDIR
echo "Current directory: $(pwd)"
echo RPMA_SOFT_ROCE_IP=$RPMA_SOFT_ROCE_IP

echo "Building rpma ..."
mkdir build
cd build
cmake .. -DTESTS_USE_VALGRIND=ON
make -j$(nproc)

echo "Running all tests ..."
ctest --output-on-failure

echo "Running all examples ..."
make run_all_examples

echo "Running all examples under valgrind ..."
make run_all_examples_under_valgrind
