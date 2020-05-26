#!/usr/bin/env bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2016-2020, Intel Corporation
#

#
# run-build.sh - is called inside a Docker container,
#                starts rpma build with tests.
#

set -e

if [ "$WORKDIR" == "" ]; then
	echo "Error: WORKDIR is not set"
	exit 1
fi

./prepare-for-build.sh

EXAMPLE_TEST_DIR="/tmp/rpma_example_build"
PREFIX=/usr
TEST_DIR=${RPMA_TEST_DIR:-${DEFAULT_TEST_DIR}}
CHECK_CSTYLE=${CHECK_CSTYLE:-ON}

function sudo_password() {
	echo $USERPASS | sudo -Sk $*
}

function cleanup() {
	find . -name ".coverage" -exec rm {} \;
	find . -name "coverage.xml" -exec rm {} \;
	find . -name "*.gcov" -exec rm {} \;
	find . -name "*.gcda" -exec rm {} \;
}

function upload_codecov() {
	clang_used=$(cmake -LA -N . | grep CMAKE_C_COMPILER | grep clang | wc -c)

	if [[ $clang_used > 0 ]]; then
		gcovexe="llvm-cov gcov"
	else
		gcovexe="gcov"
	fi

	# the output is redundant in this case, i.e. we rely on parsed report from codecov on github
	bash <(curl -s https://codecov.io/bash) -c -F $1 -x "$gcovexe"
	cleanup
}

function compile_example_standalone() {
	rm -rf $EXAMPLE_TEST_DIR
	mkdir $EXAMPLE_TEST_DIR
	cd $EXAMPLE_TEST_DIR

	cmake $1

	# exit on error
	if [[ $? != 0 ]]; then
		cd -
		return 1
	fi

	make -j$(nproc)
	cd -
}

function run_all_tests() {
	PREFIX=$1

	echo
	echo "##############################################################"
	echo "### Verify build and install (in dir: ${PREFIX})"
	echo "##############################################################"

	mkdir -p $WORKDIR/build
	cd $WORKDIR/build

	cmake .. -DCMAKE_BUILD_TYPE=Debug \
		-DTEST_DIR=$TEST_DIR \
		-DCMAKE_INSTALL_PREFIX=$PREFIX \
		-DCOVERAGE=$COVERAGE \
		-DCHECK_CSTYLE=${CHECK_CSTYLE} \
		-DDEVELOPER_MODE=1

	make -j$(nproc)
	make -j$(nproc) doc

	# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
	# XXX what about tests - when ? XXX
	ctest --output-on-failure
	# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

	sudo_password -S make -j$(nproc) install

	if [ "$COVERAGE" == "1" ]; then
		upload_codecov tests
	fi

	# Test standalone compilation of all examples
	EXAMPLES=$(ls -1 $WORKDIR/examples/)
	for e in $EXAMPLES; do
		DIR=$WORKDIR/examples/$e
		[ ! -d $DIR ] && continue
		[ ! -f $DIR/CMakeLists.txt ] && continue
		echo
		echo "###########################################################"
		echo "### Testing standalone compilation of example: $e"
		echo "###########################################################"
		compile_example_standalone $DIR
	done

	# Uninstall libraries
	cd $WORKDIR/build
	sudo_password -S make uninstall

	cd $WORKDIR
	rm -rf $WORKDIR/build
}

mkdir -p /tmp/rpma
PREFIXES="/tmp/rpma /usr/local /usr"
for pref in $PREFIXES; do
	run_all_tests $pref
done

