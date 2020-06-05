#!/bin/bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020, Intel Corporation
#

set -x

rm -f /var/lib/rpm/__db*

db_verify /var/lib/rpm/Packages
rpm --rebuilddb

ls -ald /var/lib/rpmrebuilddb.*
cp -rfv /var/lib/rpmrebuilddb.*/* /var/lib/rpm/

db_verify /var/lib/rpm/Packages
rpm --rebuilddb

yum clean all
