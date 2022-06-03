#!/usr/bin/env bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2022, Intel Corporation
#

LIMITS="/etc/security/limits.conf"

echo "* soft memlock unlimited" >> $LIMITS
echo "* hard memlock unlimited" >> $LIMITS
echo "* soft nofile 1048000" >> $LIMITS
echo "* hard nofile 1048000" >> $LIMITS

cat $LIMITS | grep -e memlock -e nofile
