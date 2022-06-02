#!/usr/bin/env bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2021-2022, Intel Corporation
#

#
#

set -e

# Update existing packages
sudo apt-get update --allow-unauthenticated

sudo apt-get install --assume-yes --no-install-recommends --allow-unauthenticated linux-modules-extra-$(uname -r)
