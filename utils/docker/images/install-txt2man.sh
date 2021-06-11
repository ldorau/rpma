#!/usr/bin/env bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2021, Intel Corporation
#

#
# install-txt2man.sh - installs txt2man
#

set -e

git clone https://github.com/mvertes/txt2man.git
cd txt2man

# txt2man v1.7.1
git checkout txt2man-1.7.1

make -j$(nproc)
sudo make -j$(nproc) install prefix=/usr
cd ..
rm -r txt2man
