#!/bin/bash -e

# Sep 24 2021
# common: 1.11.1 release
PMDK_VERSION=1.11.1
DIR="pmdk-${PMDK_VERSION}"

WORKDIR=$(pwd)
ZIP_FILE="pmdk.zip"

# install pmdk
wget -O $ZIP_FILE https://github.com/pmem/pmdk/archive/${PMDK_VERSION}.zip
unzip $ZIP_FILE
mkdir -p $DIR
cd $DIR
make -j$(nproc)
sudo make -j$(nproc) install prefix=/usr
cd $WORKDIR
rm -rf $ZIP_FILE $DIR
