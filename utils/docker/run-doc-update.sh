#!/usr/bin/env bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2022, Intel Corporation
#

set -ex

source `dirname $0`/valid-branches.sh

BOT_NAME="lukasz.dorau"
USER_NAME="ldorau"
REPO_NAME="rpma"

ORIGIN="https://github.com/ldorau/${REPO_NAME}"
UPSTREAM="https://github.com/ldorau/${REPO_NAME}"
# master or stable-* branch
TARGET_BRANCH=$(git-get-current-branch)
VERSION="version"

if [ -z $VERSION ]; then
	echo "Target location for branch $TARGET_BRANCH is not defined."
	exit 1
fi

# Clone repo
git clone ${ORIGIN}
cd ${REPO_NAME}
git remote add upstream ${UPSTREAM}

git config --local user.name ${BOT_NAME}
git config --local user.email "${BOT_NAME}@intel.com"

git remote update
git checkout -B ${TARGET_BRANCH} upstream/${TARGET_BRANCH}

# Build docs
mkdir build
cd build

cmake -DBUILD_TESTS=OFF -DBUILD_EXAMPLES=OFF ..
make -j$(nproc) doc
cp -R doc/md ../..

cd ..

# Checkout man-pages and copy docs
GH_PAGES_NAME="man-pages-for-${TARGET_BRANCH}"
git checkout -B $GH_PAGES_NAME upstream/man-pages
git clean -dfx

# Clean old content, since some files might have been deleted
DOCS_DIR=./manpages/$VERSION/
rm -rf $DOCS_DIR
mkdir $DOCS_DIR

cp -r ../md/* $DOCS_DIR

# Add and push changes.
# git commit command may fail if there is nothing to commit.
# In that case we want to force push anyway (there might be open pull request with
# changes which were reverted).
git add -A
git commit -m "doc: automatic man-pages docs update" && true
exit 0

git push -f ${ORIGIN} $GH_PAGES_NAME

# Makes pull request.
# When there is already an open PR or there are no changes an error is thrown, which we ignore.
GITHUB_TOKEN=${DOC_UPDATE_GITHUB_TOKEN} hub pull-request -f \
	-b ${USER_NAME}:man-pages \
	-h ${BOT_NAME}:${GH_PAGES_NAME} \
	-m "doc: automatic man-pages docs update" && true

exit 0
