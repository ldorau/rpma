/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright 2021, Intel Corporation */

/*
 * minussr-utils.h -- Minimal User-Space Soft RoCE (minussr) utils' header
 */

#include <assert.h>

#define MIN(x, y)			(((x) < (y)) ? (x) : (y))

#define assert_null(ptr)		(assert((void *)(ptr) == NULL))
#define assert_non_null(ptr)		(assert((void *)(ptr) != NULL))
#define assert_int_equal(val1, val2)	(assert((val1) == (val2)))
