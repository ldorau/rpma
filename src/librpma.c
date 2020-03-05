/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2020, Intel Corporation
 */

/*
 * librpma.c -- entry points for librpma
 */

#include "out.h"
#include "util.h"

#include "librpma.h"
#include "rpma.h"

/*
 * librpma_init -- load-time initialization for librpma
 *
 * Called automatically by the run-time loader.
 */
ATTR_CONSTRUCTOR
void
librpma_init(void)
{
	util_init();
	out_init(RPMA_LOG_PREFIX, RPMA_LOG_LEVEL_VAR, RPMA_LOG_FILE_VAR,
		 RPMA_MAJOR_VERSION, RPMA_MINOR_VERSION);

	LOG(3, NULL);
	/* XXX possible rpma_init placeholder */
}

/*
 * librpma_fini -- librpma cleanup routine
 *
 * Called automatically when the process terminates.
 */
ATTR_DESTRUCTOR
void
librpma_fini(void)
{
	LOG(3, NULL);

	out_fini();
}

/*
 * rpma_errormsg -- return last error message
 */
const char *
rpma_errormsg(void)
{
	return out_get_errormsg();
}
