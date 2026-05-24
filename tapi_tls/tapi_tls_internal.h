/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief TLS TAPI: internal helpers
 *
 * Internal to tsf-tls; not installed.
 */

#ifndef __TSF_TAPI_TLS_INTERNAL_H__
#define __TSF_TAPI_TLS_INTERNAL_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_job.h"

#include "tapi_devtool_run.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Append one argument to a vector, taking ownership of it. */
extern void tapi_tls_arg(te_vec *args, const char *fmt, ...)
    TE_LIKE_PRINTF(2, 3);

/**
 * Run @p program with @p args and wait for it.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  name         Tool name for log messages.
 * @param[in]  program      Program name or path.
 * @param[in]  args         Arguments after @c argv[0].
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] run          Run handle; release it with
 *                          tapi_devtool_run_fini().
 *
 * @return Status code of running the command, not of the command.
 */
extern te_errno tapi_tls_cmd(tapi_job_factory_t *factory, const char *name,
                             const char *program, const te_vec *args,
                             int timeout_ms, tapi_devtool_run *run);

/**
 * Start @p program with @p args and leave it running.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  name         Tool name for log messages.
 * @param[in]  program      Program name or path.
 * @param[in]  args         Arguments after @c argv[0].
 * @param[out] run          Run handle; stop it and release it with
 *                          tapi_devtool_run_stop() and
 *                          tapi_devtool_run_fini().
 *
 * @return Status code.
 */
extern te_errno tapi_tls_spawn(tapi_job_factory_t *factory, const char *name,
                               const char *program, const te_vec *args,
                               tapi_devtool_run *run);

/**
 * Put a blob on the agent, in its temporary directory.
 *
 * @param[in]  ta       Agent name.
 * @param[in]  content  What to write.
 * @param[in]  suffix   Suffix for the generated name, e.g. @c ".pem".
 * @param[out] path     String to append the path to.
 *
 * @return Status code.
 */
extern te_errno tapi_tls_put_file(const char *ta, const char *content,
                                  const char *suffix, te_string *path);

/**
 * Read the value that follows @p key on a line of @p text.
 *
 * @param text      Text to look in.
 * @param key       What the value follows, e.g. @c "subject=".
 * @param stop      Characters that end the value.
 *
 * @return A fresh string, or @c NULL when the key is not there.
 */
extern char *tapi_tls_field(const char *text, const char *key,
                            const char *stop);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_TLS_INTERNAL_H__ */
