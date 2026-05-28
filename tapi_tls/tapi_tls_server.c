/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Testing the other end
 *
 * A server whose certificate is wrong in a chosen way, and a reading of
 * what the client did about it.
 */

#define TE_LGR_USER "TAPI TLS SERVER"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "tapi_cfg_base.h"
#include "tapi_file.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_tls_internal.h"
#include "tapi_tls_server.h"

/** How long the certificates are valid for, days. */
#define TLS_SERVER_DAYS     365

/**
 * How long the server is given to notice it is finished, ms.
 *
 * With -naccept it exits by itself after the last connection, but the
 * test asks the moment its client is done and the two races. A short
 * wait costs nothing when the server has already gone and saves the
 * statistics when it has not quite.
 */
#define TLS_SERVER_SETTLE_MS 3000

/** How long the server is given to start listening, ms. */
#define TLS_SERVER_READY_MS 10000

/** A moment safely in the past, for an expired certificate. */
#define TLS_SERVER_EXPIRED_AT   "20200101000000Z"

const tapi_tls_server_opt tapi_tls_server_default_opt = {
    .openssl     = NULL,
    .defect      = TAPI_TLS_SERVER_SELF_SIGNED,
    .common_name = NULL,
    .wrong_name  = NULL,
    .www         = true,
    .naccept     = 1,
};

struct tapi_tls_server {
    /** s_server job. */
    tapi_devtool_run run;
    /** Agent it listens on. */
    char *ta;
    /** Certificate of the test authority, or @c NULL. */
    char *ca_file;
    /** Files to remove when the server goes away. */
    te_vec scratch;
    /** How many connections it was asked to serve; @c 0 means all. */
    unsigned int naccept;
};

/* See description in tapi_tls_server.h */
const char *
tapi_tls_defect2str(tapi_tls_server_defect defect)
{
    switch (defect)
    {
        case TAPI_TLS_SERVER_SELF_SIGNED:
            return "self-signed";
        case TAPI_TLS_SERVER_EXPIRED:
            return "expired";
        case TAPI_TLS_SERVER_WRONG_NAME:
            return "wrong-name";
        default:
            return "valid";
    }
}

/** The name the certificate will claim. */
static const char *
tls_cert_name(const tapi_tls_server_opt *opt)
{
    if (opt->defect == TAPI_TLS_SERVER_WRONG_NAME)
    {
        return opt->wrong_name != NULL ? opt->wrong_name
                                       : "not.the.right.name.example";
    }

    return opt->common_name != NULL ? opt->common_name : "localhost";
}

/** Run one openssl command and insist that it worked. */
static te_errno
tls_openssl(tapi_job_factory_t *factory, const tapi_tls_server_opt *opt,
            const te_vec *args, int timeout_ms)
{
    tapi_devtool_output output;
    tapi_devtool_run run;
    te_errno rc;

    rc = tapi_tls_cmd(factory, "openssl",
                      opt->openssl != NULL ? opt->openssl : "openssl",
                      args, timeout_ms, &run);
    if (rc != 0)
        return rc;

    tapi_devtool_run_get_output(&run, &output);

    if (output.status.type != TAPI_JOB_STATUS_EXITED ||
        output.status.value != 0)
    {
        ERROR("openssl failed: %s", output.err);
        rc = TE_RC(TE_TAPI, TE_ESHCMD);
    }

    tapi_devtool_run_fini(&run);

    return rc;
}

/** Make a path in the directory the server works in. */
static void
tls_scratch_path(const char *ta, const tapi_tls_server_opt *opt,
                 const char *suffix, te_string *path)
{
    char *tmp_dir = NULL;
    const char *dir = opt->work_dir;

    if (dir == NULL)
    {
        tmp_dir = tapi_cfg_base_get_ta_dir(ta, TAPI_CFG_BASE_TA_DIR_TMP);
        dir = tmp_dir;
    }

    tapi_file_make_custom_pathname(path, dir, suffix);
    free(tmp_dir);
}

/* See description in tapi_tls_server.h */
te_errno
tapi_tls_server_make_cert(tapi_job_factory_t *factory,
                          const tapi_tls_server_opt *opt, int timeout_ms,
                          te_string *cert_file, te_string *key_file,
                          te_string *ca_file)
{
    const char *ta = tapi_job_factory_ta(factory);
    const char *name = tls_cert_name(opt);
    te_string ca_key = TE_STRING_INIT;
    te_string ca_crt = TE_STRING_INIT;
    te_string csr = TE_STRING_INIT;
    te_string ext = TE_STRING_INIT;
    te_vec args = TE_VEC_INIT(char *);
    te_errno rc;

    if (ta == NULL)
    {
        ERROR("Cannot determine the agent behind the job factory");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    tls_scratch_path(ta, opt, ".crt", cert_file);
    tls_scratch_path(ta, opt, ".key", key_file);

    if (opt->defect == TAPI_TLS_SERVER_SELF_SIGNED)
    {
        /* Nothing signs it but itself, which is the whole point. */
        tapi_tls_arg(&args, "req");
        tapi_tls_arg(&args, "-x509");
        tapi_tls_arg(&args, "-newkey");
        tapi_tls_arg(&args, "rsa:2048");
        tapi_tls_arg(&args, "-nodes");
        tapi_tls_arg(&args, "-keyout");
        tapi_tls_arg(&args, "%s", key_file->ptr);
        tapi_tls_arg(&args, "-out");
        tapi_tls_arg(&args, "%s", cert_file->ptr);
        tapi_tls_arg(&args, "-days");
        tapi_tls_arg(&args, "%u", TLS_SERVER_DAYS);
        tapi_tls_arg(&args, "-subj");
        tapi_tls_arg(&args, "/CN=%s", name);
        tapi_tls_arg(&args, "-addext");
        tapi_tls_arg(&args, "subjectAltName=DNS:%s", name);

        rc = tls_openssl(factory, opt, &args, timeout_ms);
        te_vec_deep_free(&args);

        return rc;
    }

    /*
     * Everything else is signed by a test authority, so that the only
     * thing wrong with the certificate is the thing under test.
     */
    tls_scratch_path(ta, opt, ".ca.key", &ca_key);
    tls_scratch_path(ta, opt, ".ca.crt", &ca_crt);
    tls_scratch_path(ta, opt, ".csr", &csr);

    tapi_tls_arg(&args, "req");
    tapi_tls_arg(&args, "-x509");
    tapi_tls_arg(&args, "-newkey");
    tapi_tls_arg(&args, "rsa:2048");
    tapi_tls_arg(&args, "-nodes");
    tapi_tls_arg(&args, "-keyout");
    tapi_tls_arg(&args, "%s", ca_key.ptr);
    tapi_tls_arg(&args, "-out");
    tapi_tls_arg(&args, "%s", ca_crt.ptr);
    tapi_tls_arg(&args, "-days");
    tapi_tls_arg(&args, "%u", TLS_SERVER_DAYS);
    tapi_tls_arg(&args, "-subj");
    tapi_tls_arg(&args, "/CN=tsf-test-ca");

    rc = tls_openssl(factory, opt, &args, timeout_ms);
    te_vec_deep_free(&args);
    if (rc != 0)
        goto out;

    args = (te_vec)TE_VEC_INIT(char *);
    tapi_tls_arg(&args, "req");
    tapi_tls_arg(&args, "-new");
    tapi_tls_arg(&args, "-newkey");
    tapi_tls_arg(&args, "rsa:2048");
    tapi_tls_arg(&args, "-nodes");
    tapi_tls_arg(&args, "-keyout");
    tapi_tls_arg(&args, "%s", key_file->ptr);
    tapi_tls_arg(&args, "-out");
    tapi_tls_arg(&args, "%s", csr.ptr);
    tapi_tls_arg(&args, "-subj");
    tapi_tls_arg(&args, "/CN=%s", name);

    rc = tls_openssl(factory, opt, &args, timeout_ms);
    te_vec_deep_free(&args);
    if (rc != 0)
        goto out;

    /*
     * A modern client looks at the subject alternative name and not at
     * the common name, so the name under test has to be there.
     */
    {
        te_string content = TE_STRING_INIT;

        te_string_append(&content, "subjectAltName=DNS:%s\n", name);
        rc = tapi_tls_put_file(ta, content.ptr, ".ext", &ext);
        te_string_free(&content);
        if (rc != 0)
            goto out;
    }

    args = (te_vec)TE_VEC_INIT(char *);
    tapi_tls_arg(&args, "x509");
    tapi_tls_arg(&args, "-req");
    tapi_tls_arg(&args, "-in");
    tapi_tls_arg(&args, "%s", csr.ptr);
    tapi_tls_arg(&args, "-CA");
    tapi_tls_arg(&args, "%s", ca_crt.ptr);
    tapi_tls_arg(&args, "-CAkey");
    tapi_tls_arg(&args, "%s", ca_key.ptr);
    tapi_tls_arg(&args, "-CAcreateserial");
    tapi_tls_arg(&args, "-extfile");
    tapi_tls_arg(&args, "%s", ext.ptr);
    tapi_tls_arg(&args, "-out");
    tapi_tls_arg(&args, "%s", cert_file->ptr);

    if (opt->defect == TAPI_TLS_SERVER_EXPIRED)
    {
        /* Needs OpenSSL 3.0; older ones cannot date a certificate. */
        tapi_tls_arg(&args, "-not_after");
        tapi_tls_arg(&args, TLS_SERVER_EXPIRED_AT);
    }
    else
    {
        tapi_tls_arg(&args, "-days");
        tapi_tls_arg(&args, "%u", TLS_SERVER_DAYS);
    }

    rc = tls_openssl(factory, opt, &args, timeout_ms);
    te_vec_deep_free(&args);
    if (rc != 0)
    {
        if (opt->defect == TAPI_TLS_SERVER_EXPIRED)
        {
            ERROR("Dating a certificate in the past needs OpenSSL 3.0; "
                  "on an older one pass a certificate of your own in "
                  "tapi_tls_server_opt::cert_file");
        }
        goto out;
    }

    if (ca_file != NULL)
        te_string_append(ca_file, "%s", ca_crt.ptr);

out:
    tapi_file_ta_unlink_fmt(ta, "%s", csr.ptr);
    if (ext.ptr != NULL)
        tapi_file_ta_unlink_fmt(ta, "%s", ext.ptr);

    te_string_free(&ca_key);
    te_string_free(&ca_crt);
    te_string_free(&csr);
    te_string_free(&ext);

    return rc;
}

/** Remember a file to remove when the server goes away. */
static void
tls_scratch_keep(tapi_tls_server *server, const char *path)
{
    char *value = TE_STRDUP(path);

    TE_VEC_APPEND(&server->scratch, value);
}

/** Release a server handle and everything it made. */
static void
tls_server_cleanup(tapi_tls_server *server)
{
    char *const *path;

    TE_VEC_FOREACH(&server->scratch, path)
        tapi_file_ta_unlink_fmt(server->ta, "%s", *path);

    te_vec_deep_free(&server->scratch);
    free(server->ca_file);
    free(server->ta);
    free(server);
}

/* See description in tapi_tls_server.h */
te_errno
tapi_tls_server_start(tapi_job_factory_t *factory,
                      const tapi_tls_server_opt *opt, int timeout_ms,
                      tapi_tls_server **server)
{
    const char *ta = tapi_job_factory_ta(factory);
    te_string cert_file = TE_STRING_INIT;
    te_string key_file = TE_STRING_INIT;
    te_string ca_file = TE_STRING_INIT;
    te_vec args = TE_VEC_INIT(char *);
    tapi_tls_server *result;
    te_errno rc;

    if (opt->port == 0)
    {
        ERROR("The server needs a port to listen on");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    if (ta == NULL)
    {
        ERROR("Cannot determine the agent behind the job factory");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    result = TE_ALLOC(sizeof(*result));
    result->run = (tapi_devtool_run)TAPI_DEVTOOL_RUN_INIT;
    result->ta = TE_STRDUP(ta);
    result->naccept = opt->naccept;
    result->scratch = (te_vec)TE_VEC_INIT(char *);

    if (opt->cert_file != NULL && opt->key_file != NULL)
    {
        te_string_append(&cert_file, "%s", opt->cert_file);
        te_string_append(&key_file, "%s", opt->key_file);
    }
    else
    {
        rc = tapi_tls_server_make_cert(factory, opt, timeout_ms, &cert_file,
                                       &key_file, &ca_file);
        if (rc != 0)
            goto fail;

        tls_scratch_keep(result, cert_file.ptr);
        tls_scratch_keep(result, key_file.ptr);

        /* Not scratch: the test may install it on the device. */
        if (ca_file.len != 0)
            result->ca_file = TE_STRDUP(ca_file.ptr);
    }

    RING("Offering a %s certificate for '%s' on port %u",
         tapi_tls_defect2str(opt->defect), tls_cert_name(opt), opt->port);

    tapi_tls_arg(&args, "s_server");
    tapi_tls_arg(&args, "-accept");
    tapi_tls_arg(&args, "%u", opt->port);
    tapi_tls_arg(&args, "-cert");
    tapi_tls_arg(&args, "%s", cert_file.ptr);
    tapi_tls_arg(&args, "-key");
    tapi_tls_arg(&args, "%s", key_file.ptr);
    if (opt->www)
        tapi_tls_arg(&args, "-www");
    if (opt->naccept != 0)
    {
        tapi_tls_arg(&args, "-naccept");
        tapi_tls_arg(&args, "%u", opt->naccept);
    }

    rc = tapi_tls_spawn(factory, "s_server",
                        opt->openssl != NULL ? opt->openssl : "openssl",
                        &args, &result->run);
    if (rc == 0)
    {
        /*
         * Wait until it is actually listening. s_server prints ACCEPT
         * when the socket is bound, and it does so a few milliseconds
         * after the process exists - measured, the client of the very
         * next line got ECONNREFUSED five milliseconds before ACCEPT
         * appeared, and every test of what a client does reported that
         * the client never arrived.
         */
        rc = tapi_devtool_run_expect(&result->run, "ACCEPT",
                                     TLS_SERVER_READY_MS);
        if (rc != 0)
            ERROR("The server never started listening on port %u",
                  opt->port);
    }

fail:
    te_vec_deep_free(&args);
    te_string_free(&cert_file);
    te_string_free(&key_file);
    te_string_free(&ca_file);

    if (rc != 0)
    {
        tls_server_cleanup(result);
        return rc;
    }

    *server = result;

    return 0;
}

/* See description in tapi_tls_server.h */
const char *
tapi_tls_server_ca_file(const tapi_tls_server *server)
{
    return server->ca_file;
}

/**
 * Read one of the counters out of s_server's closing statistics.
 *
 * The lines are "   1 server accepts (SSL_accept())": the count comes
 * first, so the search is for the label and the number is read
 * backwards from it. Returns 0 when the label is not there at all,
 * which is the same answer as a count of zero and wants no special
 * case - a server that printed no statistics saw no connection it can
 * tell us about either way.
 */
static unsigned int
tls_server_stat(const char *text, const char *label)
{
    const char *found = strstr(text, label);
    const char *digits;

    if (found == NULL)
        return 0;

    /* Back over the space, then over the number. */
    while (found > text && (found[-1] == ' ' || found[-1] == '\t'))
        found--;

    digits = found;
    while (digits > text && digits[-1] >= '0' && digits[-1] <= '9')
        digits--;

    if (digits == found)
        return 0;

    return (unsigned int)strtoul(digits, NULL, 10);
}

/* See description in tapi_tls_server.h */
te_errno
tapi_tls_server_stop(tapi_tls_server *server,
                     tapi_tls_client_behaviour *behaviour)
{
    tapi_devtool_output output;
    te_string text = TE_STRING_INIT;
    te_errno rc;

    *behaviour = TAPI_TLS_CLIENT_NONE;

    if (server == NULL)
        return 0;

    /*
     * Waited for first, and only then stopped. With -naccept the
     * server leaves of its own accord once it has served its
     * connections, and on the way out it prints the statistics this
     * whole function reads. Killing it first would take those with it
     * and every client would look like a client that never arrived -
     * which is exactly what happened before this was written.
     */
    rc = tapi_devtool_run_wait(&server->run, TLS_SERVER_SETTLE_MS);
    if (TE_RC_GET_ERROR(rc) == TE_EINPROGRESS)
    {
        rc = tapi_devtool_run_stop(&server->run);
        if (rc == 0)
            rc = tapi_devtool_run_wait(&server->run,
                                       TAPI_DEVTOOL_TERM_TIMEOUT_MS * 5);
    }

    tapi_devtool_run_get_output(&server->run, &output);
    te_string_append(&text, "%s%s",
                     output.out != NULL ? output.out : "",
                     output.err != NULL ? output.err : "");

    /*
     * The statistics, which are printed once and say everything:
     *
     *     1 server accepts (SSL_accept())
     *     1 server accepts that finished
     *
     * A connection that was made and finished is a client that took
     * the certificate. One that was made and did not finish is a
     * client that refused it - and the alert it sent is in the text
     * as well, which is what the log wants. None at all, or no
     * statistics because the server was still listening, is a client
     * that never arrived, and that is not a result about the client.
     */
    if (tls_server_stat(text.ptr, "server accepts that finished") > 0)
        *behaviour = TAPI_TLS_CLIENT_COMPLETED;
    else if (tls_server_stat(text.ptr, "server accepts (SSL_accept())") > 0)
        *behaviour = TAPI_TLS_CLIENT_REJECTED;
    else if (server->naccept == 0)
    {
        /*
         * Said rather than silently reported as NONE, because the two
         * are indistinguishable from here and only one of them is a
         * result about the client. A server told to keep listening is
         * never asked to leave politely, so it never prints the
         * statistics, so it can only ever answer "nobody came".
         */
        WARN("The server was started with naccept=0, so it cannot say "
             "what the client did. Set tapi_tls_server_opt::naccept to "
             "the number of connections the client will make.");
    }

    if (*behaviour == TAPI_TLS_CLIENT_REJECTED)
    {
        const char *alert = strstr(text.ptr, "alert");

        if (alert != NULL)
        {
            RING("The client refused the certificate: %.*s",
                 (int)strcspn(alert, "\n"), alert);
        }
    }

    te_string_free(&text);

    tapi_devtool_run_fini(&server->run);
    tls_server_cleanup(server);

    return 0;
}

/* See description in tapi_tls_server.h */
te_errno
tapi_tls_check_client(tapi_tls_server_defect defect,
                      tapi_tls_client_behaviour behaviour,
                      const char *subject, tapi_cybersec_report *report)
{
    if (behaviour == TAPI_TLS_CLIENT_NONE)
    {
        /*
         * Nothing connected, so nothing was proven either way. Saying
         * so is the honest result; calling it a pass is not.
         */
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
                                 "tls.client-did-not-connect", subject,
                                 "no client reached the %s server, so its "
                                 "checking was not tested",
                                 tapi_tls_defect2str(defect));
        return 0;
    }

    if (defect == TAPI_TLS_SERVER_VALID)
    {
        if (behaviour == TAPI_TLS_CLIENT_REJECTED)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "tls.client-rejects-valid", subject,
                                     "the client refused a certificate that "
                                     "was correct, so the control case says "
                                     "nothing about the others");
        }
        return 0;
    }

    if (behaviour == TAPI_TLS_CLIENT_COMPLETED)
    {
        te_string check = TE_STRING_INIT;

        te_string_append(&check, "tls.client-accepts-%s",
                         tapi_tls_defect2str(defect));
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_CRITICAL,
                                 check.ptr, subject,
                                 "the client completed a handshake with a %s "
                                 "certificate: everything the connection "
                                 "carries is readable and writable by "
                                 "whoever sits in the middle",
                                 tapi_tls_defect2str(defect));
        te_string_free(&check);
    }
    else
    {
        RING("The client refused the %s certificate, as it should",
             tapi_tls_defect2str(defect));
    }

    return 0;
}
