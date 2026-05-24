/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief TLS assurance TAPI
 *
 * Handshakes are made with @c openssl @c s_client on an agent and the
 * facts are read out of what it printed.
 */

#define TE_LGR_USER "TAPI TLS"

#include "te_config.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "tapi_cfg_base.h"
#include "tapi_file.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_tls.h"
#include "tapi_tls_cert.h"
#include "tapi_tls_internal.h"

/** Signature algorithms nobody should still be signing with. */
static const char *const tls_weak_signatures[] = {
    "sha1",
    "md5",
    "md2",
    NULL,
};

const tapi_tls_probe_opt tapi_tls_probe_default_opt = {
    .openssl    = NULL,
    .version    = TAPI_TLS_VERSION_ANY,
    .show_certs = true,
};

const tapi_tls_policy tapi_tls_default_policy = {
    .min_version         = TAPI_TLS_VERSION_TLS1_2,
    .min_key_bits        = 2048,
    .min_days_left       = 30,
    .require_valid_chain = true,
    .expected_name       = NULL,
    .weak_signatures     = tls_weak_signatures,
};

/** An argument vector built by hand. */
typedef struct tls_args_opt {
    size_t n_args;
    const char **args;
} tls_args_opt;

static const tapi_job_opt_bind tls_args_binds[] = TAPI_JOB_OPT_SET(
    TAPI_JOB_OPT_ARRAY_PTR(tls_args_opt, n_args, args,
        TAPI_JOB_OPT_CONTENT(TAPI_JOB_OPT_STRING, NULL, false))
);

/* See description in tapi_tls_internal.h */
void
tapi_tls_arg(te_vec *args, const char *fmt, ...)
{
    te_string text = TE_STRING_INIT;
    char *value;
    va_list ap;

    va_start(ap, fmt);
    te_string_append_va(&text, fmt, ap);
    va_end(ap);

    value = text.ptr;
    TE_VEC_APPEND(args, value);
}

/* See description in tapi_tls_internal.h */
te_errno
tapi_tls_cmd(tapi_job_factory_t *factory, const char *name,
             const char *program, const te_vec *args, int timeout_ms,
             tapi_devtool_run *run)
{
    tls_args_opt opt = { .n_args = te_vec_size(args),
                         .args = (const char **)args->data.ptr };
    te_errno rc;

    *run = (tapi_devtool_run)TAPI_DEVTOOL_RUN_INIT;

    rc = tapi_devtool_run_init(run, factory, name, program, tls_args_binds,
                               &opt, NULL);
    if (rc != 0)
        return rc;

    rc = tapi_devtool_run_start(run);
    if (rc == 0)
        rc = tapi_devtool_run_wait(run, timeout_ms);

    if (rc != 0)
        tapi_devtool_run_fini(run);

    return rc;
}

/* See description in tapi_tls_internal.h */
te_errno
tapi_tls_spawn(tapi_job_factory_t *factory, const char *name,
               const char *program, const te_vec *args,
               tapi_devtool_run *run)
{
    tls_args_opt opt = { .n_args = te_vec_size(args),
                         .args = (const char **)args->data.ptr };
    te_errno rc;

    *run = (tapi_devtool_run)TAPI_DEVTOOL_RUN_INIT;

    rc = tapi_devtool_run_init(run, factory, name, program, tls_args_binds,
                               &opt, NULL);
    if (rc != 0)
        return rc;

    rc = tapi_devtool_run_start(run);
    if (rc != 0)
        tapi_devtool_run_fini(run);

    return rc;
}

/* See description in tapi_tls_internal.h */
te_errno
tapi_tls_put_file(const char *ta, const char *content, const char *suffix,
                  te_string *path)
{
    char *tmp_dir;
    te_errno rc;

    tmp_dir = tapi_cfg_base_get_ta_dir(ta, TAPI_CFG_BASE_TA_DIR_TMP);
    if (tmp_dir == NULL)
    {
        ERROR("Failed to get the temporary directory of TA %s", ta);
        return TE_RC(TE_TAPI, TE_EFAIL);
    }

    tapi_file_make_custom_pathname(path, tmp_dir, suffix);
    free(tmp_dir);

    rc = tapi_file_create_ta(ta, path->ptr, "%s", content);
    if (rc != 0)
        ERROR("Failed to put a file on TA %s: %r", ta, rc);

    return rc;
}

/* See description in tapi_tls_internal.h */
char *
tapi_tls_field(const char *text, const char *key, const char *stop)
{
    const char *found = strstr(text, key);
    size_t len;
    char *value;

    if (found == NULL)
        return NULL;

    found += strlen(key);
    while (*found == ' ' || *found == '\t')
        found++;

    len = strcspn(found, stop);
    value = TE_ALLOC(len + 1);
    memcpy(value, found, len);
    value[len] = '\0';

    while (len > 0 && (value[len - 1] == ' ' || value[len - 1] == '\r'))
        value[--len] = '\0';

    return value;
}

/* See description in tapi_tls.h */
const char *
tapi_tls_version2str(tapi_tls_version version)
{
    switch (version)
    {
        case TAPI_TLS_VERSION_SSL3:
            return "SSLv3";
        case TAPI_TLS_VERSION_TLS1_0:
            return "TLSv1";
        case TAPI_TLS_VERSION_TLS1_1:
            return "TLSv1.1";
        case TAPI_TLS_VERSION_TLS1_2:
            return "TLSv1.2";
        case TAPI_TLS_VERSION_TLS1_3:
            return "TLSv1.3";
        default:
            return "any";
    }
}

/** The s_client option that insists on one version. */
static const char *
tls_version_flag(tapi_tls_version version)
{
    switch (version)
    {
        case TAPI_TLS_VERSION_SSL3:
            return "-ssl3";
        case TAPI_TLS_VERSION_TLS1_0:
            return "-tls1";
        case TAPI_TLS_VERSION_TLS1_1:
            return "-tls1_1";
        case TAPI_TLS_VERSION_TLS1_2:
            return "-tls1_2";
        case TAPI_TLS_VERSION_TLS1_3:
            return "-tls1_3";
        default:
            return NULL;
    }
}

/** Recognise the version OpenSSL named in its output. */
static tapi_tls_version
tls_version_from_str(const char *text)
{
    if (text == NULL)
        return TAPI_TLS_VERSION_ANY;

    if (strcmp(text, "TLSv1.3") == 0)
        return TAPI_TLS_VERSION_TLS1_3;
    if (strcmp(text, "TLSv1.2") == 0)
        return TAPI_TLS_VERSION_TLS1_2;
    if (strcmp(text, "TLSv1.1") == 0)
        return TAPI_TLS_VERSION_TLS1_1;
    if (strcmp(text, "TLSv1") == 0)
        return TAPI_TLS_VERSION_TLS1_0;
    if (strcmp(text, "SSLv3") == 0)
        return TAPI_TLS_VERSION_SSL3;

    return TAPI_TLS_VERSION_ANY;
}

/** Pull the chain out of what s_client printed. */
static char *
tls_extract_chain(const char *text)
{
    const char *begin = strstr(text, "-----BEGIN CERTIFICATE-----");
    const char *end;
    te_string chain = TE_STRING_INIT;

    if (begin == NULL)
        return NULL;

    end = strstr(begin, "-----END CERTIFICATE-----");
    while (end != NULL)
    {
        end += strlen("-----END CERTIFICATE-----");
        te_string_append(&chain, "%.*s\n", (int)(end - begin), begin);

        begin = strstr(end, "-----BEGIN CERTIFICATE-----");
        if (begin == NULL)
            break;
        end = strstr(begin, "-----END CERTIFICATE-----");
    }

    return chain.ptr;
}

/** Read the facts out of what s_client printed. */
static void
tls_parse_handshake(const char *text, tapi_tls_handshake *handshake)
{
    char *version_text;
    char *bits;

    handshake->raw = TE_STRDUP(text);
    handshake->connected = strstr(text, "CONNECTED(") != NULL;

    /* "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384" */
    version_text = tapi_tls_field(text, "New, ", ",\n");
    if (version_text == NULL)
        version_text = tapi_tls_field(text, "Protocol  :", "\n");

    handshake->version = tls_version_from_str(version_text);
    free(version_text);

    handshake->cipher = tapi_tls_field(text, "Cipher is ", " \n");
    if (handshake->cipher == NULL)
        handshake->cipher = tapi_tls_field(text, "Cipher    :", "\n");

    handshake->negotiated = handshake->version != TAPI_TLS_VERSION_ANY &&
                            handshake->cipher != NULL &&
                            strcmp(handshake->cipher, "(NONE)") != 0;

    bits = tapi_tls_field(text, "Server public key is ", " \n");
    if (bits != NULL)
    {
        unsigned int value;

        if (te_strtoui(bits, 10, &value) == 0)
            handshake->server_key_bits = value;
        free(bits);
    }

    {
        char *code = tapi_tls_field(text, "Verify return code:", " \n");

        handshake->verify_code = -1;
        if (code != NULL)
        {
            int value;

            if (te_strtoi(code, 10, &value) == 0)
                handshake->verify_code = value;
            free(code);
        }
    }

    handshake->verify_text = tapi_tls_field(text, "Verify return code:", "\n");
    if (handshake->verify_text == NULL)
        handshake->verify_text = tapi_tls_field(text, "Verification error:",
                                                "\n");

    handshake->secure_renegotiation =
        strstr(text, "Secure Renegotiation IS supported") != NULL;

    handshake->chain_pem = tls_extract_chain(text);
}

/* See description in tapi_tls.h */
te_errno
tapi_tls_probe(tapi_job_factory_t *factory, const tapi_tls_probe_opt *opt,
               int timeout_ms, tapi_tls_handshake *handshake)
{
    te_vec args = TE_VEC_INIT(char *);
    tapi_devtool_output output;
    tapi_devtool_run run;
    const char *flag;
    te_string text = TE_STRING_INIT;
    size_t i;
    te_errno rc;

    memset(handshake, 0, sizeof(*handshake));

    if (opt->host == NULL || opt->port == 0)
    {
        ERROR("A probe needs a host and a port");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    tapi_tls_arg(&args, "s_client");
    tapi_tls_arg(&args, "-connect");
    tapi_tls_arg(&args, "%s:%u", opt->host, opt->port);

    if (opt->servername != NULL)
    {
        tapi_tls_arg(&args, "-servername");
        tapi_tls_arg(&args, "%s", opt->servername);
    }

    flag = tls_version_flag(opt->version);
    if (flag != NULL)
        tapi_tls_arg(&args, "%s", flag);

    if (opt->cipher != NULL)
    {
        tapi_tls_arg(&args, "-cipher");
        tapi_tls_arg(&args, "%s", opt->cipher);
    }
    if (opt->ciphersuites != NULL)
    {
        tapi_tls_arg(&args, "-ciphersuites");
        tapi_tls_arg(&args, "%s", opt->ciphersuites);
    }
    if (opt->ca_file != NULL)
    {
        tapi_tls_arg(&args, "-CAfile");
        tapi_tls_arg(&args, "%s", opt->ca_file);
    }
    if (opt->starttls != NULL)
    {
        tapi_tls_arg(&args, "-starttls");
        tapi_tls_arg(&args, "%s", opt->starttls);
    }
    if (opt->show_certs)
        tapi_tls_arg(&args, "-showcerts");

    for (i = 0; i < opt->n_extra_args; i++)
        tapi_tls_arg(&args, "%s", opt->extra_args[i]);

    rc = tapi_tls_cmd(factory, "s_client",
                      opt->openssl != NULL ? opt->openssl : "openssl",
                      &args, timeout_ms, &run);
    te_vec_deep_free(&args);

    if (rc != 0)
    {
        /*
         * s_client stays connected once the handshake is done and its
         * standard input cannot be closed through tapi_job, so a probe
         * that reached a live server ends by timing out. Everything
         * worth reading has been printed by then.
         */
        if (TE_RC_GET_ERROR(rc) != TE_EINPROGRESS)
            return rc;
    }

    tapi_devtool_run_get_output(&run, &output);
    te_string_append(&text, "%s%s", output.out, output.err);
    tls_parse_handshake(te_string_value(&text), handshake);
    te_string_free(&text);

    tapi_devtool_run_stop(&run);
    tapi_devtool_run_fini(&run);

    return 0;
}

/* See description in tapi_tls.h */
void
tapi_tls_handshake_log(const tapi_tls_handshake *handshake)
{
    if (!handshake->connected)
    {
        RING("No connection was made");
        return;
    }

    if (!handshake->negotiated)
    {
        RING("Connected, but no handshake was completed");
        return;
    }

    RING("Handshake: %s, %s",
         tapi_tls_version2str(handshake->version),
         handshake->cipher != NULL ? handshake->cipher : "?");
    RING("  server key: %u bits", handshake->server_key_bits);
    RING("  verification: %s",
         handshake->verify_text != NULL ? handshake->verify_text : "?");
    RING("  secure renegotiation: %s",
         handshake->secure_renegotiation ? "yes" : "no");
}

/* See description in tapi_tls.h */
void
tapi_tls_handshake_free(tapi_tls_handshake *handshake)
{
    free(handshake->cipher);
    free(handshake->verify_text);
    free(handshake->chain_pem);
    free(handshake->raw);

    memset(handshake, 0, sizeof(*handshake));
}

/* See description in tapi_tls.h */
te_errno
tapi_tls_scan_versions(tapi_job_factory_t *factory,
                       const tapi_tls_probe_opt *opt, int timeout_ms,
                       unsigned int *accepted)
{
    static const tapi_tls_version versions[] = {
        TAPI_TLS_VERSION_SSL3,
        TAPI_TLS_VERSION_TLS1_0,
        TAPI_TLS_VERSION_TLS1_1,
        TAPI_TLS_VERSION_TLS1_2,
        TAPI_TLS_VERSION_TLS1_3,
    };
    size_t i;

    *accepted = 0;

    for (i = 0; i < TE_ARRAY_LEN(versions); i++)
    {
        tapi_tls_probe_opt attempt = *opt;
        tapi_tls_handshake handshake;
        te_errno rc;

        attempt.version = versions[i];
        attempt.show_certs = false;

        rc = tapi_tls_probe(factory, &attempt, timeout_ms, &handshake);
        if (rc != 0)
        {
            tapi_tls_handshake_free(&handshake);
            return rc;
        }

        /*
         * An OpenSSL that was built without a version refuses to offer
         * it, which says nothing about the server. It shows up as a
         * failure to connect at all rather than as a refused
         * handshake, and is logged as such.
         */
        if (handshake.negotiated)
        {
            *accepted |= 1u << versions[i];
            RING("%s: accepted", tapi_tls_version2str(versions[i]));
        }
        else
        {
            RING("%s: not accepted%s", tapi_tls_version2str(versions[i]),
                 handshake.connected ? "" : " (the probe never connected)");
        }

        tapi_tls_handshake_free(&handshake);
    }

    return 0;
}

/** Report the versions that are older than the policy allows. */
static void
tls_check_versions(unsigned int accepted, const tapi_tls_policy *policy,
                   const char *subject, tapi_cybersec_report *report)
{
    static const tapi_tls_version versions[] = {
        TAPI_TLS_VERSION_SSL3,
        TAPI_TLS_VERSION_TLS1_0,
        TAPI_TLS_VERSION_TLS1_1,
        TAPI_TLS_VERSION_TLS1_2,
        TAPI_TLS_VERSION_TLS1_3,
    };
    size_t i;

    if (accepted == 0)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
                                 "tls.no-handshake", subject,
                                 "no version completed a handshake, so "
                                 "nothing was checked");
        return;
    }

    for (i = 0; i < TE_ARRAY_LEN(versions); i++)
    {
        if ((accepted & (1u << versions[i])) == 0)
            continue;

        if (versions[i] >= policy->min_version)
            continue;

        tapi_cybersec_report_add(report,
                                 versions[i] <= TAPI_TLS_VERSION_TLS1_0 ?
                                     TAPI_CYBERSEC_SEV_HIGH :
                                     TAPI_CYBERSEC_SEV_MEDIUM,
                                 "tls.obsolete-version", subject,
                                 "the endpoint agreed to %s, and the policy "
                                 "allows nothing below %s",
                                 tapi_tls_version2str(versions[i]),
                                 tapi_tls_version2str(policy->min_version));
    }
}

/** Report everything wrong with the certificate the endpoint presents. */
static te_errno
tls_check_certificate(tapi_job_factory_t *factory,
                      const tapi_tls_handshake *handshake,
                      const tapi_tls_policy *policy, const char *subject,
                      int timeout_ms, tapi_cybersec_report *report)
{
    tapi_tls_cert cert;
    bool still_valid = false;
    te_errno rc;
    size_t i;

    if (handshake->chain_pem == NULL)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
                                 "tls.no-certificate", subject,
                                 "the endpoint presented no certificate to "
                                 "look at");
        return 0;
    }

    rc = tapi_tls_cert_read(factory, handshake->chain_pem, timeout_ms, &cert);
    if (rc != 0)
        return rc;

    tapi_tls_cert_log(&cert);

    if (cert.expired)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "tls.certificate-expired", subject,
                                 "it expired on %s",
                                 cert.not_after != NULL ? cert.not_after :
                                     "an unknown date");
    }
    else if (policy->min_days_left != 0)
    {
        rc = tapi_tls_cert_checkend(factory, handshake->chain_pem,
                                    policy->min_days_left * 24 * 3600,
                                    timeout_ms, &still_valid);
        if (rc != 0)
            goto out;

        if (!still_valid)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "tls.certificate-expiring", subject,
                                     "it expires on %s, within the %u days "
                                     "the policy requires",
                                     cert.not_after != NULL ? cert.not_after :
                                         "an unknown date",
                                     policy->min_days_left);
        }
    }

    if (policy->min_key_bits != 0 && cert.key_bits != 0 &&
        cert.key_bits < policy->min_key_bits)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "tls.weak-key", subject,
                                 "the key is %u bits, and the policy "
                                 "requires at least %u", cert.key_bits,
                                 policy->min_key_bits);
    }

    if (policy->weak_signatures != NULL &&
        cert.signature_algorithm != NULL)
    {
        for (i = 0; policy->weak_signatures[i] != NULL; i++)
        {
            if (strstr(cert.signature_algorithm,
                       policy->weak_signatures[i]) == NULL)
                continue;

            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                     "tls.weak-signature", subject,
                                     "it is signed with %s",
                                     cert.signature_algorithm);
            break;
        }
    }

    if (cert.self_signed)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "tls.self-signed", subject,
                                 "the certificate signs itself, so no trust "
                                 "anchor leads to it");
    }

    if (policy->require_valid_chain && handshake->verify_code != 0)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "tls.chain-not-verified", subject,
                                 "verification failed: %s",
                                 handshake->verify_text != NULL ?
                                     handshake->verify_text : "no reason given");
    }

    if (policy->expected_name != NULL &&
        !tapi_tls_cert_matches_name(&cert, policy->expected_name))
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "tls.name-mismatch", subject,
                                 "the certificate does not cover '%s'",
                                 policy->expected_name);
    }

out:
    tapi_tls_cert_free(&cert);

    return rc;
}

/* See description in tapi_tls.h */
te_errno
tapi_tls_check_server(tapi_job_factory_t *factory,
                      const tapi_tls_probe_opt *opt,
                      const tapi_tls_policy *policy, int timeout_ms,
                      tapi_cybersec_report *report)
{
    tapi_tls_handshake handshake;
    te_string subject = TE_STRING_INIT;
    unsigned int accepted = 0;
    te_errno rc;

    if (policy == NULL)
        policy = &tapi_tls_default_policy;

    te_string_append(&subject, "%s:%u", opt->host, opt->port);

    rc = tapi_tls_scan_versions(factory, opt, timeout_ms, &accepted);
    if (rc != 0)
        goto out;

    tls_check_versions(accepted, policy, subject.ptr, report);

    rc = tapi_tls_probe(factory, opt, timeout_ms, &handshake);
    if (rc != 0)
        goto out;

    tapi_tls_handshake_log(&handshake);

    if (handshake.negotiated)
    {
        if (policy->min_key_bits != 0 && handshake.server_key_bits != 0 &&
            handshake.server_key_bits < policy->min_key_bits)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                     "tls.weak-key", subject.ptr,
                                     "the server key is %u bits",
                                     handshake.server_key_bits);
        }

        if (!handshake.secure_renegotiation &&
            handshake.version < TAPI_TLS_VERSION_TLS1_3)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "tls.insecure-renegotiation",
                                     subject.ptr,
                                     "the endpoint does not support secure "
                                     "renegotiation");
        }

        rc = tls_check_certificate(factory, &handshake, policy, subject.ptr,
                                   timeout_ms, report);
    }

    tapi_tls_handshake_free(&handshake);

out:
    te_string_free(&subject);

    return rc;
}
