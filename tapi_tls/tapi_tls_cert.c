/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Certificate facts
 *
 * The certificate is put on the agent and read with @c openssl @c x509,
 * because a hand-written X.509 parser that is subtly wrong is worse
 * than no check at all.
 */

#define TE_LGR_USER "TAPI TLS CERT"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "tapi_file.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_tls_cert.h"
#include "tapi_tls_internal.h"

/** Run openssl x509 over a PEM that is already on the agent. */
static te_errno
cert_x509(tapi_job_factory_t *factory, const char *path,
          const char *const *extra, size_t n_extra, int timeout_ms,
          te_string *out, bool *ok)
{
    te_vec args = TE_VEC_INIT(char *);
    tapi_devtool_output output;
    tapi_devtool_run run;
    size_t i;
    te_errno rc;

    tapi_tls_arg(&args, "x509");
    tapi_tls_arg(&args, "-in");
    tapi_tls_arg(&args, "%s", path);
    tapi_tls_arg(&args, "-noout");

    for (i = 0; i < n_extra; i++)
        tapi_tls_arg(&args, "%s", extra[i]);

    rc = tapi_tls_cmd(factory, "x509", "openssl", &args, timeout_ms, &run);
    te_vec_deep_free(&args);
    if (rc != 0)
        return rc;

    tapi_devtool_run_get_output(&run, &output);

    *ok = output.status.type == TAPI_JOB_STATUS_EXITED &&
          output.status.value == 0;
    if (out != NULL)
        te_string_append(out, "%s", output.out);

    tapi_devtool_run_fini(&run);

    return 0;
}

/**
 * The common name of a subject line.
 *
 * Two spellings, because OpenSSL has both: `openssl x509 -subject`
 * printed @c "subject=CN=host" up to 1.1.1 and prints
 * @c "subject=CN = host" from 3.0 on. Asking only for the first and
 * getting nothing is not a certificate without a common name, it is a
 * parser reading the wrong version's output - and it comes back as a
 * name mismatch on a certificate that matches perfectly.
 */
static char *
cert_common_name(const char *subject)
{
    static const char *const spellings[] = { "CN=", "CN =" };
    size_t i;

    for (i = 0; i < TE_ARRAY_LEN(spellings); i++)
    {
        char *common = tapi_tls_field(subject, spellings[i], ",/\n");

        if (common != NULL && *common != '\0')
            return common;

        free(common);
    }

    return NULL;
}

/** Take the names out of the text form of a certificate. */
static void
cert_collect_names(const char *text, tapi_tls_cert *cert)
{
    te_vec names = TE_VEC_INIT(char *);
    const char *san;
    char *common;

    /* The common name, which is still what some clients look at. */
    if (cert->subject != NULL)
    {
        common = cert_common_name(cert->subject);
        if (common != NULL)
            TE_VEC_APPEND(&names, common);
    }

    /*
     * The alternative names, which are what everything else looks at.
     * They sit on the line below the extension's own, indented and
     * comma separated:
     *
     *     X509v3 Subject Alternative Name:
     *         DNS:dut.example.net, DNS:www.dut.example.net
     */
    san = strstr(text, "X509v3 Subject Alternative Name:");
    if (san != NULL)
    {
        const char *values = strchr(san, '\n');
        const char *end;
        const char *entry;

        if (values != NULL)
        {
            values++;
            end = strchr(values, '\n');
            if (end == NULL)
                end = values + strlen(values);

            for (entry = strstr(values, "DNS:");
                 entry != NULL && entry < end;
                 entry = strstr(entry, "DNS:"))
            {
                size_t len;
                char *name;

                entry += strlen("DNS:");
                len = strcspn(entry, ",\n ");
                name = TE_ALLOC(len + 1);
                memcpy(name, entry, len);
                TE_VEC_APPEND(&names, name);
            }
        }
    }

    cert->n_names = te_vec_size(&names);
    if (cert->n_names != 0)
    {
        cert->names = TE_ALLOC(cert->n_names * sizeof(*cert->names));
        memcpy(cert->names, names.data.ptr,
               cert->n_names * sizeof(*cert->names));
    }
    te_vec_free(&names);
}

/* See description in tapi_tls_cert.h */
te_errno
tapi_tls_cert_read(tapi_job_factory_t *factory, const char *pem,
                   int timeout_ms, tapi_tls_cert *cert)
{
    static const char *const fields[] = {
        "-subject", "-issuer", "-serial", "-fingerprint", "-sha256",
        "-startdate", "-enddate",
    };
    static const char *const as_text[] = { "-text" };
    const char *ta = tapi_job_factory_ta(factory);
    te_string path = TE_STRING_INIT;
    te_string summary = TE_STRING_INIT;
    te_string text = TE_STRING_INIT;
    char *bits;
    bool ok = false;
    te_errno rc;

    memset(cert, 0, sizeof(*cert));

    if (ta == NULL)
    {
        ERROR("Cannot determine the agent behind the job factory");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    rc = tapi_tls_put_file(ta, pem, ".pem", &path);
    if (rc != 0)
        goto out;

    rc = cert_x509(factory, path.ptr, fields, TE_ARRAY_LEN(fields),
                   timeout_ms, &summary, &ok);
    if (rc != 0)
        goto out;

    if (!ok)
    {
        ERROR("openssl could not read the certificate");
        rc = TE_RC(TE_TAPI, TE_EBADMSG);
        goto out;
    }

    cert->subject = tapi_tls_field(summary.ptr, "subject=", "\n");
    cert->issuer = tapi_tls_field(summary.ptr, "issuer=", "\n");
    cert->serial = tapi_tls_field(summary.ptr, "serial=", "\n");
    cert->fingerprint = tapi_tls_field(summary.ptr, "Fingerprint=", "\n");
    cert->not_before = tapi_tls_field(summary.ptr, "notBefore=", "\n");
    cert->not_after = tapi_tls_field(summary.ptr, "notAfter=", "\n");

    cert->self_signed = cert->subject != NULL && cert->issuer != NULL &&
                        strcmp(cert->subject, cert->issuer) == 0;

    rc = cert_x509(factory, path.ptr, as_text, TE_ARRAY_LEN(as_text),
                   timeout_ms, &text, &ok);
    if (rc != 0)
        goto out;

    cert->signature_algorithm = tapi_tls_field(text.ptr,
                                               "Signature Algorithm:", "\n");

    /* "Public-Key: (2048 bit)", whatever the key type is called. */
    bits = tapi_tls_field(text.ptr, "Public-Key: (", " ");
    if (bits != NULL)
    {
        unsigned int value;

        if (te_strtoui(bits, 10, &value) == 0)
            cert->key_bits = value;
        free(bits);
    }

    cert_collect_names(text.ptr, cert);

    /* Asked, not computed: no date parsing, no time zones. */
    {
        bool still_valid = false;

        rc = tapi_tls_cert_checkend(factory, pem, 0, timeout_ms,
                                    &still_valid);
        if (rc != 0)
            goto out;

        cert->expired = !still_valid;
    }

out:
    if (path.ptr != NULL)
        tapi_file_ta_unlink_fmt(ta, "%s", path.ptr);
    te_string_free(&path);
    te_string_free(&summary);
    te_string_free(&text);

    if (rc != 0)
        tapi_tls_cert_free(cert);

    return rc;
}

/* See description in tapi_tls_cert.h */
te_errno
tapi_tls_cert_checkend(tapi_job_factory_t *factory, const char *pem,
                       unsigned int seconds, int timeout_ms, bool *valid)
{
    const char *ta = tapi_job_factory_ta(factory);
    te_string path = TE_STRING_INIT;
    te_string flag = TE_STRING_INIT;
    const char *extra[2];
    bool ok = false;
    te_errno rc;

    if (ta == NULL)
    {
        ERROR("Cannot determine the agent behind the job factory");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    rc = tapi_tls_put_file(ta, pem, ".pem", &path);
    if (rc != 0)
        goto out;

    te_string_append(&flag, "%u", seconds);
    extra[0] = "-checkend";
    extra[1] = flag.ptr;

    /* x509 -checkend exits zero while the certificate is still valid. */
    rc = cert_x509(factory, path.ptr, extra, TE_ARRAY_LEN(extra), timeout_ms,
                   NULL, &ok);
    if (rc == 0)
        *valid = ok;

out:
    if (path.ptr != NULL)
        tapi_file_ta_unlink_fmt(ta, "%s", path.ptr);
    te_string_free(&path);
    te_string_free(&flag);

    return rc;
}

/** Does a certificate name cover a host name? */
static bool
cert_name_matches(const char *pattern, const char *name)
{
    const char *dot;

    if (strcasecmp(pattern, name) == 0)
        return true;

    /* Exactly one leading "*.", standing for exactly one label. */
    if (strncmp(pattern, "*.", 2) != 0)
        return false;

    dot = strchr(name, '.');
    if (dot == NULL)
        return false;

    return strcasecmp(pattern + 2, dot + 1) == 0;
}

/* See description in tapi_tls_cert.h */
bool
tapi_tls_cert_matches_name(const tapi_tls_cert *cert, const char *name)
{
    size_t i;

    for (i = 0; i < cert->n_names; i++)
    {
        if (cert_name_matches(cert->names[i], name))
            return true;
    }

    return false;
}

/* See description in tapi_tls_cert.h */
void
tapi_tls_cert_log(const tapi_tls_cert *cert)
{
    size_t i;

    RING("Certificate:");
    RING("  subject: %s", cert->subject != NULL ? cert->subject : "?");
    RING("  issuer: %s%s", cert->issuer != NULL ? cert->issuer : "?",
         cert->self_signed ? " (itself)" : "");
    RING("  valid: %s .. %s%s",
         cert->not_before != NULL ? cert->not_before : "?",
         cert->not_after != NULL ? cert->not_after : "?",
         cert->expired ? " (expired)" : "");
    RING("  key: %u bits, signed with %s", cert->key_bits,
         cert->signature_algorithm != NULL ? cert->signature_algorithm : "?");
    RING("  fingerprint: %s",
         cert->fingerprint != NULL ? cert->fingerprint : "?");

    for (i = 0; i < cert->n_names; i++)
        RING("  name: %s", cert->names[i]);
}

/* See description in tapi_tls_cert.h */
void
tapi_tls_cert_free(tapi_tls_cert *cert)
{
    size_t i;

    free(cert->subject);
    free(cert->issuer);
    free(cert->serial);
    free(cert->fingerprint);
    free(cert->not_before);
    free(cert->not_after);
    free(cert->signature_algorithm);

    for (i = 0; i < cert->n_names; i++)
        free(cert->names[i]);
    free(cert->names);

    memset(cert, 0, sizeof(*cert));
}
