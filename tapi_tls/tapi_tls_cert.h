/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Certificate facts
 *
 * @defgroup tapi_tls_cert Certificates (tapi_tls_cert)
 * @ingroup tapi_tls
 * @{
 *
 * What a certificate says, and whether any of it is still true.
 *
 * The certificate comes out of a handshake as PEM. It is put on the
 * agent and read with @c openssl @c x509, because the alternative is to
 * write an X.509 parser, and a wrong one would be worse than no check
 * at all.
 *
 * Expiry is asked rather than computed: @c openssl @c x509
 * @c -checkend answers "will this still be valid in N seconds" without
 * anybody having to parse a date or worry about a time zone.
 */

#ifndef __TSF_TAPI_TLS_CERT_H__
#define __TSF_TAPI_TLS_CERT_H__

#include "te_defs.h"
#include "te_errno.h"
#include "tapi_job.h"

#include "tapi_cybersec.h"

#ifdef __cplusplus
extern "C" {
#endif

/** What a certificate says. */
typedef struct tapi_tls_cert {
    /** Who it is for. */
    char *subject;
    /** Who signed it. */
    char *issuer;
    /** Serial number. */
    char *serial;
    /** SHA-256 fingerprint. */
    char *fingerprint;
    /** Start of validity, as OpenSSL prints it. */
    char *not_before;
    /** End of validity, as OpenSSL prints it. */
    char *not_after;
    /** Size of the public key, bits. */
    unsigned int key_bits;
    /** Algorithm the certificate is signed with. */
    char *signature_algorithm;
    /** Subject and issuer are the same. */
    bool self_signed;
    /** It has already expired. */
    bool expired;
    /** Number of names. */
    size_t n_names;
    /** The common name and every subject alternative name. */
    char **names;
} tapi_tls_cert;

/**
 * Read a certificate given as PEM.
 *
 * @param[in]  factory      Job factory; @c openssl runs on this agent.
 * @param[in]  pem          The certificate, or a chain, in PEM. Only
 *                          the first certificate is read.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] cert         What it says; release it with
 *                          tapi_tls_cert_free().
 *
 * @return Status code.
 */
extern te_errno tapi_tls_cert_read(tapi_job_factory_t *factory,
                                   const char *pem, int timeout_ms,
                                   tapi_tls_cert *cert);

/**
 * Check whether the certificate will still be valid in @p seconds.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  pem          The certificate in PEM.
 * @param[in]  seconds      How far ahead to look.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] valid        @c true if it is still valid then.
 *
 * @return Status code.
 */
extern te_errno tapi_tls_cert_checkend(tapi_job_factory_t *factory,
                                       const char *pem, unsigned int seconds,
                                       int timeout_ms, bool *valid);

/**
 * Check whether a certificate is valid for a name.
 *
 * Matches the common name and every subject alternative name, with the
 * one wildcard form that is allowed: a leading @c "*." standing for
 * exactly one label.
 *
 * @param cert          Certificate.
 * @param name          Name to check.
 *
 * @return @c true if the certificate covers the name.
 */
extern bool tapi_tls_cert_matches_name(const tapi_tls_cert *cert,
                                       const char *name);

/**
 * Write a certificate into the log.
 *
 * @param cert          Certificate.
 */
extern void tapi_tls_cert_log(const tapi_tls_cert *cert);

/**
 * Release a certificate.
 *
 * @param cert          Certificate.
 */
extern void tapi_tls_cert_free(tapi_tls_cert *cert);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_TLS_CERT_H__ */

/**@} <!-- END tapi_tls_cert --> */
