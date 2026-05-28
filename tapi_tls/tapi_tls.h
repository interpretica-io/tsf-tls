/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief TLS assurance TAPI
 *
 * @defgroup tapi_tls TLS (tapi_tls)
 * @{
 *
 * What a TLS endpoint actually agrees to, and whether a TLS client
 * actually checks anything.
 *
 * The traffic rules of tsf-cybersec watch a handshake go past and say
 * whether it was an old one. This asks the questions directly:
 *
 * - @ref tapi_tls - one handshake with parameters of your choosing,
 *   and what came back; enumeration of the versions a server accepts;
 * - @ref tapi_tls_cert - what the certificate says, and whether any of
 *   it is true;
 * - @ref tapi_tls_server - the other direction, and the one that finds
 *   the most: stand up a server with a deliberately bad certificate and
 *   see whether the device's own client notices.
 *
 * Everything is driven through @c openssl on an agent, the same way
 * @c objdump and Frida are driven in tsf-cybersec. Nothing new has to
 * be linked into the engine, a version of TLS the engine's library
 * dropped years ago can still be offered to the device, and the
 * connection comes from a Test Agent the suite already owns.
 *
 * @code
 * tapi_tls_probe_opt opt = tapi_tls_probe_default_opt;
 * tapi_tls_policy policy = tapi_tls_default_policy;
 *
 * opt.host = "10.0.0.7";
 * opt.port = 443;
 * policy.expected_name = "dut.example.net";
 *
 * CHECK_RC(tapi_tls_check_server(factory, &opt, &policy, 10000, &report));
 * @endcode
 *
 * @note A probe takes about as long as its timeout. @c s_client stays
 *       connected once the handshake is done and there is no way to
 *       close its standard input through @ref tapi_job, so a probe runs
 *       it, waits, stops it and reads what it printed. The handshake
 *       facts are all printed immediately, so nothing is lost - but a
 *       scan of five versions costs five timeouts, and the timeout
 *       should be short.
 */

#ifndef __TSF_TAPI_TLS_H__
#define __TSF_TAPI_TLS_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "tapi_job.h"

#include "tapi_cybersec.h"

#ifdef __cplusplus
extern "C" {
#endif

/** A protocol version. */
typedef enum tapi_tls_version {
    /** Whatever the two ends agree on. */
    TAPI_TLS_VERSION_ANY = 0,
    /** SSL 3.0, which nothing should still offer. */
    TAPI_TLS_VERSION_SSL3,
    /** TLS 1.0. */
    TAPI_TLS_VERSION_TLS1_0,
    /** TLS 1.1. */
    TAPI_TLS_VERSION_TLS1_1,
    /** TLS 1.2. */
    TAPI_TLS_VERSION_TLS1_2,
    /** TLS 1.3. */
    TAPI_TLS_VERSION_TLS1_3,
} tapi_tls_version;

/** How to make one handshake. */
typedef struct tapi_tls_probe_opt {
    /** The @c openssl program; @c NULL means @c openssl. */
    const char *openssl;
    /** Address of the endpoint. Mandatory. */
    const char *host;
    /** Port of the endpoint. Mandatory. */
    uint16_t port;
    /** Name to send in SNI, or @c NULL to send none. */
    const char *servername;
    /** Version to insist on, or @ref TAPI_TLS_VERSION_ANY. */
    tapi_tls_version version;
    /** Cipher list for TLS 1.2 and older (@c -cipher). */
    const char *cipher;
    /** Cipher suites for TLS 1.3 (@c -ciphersuites). */
    const char *ciphersuites;
    /** Trust anchors to verify against (@c -CAfile), or @c NULL. */
    const char *ca_file;
    /** Ask for the whole chain, which costs nothing and tells more. */
    bool show_certs;
    /** Protocol to upgrade from, e.g. @c "smtp" (@c -starttls). */
    const char *starttls;
    /** Number of extra arguments. */
    size_t n_extra_args;
    /** Extra arguments, passed to @c s_client as they are. */
    const char **extra_args;
} tapi_tls_probe_opt;

/** Default probe: whatever the server offers, with the chain. */
extern const tapi_tls_probe_opt tapi_tls_probe_default_opt;

/** What came back from a handshake attempt. */
typedef struct tapi_tls_handshake {
    /** The TCP connection was made. */
    bool connected;
    /** The handshake completed. */
    bool negotiated;
    /** Version that was agreed. */
    tapi_tls_version version;
    /** Cipher that was agreed, or @c NULL. */
    char *cipher;
    /** Size of the server's public key, bits; @c 0 when not reported. */
    unsigned int server_key_bits;
    /** OpenSSL's verify result, @c 0 when the chain verified. */
    int verify_code;
    /** OpenSSL's wording for @a verify_code, or @c NULL. */
    char *verify_text;
    /** The server supports secure renegotiation. */
    bool secure_renegotiation;
    /** The chain in PEM, when it was asked for; @c NULL otherwise. */
    char *chain_pem;
    /** Everything @c s_client printed, for a test that wants more. */
    char *raw;
} tapi_tls_handshake;

/**
 * Make one handshake and read what came back.
 *
 * @param[in]  factory      Job factory; the connection is made from
 *                          this agent.
 * @param[in]  opt          What to offer.
 * @param[in]  timeout_ms   How long to let @c s_client run.
 * @param[out] handshake    What came back; release it with
 *                          tapi_tls_handshake_free().
 *
 * @return Status code.
 */
extern te_errno tapi_tls_probe(tapi_job_factory_t *factory,
                               const tapi_tls_probe_opt *opt,
                               int timeout_ms,
                               tapi_tls_handshake *handshake);

/**
 * Write a handshake into the log.
 *
 * @param handshake     Result of tapi_tls_probe().
 */
extern void tapi_tls_handshake_log(const tapi_tls_handshake *handshake);

/**
 * Release a handshake.
 *
 * @param handshake     Result of tapi_tls_probe().
 */
extern void tapi_tls_handshake_free(tapi_tls_handshake *handshake);

/**
 * Find out which protocol versions an endpoint accepts.
 *
 * One handshake is attempted per version, so this costs as many
 * timeouts as there are versions.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  opt          Endpoint to ask; its @a version is ignored.
 * @param[in]  timeout_ms   How long to let each attempt run.
 * @param[out] accepted     Bit mask of @c 1 << #tapi_tls_version for
 *                          the versions that completed a handshake.
 *
 * @return Status code.
 */
extern te_errno tapi_tls_scan_versions(tapi_job_factory_t *factory,
                                       const tapi_tls_probe_opt *opt,
                                       int timeout_ms,
                                       unsigned int *accepted);

/** What an endpoint is required to do. */
typedef struct tapi_tls_policy {
    /** Oldest version the endpoint may agree to. */
    tapi_tls_version min_version;
    /** Smallest server key, bits. */
    unsigned int min_key_bits;
    /** Fewest days the certificate must still be valid for. */
    unsigned int min_days_left;
    /** The chain must verify against the trust anchors. */
    bool require_valid_chain;
    /** The certificate must be valid for this name, or @c NULL. */
    const char *expected_name;
    /** Signature algorithms that are not acceptable, @c NULL terminated. */
    const char *const *weak_signatures;
} tapi_tls_policy;

/**
 * The default policy: nothing older than TLS 1.2, a key of at least
 * 2048 bits, a month of validity left, a chain that verifies, and no
 * SHA-1 or MD5 in the signature.
 */
extern const tapi_tls_policy tapi_tls_default_policy;

/**
 * Check an endpoint against a policy.
 *
 * Scans the versions, takes the certificate the endpoint presents, and
 * reports everything that does not match.
 *
 * @param[in]     factory     Job factory.
 * @param[in]     opt         Endpoint to check.
 * @param[in]     policy      Policy, or @c NULL for
 *                            @ref tapi_tls_default_policy.
 * @param[in]     timeout_ms  How long to let each attempt run.
 * @param[in,out] report      Report to append findings to.
 *
 * @return Status code.
 */
extern te_errno tapi_tls_check_server(tapi_job_factory_t *factory,
                                      const tapi_tls_probe_opt *opt,
                                      const tapi_tls_policy *policy,
                                      int timeout_ms,
                                      tapi_cybersec_report *report);

/**
 * Spell out a protocol version.
 *
 * @param version       Version.
 *
 * @return A static string, never @c NULL.
 */
extern const char *tapi_tls_version2str(tapi_tls_version version);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_TLS_H__ */

/**@} <!-- END tapi_tls --> */
