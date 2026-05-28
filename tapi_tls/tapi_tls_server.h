/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Testing the other end
 *
 * @defgroup tapi_tls_server Does the client check? (tapi_tls_server)
 * @ingroup tapi_tls
 * @{
 *
 * The question that finds the most, and the one nothing else here asks:
 * when the device under test is the TLS **client**, does it verify the
 * certificate at all?
 *
 * A server with a valid certificate cannot answer that. A client that
 * checks nothing looks exactly like a client that checks everything,
 * until it is offered something wrong. So this stands up a server whose
 * certificate is wrong in a chosen way, lets the device connect to it,
 * and reports what the device did about it.
 *
 * @code
 * tapi_tls_server_opt opt = tapi_tls_server_default_opt;
 * tapi_tls_server *server = NULL;
 * tapi_tls_client_behaviour behaviour;
 *
 * opt.port = 4433;
 * opt.defect = TAPI_TLS_SERVER_SELF_SIGNED;
 * opt.common_name = "dut.example.net";
 *
 * CHECK_RC(tapi_tls_server_start(factory, &opt, 10000, &server));
 * ... make the device connect to this agent on port 4433 ...
 * CHECK_RC(tapi_tls_server_stop(server, &behaviour));
 *
 * if (behaviour == TAPI_TLS_CLIENT_COMPLETED)
 *     TEST_VERDICT("The client accepted a self-signed certificate");
 * @endcode
 *
 * @note An expired certificate is generated with the @c -not_after
 *       option of @c openssl @c req, which needs OpenSSL 3.0 or newer.
 *       On an older one, hand in a certificate of your own through
 *       tapi_tls_server_opt::cert_file.
 *
 * @note A test that gets @ref TAPI_TLS_CLIENT_NONE learns nothing:
 *       the device never connected, so nothing was proven either way.
 *       That is reported as its own outcome rather than as a pass.
 */

#ifndef __TSF_TAPI_TLS_SERVER_H__
#define __TSF_TAPI_TLS_SERVER_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "tapi_job.h"

#include "tapi_cybersec.h"

#ifdef __cplusplus
extern "C" {
#endif

/** What is wrong with the server's certificate, on purpose. */
typedef enum tapi_tls_server_defect {
    /** Nothing: the control case. */
    TAPI_TLS_SERVER_VALID = 0,
    /** Signed by itself, so no trust anchor leads to it. */
    TAPI_TLS_SERVER_SELF_SIGNED,
    /** Valid, but its time has passed. */
    TAPI_TLS_SERVER_EXPIRED,
    /** Well formed, for somebody else's name. */
    TAPI_TLS_SERVER_WRONG_NAME,
} tapi_tls_server_defect;

/** What the client did about it. */
typedef enum tapi_tls_client_behaviour {
    /** Nothing connected, so nothing was learned. */
    TAPI_TLS_CLIENT_NONE = 0,
    /** It completed the handshake and carried on. */
    TAPI_TLS_CLIENT_COMPLETED,
    /** It refused, and said why in an alert. */
    TAPI_TLS_CLIENT_REJECTED,
} tapi_tls_client_behaviour;

/** How to stand up the server. */
typedef struct tapi_tls_server_opt {
    /** The @c openssl program; @c NULL means @c openssl. */
    const char *openssl;
    /** Port to listen on. Mandatory. */
    uint16_t port;
    /** What to be wrong about. */
    tapi_tls_server_defect defect;
    /** Name the certificate claims; @c NULL means @c "localhost". */
    const char *common_name;
    /** Name to put in a @ref TAPI_TLS_SERVER_WRONG_NAME certificate. */
    const char *wrong_name;
    /** Directory on the agent to generate into; @c NULL for its temp dir. */
    const char *work_dir;
    /** Use this certificate instead of generating one. */
    const char *cert_file;
    /** Key of @a cert_file. */
    const char *key_file;
    /** Serve a page, so that a client that checks nothing gets an answer. */
    bool www;
    /**
     * Stop listening after this many connections; @c 0 means never.
     *
     * The default is @c 1, and it is not a limit but the measurement.
     * `s_server` says nothing about a handshake while it is running -
     * with @c -www it prints @c ACCEPT and then nothing at all,
     * whether the client completed the handshake, refused the
     * certificate or never arrived. What it does print, on the way
     * out, is its session statistics, and those answer the question
     * exactly:
     *
     *     1 server accepts (SSL_accept())
     *     1 server accepts that finished
     *
     * So the server is asked to serve one connection and leave. A test
     * that needs it to stay up for several sets this higher and gets
     * the totals for all of them; a test that sets it to @c 0 gets a
     * server that never reports, and
     * @ref TAPI_TLS_CLIENT_NONE whatever the client did.
     */
    unsigned int naccept;
} tapi_tls_server_opt;

/** Default: a self-signed certificate for @c localhost, serving a page. */
extern const tapi_tls_server_opt tapi_tls_server_default_opt;

/** A running server. */
typedef struct tapi_tls_server tapi_tls_server;

/**
 * Generate a certificate with a chosen defect.
 *
 * Useful on its own: the same certificate can be handed to something
 * other than @c s_server.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  opt          What to generate; @a port is not used.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] cert_file    String to append the path of the certificate
 *                          on the agent to.
 * @param[out] key_file     String to append the path of the key to.
 * @param[out] ca_file      String to append the path of the test
 *                          authority's certificate to, or @c NULL. It
 *                          is empty for a self-signed certificate,
 *                          which has no authority behind it.
 *
 * @return Status code.
 */
extern te_errno tapi_tls_server_make_cert(tapi_job_factory_t *factory,
                                          const tapi_tls_server_opt *opt,
                                          int timeout_ms,
                                          te_string *cert_file,
                                          te_string *key_file,
                                          te_string *ca_file);

/**
 * Start the server and wait for something to connect to it.
 *
 * @param[in]  factory      Job factory; the server listens on this agent.
 * @param[in]  opt          How to stand it up.
 * @param[in]  timeout_ms   Timeout for generating the certificate, ms.
 * @param[out] server       Handle; released by tapi_tls_server_stop().
 *
 * @return Status code.
 */
extern te_errno tapi_tls_server_start(tapi_job_factory_t *factory,
                                      const tapi_tls_server_opt *opt,
                                      int timeout_ms,
                                      tapi_tls_server **server);

/**
 * Get the certificate of the test authority the server's certificate
 * was signed by.
 *
 * Install it in the device's trust store and the control case becomes
 * meaningful: a client that then refuses @ref TAPI_TLS_SERVER_VALID is
 * broken in a different way, and one that accepts it is known to be
 * checking something.
 *
 * @param server        Handle.
 *
 * @return Path on the agent, or @c NULL for a self-signed certificate.
 */
extern const char *tapi_tls_server_ca_file(const tapi_tls_server *server);

/**
 * Stop the server and say what the client did.
 *
 * The handle is released whether the call succeeds or not.
 *
 * @param[in]  server       Handle.
 * @param[out] behaviour    What the client did.
 *
 * @return Status code.
 */
extern te_errno tapi_tls_server_stop(tapi_tls_server *server,
                                     tapi_tls_client_behaviour *behaviour);

/**
 * Turn what the client did into a finding.
 *
 * A client that completes a handshake with a certificate it should have
 * refused is a critical finding: everything the connection carries is
 * readable and writable by whoever is in the middle.
 *
 * @param[in]     defect     What was wrong with the certificate.
 * @param[in]     behaviour  What the client did.
 * @param[in]     subject    What the finding is about, e.g. the name of
 *                           the component that connected.
 * @param[in,out] report     Report to append findings to.
 *
 * @return Status code.
 */
extern te_errno tapi_tls_check_client(tapi_tls_server_defect defect,
                                      tapi_tls_client_behaviour behaviour,
                                      const char *subject,
                                      tapi_cybersec_report *report);

/**
 * Spell out a certificate defect.
 *
 * @param defect        Defect.
 *
 * @return A static string, never @c NULL.
 */
extern const char *tapi_tls_defect2str(tapi_tls_server_defect defect);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_TLS_SERVER_H__ */

/**@} <!-- END tapi_tls_server --> */
