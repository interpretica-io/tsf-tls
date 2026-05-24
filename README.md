# tsf-tls

TLS assurance for a Test Environment (TE) suite, packaged as an external
TE repository and consumed with the `TE_EXT_REPO` builder directive.

Library:

- `tapi_tls` — engine-side, built as a shared library:
  - `tapi_tls` — one handshake with parameters of your choosing, what
    came back, and the versions an endpoint accepts;
  - `tapi_tls_cert` — what the certificate says, and whether any of it
    is still true;
  - `tapi_tls_server` — the other direction: stand up a server with a
    deliberately bad certificate and see whether the device's own client
    notices.

The traffic rules of
[tsf-cybersec](https://github.com/interpretica-io/tsf-cybersec) watch a
handshake go past and say whether it was an old one. This asks the
questions directly, and asks the one that passive observation cannot.

Everything is driven through `openssl` on an agent, the same way
`objdump` and Frida are driven in tsf-cybersec. Nothing new is linked
into the engine, a protocol version the engine's own library dropped
years ago can still be offered to the device, and every connection comes
from a Test Agent the suite already owns.

## Usage

```
TE_EXT_REPO_USE([tsf_devtool], [], [tapi_devtool])
TE_EXT_REPO_USE([tsf_kernel], [], [tapi_kernel])
TE_EXT_REPO_USE([tsf_cybersec], [], [tapi_cybersec])
TE_EXT_REPO_USE([tsf_tls], [], [tapi_tls])
```

Then add `tapi_tls` to `te_libs` in the suite's `meson.build`. Findings
use the report model of tsf-cybersec, so a TLS group and a scanning
group produce the same kind of result and share one verdict.

Requires TE with `TE_EXT_REPO` support, an **RPC** job factory, and
`openssl` on the agent that does the probing.

## Checking a server

```c
tapi_tls_probe_opt opt = tapi_tls_probe_default_opt;
tapi_tls_policy policy = tapi_tls_default_policy;

opt.host = "10.0.0.7";
opt.port = 443;
policy.expected_name = "dut.example.net";

CHECK_RC(tapi_tls_check_server(factory, &opt, &policy, 10000, &report));
```

That scans the protocol versions, takes the certificate the endpoint
presents, and reports everything that does not match the policy:

| Finding | |
|---|---|
| `tls.obsolete-version` | the endpoint agreed to something older than the policy allows |
| `tls.weak-key` | the key is smaller than required |
| `tls.weak-signature` | signed with SHA-1, MD5 or worse |
| `tls.certificate-expired` / `tls.certificate-expiring` | out of time, or nearly |
| `tls.self-signed` | nothing but itself vouches for it |
| `tls.chain-not-verified` | verification failed against the trust anchors |
| `tls.name-mismatch` | the certificate does not cover the name it is serving |
| `tls.insecure-renegotiation` | no secure renegotiation, below TLS 1.3 |

Expiry is **asked, not computed**: `openssl x509 -checkend` answers
"will this still be valid in N seconds" and nobody has to parse a date
or think about a time zone.

Names come from the subject alternative names as well as the common
name, and the one wildcard form that is allowed — a leading `*.`
standing for exactly one label — is honoured.

## Checking the client, which is where the findings are

A server with a valid certificate cannot tell you anything about a
client. A client that checks nothing looks exactly like a client that
checks everything, until it is offered something wrong.

```c
tapi_tls_server_opt opt = tapi_tls_server_default_opt;
tapi_tls_server *server = NULL;
tapi_tls_client_behaviour behaviour;

opt.port = 4433;
opt.defect = TAPI_TLS_SERVER_SELF_SIGNED;
opt.common_name = "dut.example.net";

CHECK_RC(tapi_tls_server_start(factory, &opt, 10000, &server));
... make the device connect to this agent on port 4433 ...
CHECK_RC(tapi_tls_server_stop(server, &behaviour));
CHECK_RC(tapi_tls_check_client(opt.defect, behaviour, "update-client",
                               &report));
```

Four certificates, one defect each:

| Defect | The certificate is |
|---|---|
| `TAPI_TLS_SERVER_VALID` | correct — the control case |
| `TAPI_TLS_SERVER_SELF_SIGNED` | signed by itself, so no trust anchor leads to it |
| `TAPI_TLS_SERVER_EXPIRED` | well formed, for a time that has passed |
| `TAPI_TLS_SERVER_WRONG_NAME` | well formed and current, for somebody else |

Except for the self-signed one, they are signed by a test authority that
is generated alongside, so the **only** thing wrong with the certificate
is the thing under test. `tapi_tls_server_ca_file()` gives that
authority's certificate: install it in the device's trust store and the
control case becomes meaningful — a client that then refuses
`TAPI_TLS_SERVER_VALID` is broken in a different way, and one that
accepts it is known to be checking something.

A client that completes the handshake anyway is
`tls.client-accepts-self-signed` and friends, at CRITICAL: everything
that connection carries is readable and writable by whoever sits in the
middle.

A run where nothing connected reports `tls.client-did-not-connect` at
INFO rather than passing quietly. Nothing was proven either way, and
saying so is the honest result.

## Notes

- **A probe costs about its timeout.** `s_client` stays connected once
  the handshake is done, and `tapi_job` has no way to close a job's
  standard input, so a probe runs it, waits, stops it and reads what it
  printed. Everything worth reading is printed immediately, so nothing
  is lost — but a five-version scan costs five timeouts, and the timeout
  should be short.
- **A version the agent's OpenSSL was built without** cannot be offered,
  and shows up as a probe that never connected rather than as a refused
  handshake. It is logged as such, so it is not mistaken for a server
  that declined.
- **Dating a certificate in the past** uses `openssl x509 -not_after`,
  which needs OpenSSL 3.0. On an older one, hand in a certificate of
  your own through `tapi_tls_server_opt::cert_file`.
- The scanners point at the endpoints the suite's own configuration
  describes. That is the engagement they belong to.
