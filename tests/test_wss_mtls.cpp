/* SPDX-License-Identifier: MPL-2.0 */

#include <string.h>
#include <stdio.h>
#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

#ifdef ZMQ_WSS_REQUIRE_CLIENT_CERT

//  Fixtures: CA, server cert+key (CN=TestServer, SAN:DNS=localhost), and
//  client cert+key (CN=minion-01). All signed by a locally-generated CA
//  whose private material is NOT bundled; only the CA cert is needed to
//  validate the chain, so these fixtures are safe to embed.

static const char *ca_pem =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIDAzCCAeugAwIBAgIUdsChx+UBSxxkMyuA025q/fD5nMwwDQYJKoZIhvcNAQEL\n"
  "BQAwETEPMA0GA1UEAwwGVGVzdENBMB4XDTI2MTEwMTA4MjEwOVoXDTM2MTAyOTA4\n"
  "MjEwOVowETEPMA0GA1UEAwwGVGVzdENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n"
  "MIIBCgKCAQEAxLbdIN5LyVPj+Pf4gHZb2SYMwsotdB/5gatzpmX/1vf2jgPWFrvu\n"
  "YzynX1acsbx2yJ+dVN39Iw8aAGrNYqFRaZOjF/4DYc4jOCfHGXfpWST8Ykk0Hanc\n"
  "IfwKOcNzDRw+5OCk5OLUf91yiHNgvl91ld3uzQMl3q0kzVEWa0CppaeKI8l44nnL\n"
  "fC49XREQwaAKplX/szQ2oBpGfPf2QYYrtWBY5ML0uxf2/+RhJywQf6c4dwzJ3fa3\n"
  "nttBmATc6iaVCZv8XuEeOLxk1gqjB4qOKljBWoj7Ha3f3SWfh5sl43zrssZNIpex\n"
  "2mNUcpS3HqFrxwZo3pnwpoGkqPwVU8QIzwIDAQABo1MwUTAdBgNVHQ4EFgQUNG6k\n"
  "+/3r89M520uEGqFoUOmlkGYwHwYDVR0jBBgwFoAUNG6k+/3r89M520uEGqFoUOml\n"
  "kGYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAeXB/WFgt37xZ\n"
  "QFtn9ziP8aI0qoHkejrxCqVA7wxhvup2XkOCh1MJ8q5PXU75uDP0N9bfiVLeOc+F\n"
  "9+DoQSvAvD4bbmtqmGoIf7Ac2CiroceCQZEBNeT99RcL8N+80wjo/OJCNztfrVqf\n"
  "cNG0LJ+9a/1x5dduX9jv04ZC2oJuI1Wv+Wj2K42Xs26XYEhrLCB6RDIvRdfbPlMA\n"
  "v/EeyPD9AAjWCxmI7Wv+QkM+/3u4FwnKZflqBQLrZX+s4luBmJXs6BP4s52LwvYY\n"
  "f8SUUJNSLj7ZJSGm89TPdInjkjXwsBvyBmLKgFI6z3U9qczkwFBOLSP/uRNHhsY3\n"
  "VsX4CKtIiQ==\n"
  "-----END CERTIFICATE-----\n";

static const char *server_cert =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIDDDCCAfSgAwIBAgIUTQT5+fzqLOmjBMkuLt5Q0HGc1KcwDQYJKoZIhvcNAQEL\n"
  "BQAwETEPMA0GA1UEAwwGVGVzdENBMB4XDTI2MTEwMTA4MjEwOVoXDTM2MTAyOTA4\n"
  "MjEwOVowFTETMBEGA1UEAwwKVGVzdFNlcnZlcjCCASIwDQYJKoZIhvcNAQEBBQAD\n"
  "ggEPADCCAQoCggEBALispRyBHTNp0ENGeLuq2Su4UaYhvjKG6SKERfDpWmy4ZuQy\n"
  "h2EN7dnbkquj3vQTUeZV3r7UYnGq/rRPrGEW3JpoPWmk6smFXH/vitU3iC4BuxE7\n"
  "JKFuMBcyX4O5OvCctFhiTb5ZHxQ31VpWA9zv/R8zy+fwXw/s9e6D6CckV1JKTSfO\n"
  "YRN8DOFov6pLMXs6pTtbW51LQhkiAsdTbwvoVWI1EbjlEXXe0NqoFnFAhVGTwA65\n"
  "vUb9nJySsa0A6YLLns/p+F6SpSP5p/D6TxvHSWMcc8oFUhVpM3g/ooJfsd8I5PUc\n"
  "x38KiJaruBlEPyQvswfGBr3jB1LOsOJ8CaUSGfUCAwEAAaNYMFYwFAYDVR0RBA0w\n"
  "C4IJbG9jYWxob3N0MB0GA1UdDgQWBBRAGcX0PNjH4qLYbEexuE2q+7ru/DAfBgNV\n"
  "HSMEGDAWgBQ0bqT7/evz0znbS4QaoWhQ6aWQZjANBgkqhkiG9w0BAQsFAAOCAQEA\n"
  "a0vRCelyEI09vTiRuLeo4tBDc11UamXISy0ZEXBSgSvH6cvaz0SFBcVaLYKKRbkP\n"
  "JpnixqymVz3sW0G2GViEoOmA4npxYX5X5GacdADqc1gA3jzMCg0A9c/4LPYZq46X\n"
  "mVtGfuji8sD70AspN7Ulq6lJ+iBDhUd2qvS9eBDnIqEGSzuRiB2B7ZH8Poc3bfdV\n"
  "S/x0NozF7fU2d8qN+33WazYt/dMHQb5CZRIwY+7zvACcy7nG35peS/88lduRSvXt\n"
  "ExTjZa27rHf8M9VOucRINm6vn3wytWMR/DAweMFld0IN4j3JDL4dym9AdrJ2lvUW\n"
  "Xxm9LlcDZ1njIvObggZrZg==\n"
  "-----END CERTIFICATE-----\n";

static const char *server_key =
  "-----BEGIN PRIVATE KEY-----\n"
  "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC4rKUcgR0zadBD\n"
  "Rni7qtkruFGmIb4yhukihEXw6VpsuGbkModhDe3Z25Kro970E1HmVd6+1GJxqv60\n"
  "T6xhFtyaaD1ppOrJhVx/74rVN4guAbsROyShbjAXMl+DuTrwnLRYYk2+WR8UN9Va\n"
  "VgPc7/0fM8vn8F8P7PXug+gnJFdSSk0nzmETfAzhaL+qSzF7OqU7W1udS0IZIgLH\n"
  "U28L6FViNRG45RF13tDaqBZxQIVRk8AOub1G/ZyckrGtAOmCy57P6fhekqUj+afw\n"
  "+k8bx0ljHHPKBVIVaTN4P6KCX7HfCOT1HMd/CoiWq7gZRD8kL7MHxga94wdSzrDi\n"
  "fAmlEhn1AgMBAAECggEAF3x3bCpcexkqMCAigyV9hJKmqaTxci4XsLjXR0X6JskF\n"
  "5uApOPXjSbljzBnlZS+e0xcZIrZShce8KFTYpKlaaXW317tuU642/xtJEghDtKwq\n"
  "LQ0TQceIbK7OmGtCfG7FfdcUsZBWhET8iIZXa+4GiEUXWdpHULhvZ4PVjsLPqyqJ\n"
  "+6+Vu0hr5C75F40kPA1P7JDVBv6iYcmFyl6RN0QWbG+o3KwEs1xUOCZabpr9og+7\n"
  "h4Wpw5w/S73Ma7H7uPjDXoUwT4+J/egzvbgX0e7nnYkBdUCf9mxEHNpEXjmipgfs\n"
  "utI/7XqlPuMtuD1UbQGGBYVvmtvHln+km743e5uSYQKBgQDoVvxVGKsbbhIpzOR9\n"
  "nl9KaqtNgPtW45zAfWWOyOgwvALUw7iCN/014WVspl7h+q66JymNB19vrbntujA2\n"
  "jaJU29Cat2UlRLlDIkjs9weYKfybmVHBZj/kn8cKtWc7WxXKMZPOEEBFVDPcAu1L\n"
  "pZ3O0KYQLHyFqT3fgj6m8GGk1QKBgQDLewoqTJ7LwqHxfnRiihY2cejONMWDnEuN\n"
  "GRL0LX2rK+kU6yJOAdsjL8rRwPKR5kZ8ZuqI7dTtcC8LwoTpsVnmYAtddgnoOilM\n"
  "pRw1Sp7y5p7rXxINdifHYdDePsi4gEL4ZtqVY0EjK1uPeMV1NT1q1ENR1efVLMuQ\n"
  "dMFElHuwoQKBgQDKT+xbgSaFtRwVz/dqtzxMxYOy8kxpxbsaFlcXtTQSM7TXZjJF\n"
  "GdHgWAuER365khsRt8ZDqpbc3U7YhdczubMP53THNEjb4fLcVX9g8F5pjq4LI7+A\n"
  "A7RBNSwR1BI3KkJYFUGaHqaIeCDMRLQyud0nWKIx1Tr8/HkHJhe+L/UmnQKBgQCE\n"
  "c572UdG8CQGpVQslaYV0A0nrkGZReVekjQHNeB8pYPfj6fr2lDa0/NMlHlfHqQGQ\n"
  "0N0yLL5BoJi/KuuhwxQl5bcAK2nfhJyFi6SE/AHjU0N3KvdxU8wo+P8g6/V0Q+lU\n"
  "EH+QZn9sCTkcdxzxYqqL84euqXKzTOllKtrzbUPmgQKBgQCgDf8Z1Wlm6dAwhK68\n"
  "bZp7MDF8vIbEUEwLwOv7MRZe3d76FhrNRk/f8qg3+SO6Ia19uiVglq/wkojM8fuf\n"
  "ZqiVuPsgTwj1mF4ayabuYGxzsN0CYr1epzhpDBeFlnyh10jsEiv0N/e8xXhAKSym\n"
  "JNyk4G+EzQDw8TLaEwqDvLg7yw==\n"
  "-----END PRIVATE KEY-----\n";

static const char *client_cert =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIC9TCCAd2gAwIBAgIUTQT5+fzqLOmjBMkuLt5Q0HGc1KgwDQYJKoZIhvcNAQEL\n"
  "BQAwETEPMA0GA1UEAwwGVGVzdENBMB4XDTI2MTEwMTA4MjEwOVoXDTM2MTAyOTA4\n"
  "MjEwOVowFDESMBAGA1UEAwwJbWluaW9uLTAxMIIBIjANBgkqhkiG9w0BAQEFAAOC\n"
  "AQ8AMIIBCgKCAQEApUBa3gM5I85JHGapQ0KS6X1vER2pCV4e/RN+B2fAdBY6fsla\n"
  "xJTp/ouKS3ToNAB+P9v7Z8VKBObynSUwYgtAkoBCMUq1++rm0p/s/obAiTKWistf\n"
  "sZYz+I7bocGxwxKF3+35/JnSdQF+PIEvhY5/ZCSiPz7MLSA3ocYTdxN8IQXNbWIn\n"
  "Ot//6Aa7Vo7lDaDATxGgxXvaKYWywOayyvwk+MJttQU+Pt/qHQMD6z1ID6Oz1d2T\n"
  "9CD9D7Kk68NC4wNw2AEqdGmh2zxgQry/uUiVn2jwrE/5TnptyVDNALgXmHHdN6MT\n"
  "kHbbbmv/qc0RkXHYiljdG8PVw8uld89P4jzw4QIDAQABo0IwQDAdBgNVHQ4EFgQU\n"
  "vQln03ixG1ovVe3pcsseG7rM5S8wHwYDVR0jBBgwFoAUNG6k+/3r89M520uEGqFo\n"
  "UOmlkGYwDQYJKoZIhvcNAQELBQADggEBAJ1G3n8jqqcfohTvyF4szru3lNgxa2rn\n"
  "UheZAHPh+DGOuLwi5KqsvFA9POAPJ4frRD/Z2YH5z8z7wklD4gfBosM/uuXZTTWK\n"
  "dS3i/1voGXHi1uEgZObDaJQPtg/dG+n0/tXLUx7f0h+h/xAeLnZhe80HTbquJipx\n"
  "DnTkOv1D+qAymZSJD/khecP62EBGJH1OEexq+64iv6tsaRt0JOWiAzlBIBUcDAwX\n"
  "SZ0EEoH/rxyLHNCAheINv0efpFR88yvLDAhX4nu4A5QjCxSHiplVXaft7xc5PlwM\n"
  "EHSGXI75Kx1jKBfeqM4Ndk4zIX7DRB0BqqtWpP2lDpyIQVRnBMVEnHw=\n"
  "-----END CERTIFICATE-----\n";

static const char *client_key =
  "-----BEGIN PRIVATE KEY-----\n"
  "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClQFreAzkjzkkc\n"
  "ZqlDQpLpfW8RHakJXh79E34HZ8B0Fjp+yVrElOn+i4pLdOg0AH4/2/tnxUoE5vKd\n"
  "JTBiC0CSgEIxSrX76ubSn+z+hsCJMpaKy1+xljP4jtuhwbHDEoXf7fn8mdJ1AX48\n"
  "gS+Fjn9kJKI/PswtIDehxhN3E3whBc1tYic63//oBrtWjuUNoMBPEaDFe9ophbLA\n"
  "5rLK/CT4wm21BT4+3+odAwPrPUgPo7PV3ZP0IP0PsqTrw0LjA3DYASp0aaHbPGBC\n"
  "vL+5SJWfaPCsT/lOem3JUM0AuBeYcd03oxOQdttua/+pzRGRcdiKWN0bw9XDy6V3\n"
  "z0/iPPDhAgMBAAECggEAHPtqdGGQVe1J+UcwDHHSnky3fAL9sHznZm9SvS2/HR0A\n"
  "6VebKbsMRu5mNNGuH+CuQ7jrIMoDL1Tp3BG3qJpcmtUPxuFZhXMvRGV0BTfQ8L8E\n"
  "lBcTE2xKdR9o+bek25eWDy4Hl/vKY2b9otLtaLkTMpcSNZFn8coit6arp0itjoTT\n"
  "2srDVGKmYeHc8fV83mQqXFzMyjORSaeKy+WWKG4SDK1XPXmvm0P8gDMmJTyR97sW\n"
  "+RGhWCEBpKc8wnalsuPseRzpXTqU6iX1dP5G4otzR4HUfUQstkd7JZD+0FS26HKb\n"
  "96haxCLe3LgS0jFD07ZRWowuVTuHPmVLobAYyqRA+QKBgQDO3IFvZZgs97UNdjAi\n"
  "la35UUA/smvE8OYcvnDTkGZ07aK/92nyQyJ474ZcD+vPX+SYefmjbexIHDs8Liq0\n"
  "c45ARpR5YB+HQ+AueFnE6btPkwx2rsZGeoo3THIabDCXRm1tkIdqPV0IQggeqqOU\n"
  "SZoY8y0PWfvjavhEIs/p/eNYwwKBgQDMgX770+ZuelvFwatE/O/GqvugcI4F3tjF\n"
  "jTWjDFeJaAN7yZz3JgWzAtIV1GXYoTOIIl6QC5DUuBzoJVq5bnx2+HiHsZ+ghZE2\n"
  "OU8/v4IYxO5RHkN/AxAH3tI3babsI0zmzf0YGNgZS9zUKW7vP92xlYiG2rq0yZoB\n"
  "cwbqWjFViwKBgCazYE/b/PVkvm2vT+AYirzbM573HWxx+UslYexi1phHoSwy+JJH\n"
  "dxqTDVsJ638XnKfeIhMuTIdNKNPge0LZX6Ks0bhHgH6I91caUwkhBVck1q8ZkaS7\n"
  "5kHkPnCtDwYuOejGol8A7ffOisBaAlKK1paWYDbACf0JFTuCG83WHwOLAoGAYxse\n"
  "fsviEAgcEWoZpgUt7glOiCIDsbSdOJ+GLs38XgqaJZM/DkbO3EGxrgKQmLsGTiLZ\n"
  "0NTKC0xuNdJkdRimGMGxJ5Fc2l3gUXbUgQA9++Lz2zvfWd4SFr5VAaeSDT3ONsv8\n"
  "q4DeuOOa0PaDXE6HEVh2IWQ+tv48NBeaclfjMKECgYEAiqVfzjmyX8/UC6oKNPcF\n"
  "9LN6MgPh0iyBBJEhF1ACnKA1n7Bgib7+pAAhfn4qy1oI9l5KiAii4m/CRFXO2GwO\n"
  "TF7wWFpynETZ4mtfXIihd62aFDbItX7BsBGEJxtBD1GX2b3YHtQJV48IBsW5znd9\n"
  "1DbvwBJyLWrEIxTNXfuQU8w=\n"
  "-----END PRIVATE KEY-----\n";

static void *make_server (bool require_client_cert_)
{
    void *sb = test_context_socket (ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sb, ZMQ_WSS_CERT_PEM, server_cert, strlen (server_cert)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sb, ZMQ_WSS_KEY_PEM, server_key, strlen (server_key)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sb, ZMQ_WSS_CLIENT_TRUST_PEM, ca_pem, strlen (ca_pem)));
    int require = require_client_cert_ ? 1 : 0;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sb, ZMQ_WSS_REQUIRE_CLIENT_CERT,
                                               &require, sizeof (require)));
    return sb;
}

static void *make_client (bool present_client_cert_)
{
    void *sc = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_WSS_TRUST_PEM, ca_pem, strlen (ca_pem)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_WSS_HOSTNAME, "localhost", strlen ("localhost")));
    if (present_client_cert_) {
        TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
          sc, ZMQ_WSS_CERT_PEM, client_cert, strlen (client_cert)));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
          sc, ZMQ_WSS_KEY_PEM, client_key, strlen (client_key)));
    }
    return sc;
}

//  Positive path: server requires a client cert, client presents one that
//  chains to the CA. Handshake succeeds; messages arrive on both sides,
//  and each side's Peer-Cert-* properties describe the other's certificate.
void test_mtls_exposes_peer_cert ()
{
    char connect_address[MAX_SOCKET_STRING + sizeof ("/mtls") - 1];
    size_t addr_length = sizeof (connect_address);

    void *sb = make_server (true);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "wss://127.0.0.1:*/mtls"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, connect_address, &addr_length));
    strcat (connect_address, "/mtls");

    void *sc = make_client (true);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, connect_address));

    TEST_ASSERT_EQUAL_INT (5, zmq_send (sc, "hello", 5, 0));

    //  Server-side: Peer-Cert-* describes the client's certificate.
    zmq_msg_t msg;
    zmq_msg_init (&msg);
    TEST_ASSERT_EQUAL_INT (5, zmq_msg_recv (&msg, sb, 0));
    const char *cn = zmq_msg_gets (&msg, "Peer-Cert-Subject-CN");
    TEST_ASSERT_NOT_NULL (cn);
    TEST_ASSERT_EQUAL_STRING ("minion-01", cn);
    const char *fp = zmq_msg_gets (&msg, "Peer-Cert-SHA256");
    TEST_ASSERT_NOT_NULL (fp);
    TEST_ASSERT_EQUAL_INT (64, (int) strlen (fp));
    zmq_msg_close (&msg);

    TEST_ASSERT_EQUAL_INT (5, zmq_send (sb, "world", 5, 0));

    //  Client-side: Peer-Cert-* describes the server's certificate.
    zmq_msg_t reply;
    zmq_msg_init (&reply);
    TEST_ASSERT_EQUAL_INT (5, zmq_msg_recv (&reply, sc, 0));
    const char *server_cn = zmq_msg_gets (&reply, "Peer-Cert-Subject-CN");
    TEST_ASSERT_NOT_NULL (server_cn);
    TEST_ASSERT_EQUAL_STRING ("TestServer", server_cn);
    const char *server_san = zmq_msg_gets (&reply, "Peer-Cert-SAN-DNS");
    TEST_ASSERT_NOT_NULL (server_san);
    TEST_ASSERT_EQUAL_STRING ("localhost", server_san);
    const char *server_fp = zmq_msg_gets (&reply, "Peer-Cert-SHA256");
    TEST_ASSERT_NOT_NULL (server_fp);
    TEST_ASSERT_EQUAL_INT (64, (int) strlen (server_fp));
    zmq_msg_close (&reply);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

//  Negative path: server requires a client cert; client connects without
//  one. The TLS handshake must fail and no message should flow in either
//  direction.
void test_mtls_rejects_unauthenticated_client ()
{
    char connect_address[MAX_SOCKET_STRING + sizeof ("/mtls") - 1];
    size_t addr_length = sizeof (connect_address);

    void *sb = make_server (true);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "wss://127.0.0.1:*/mtls"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, connect_address, &addr_length));
    strcat (connect_address, "/mtls");

    //  Deliberately omit the client cert/key.
    void *sc = make_client (false);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, connect_address));

    int timeout = 500;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_SNDTIMEO, &timeout, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sb, ZMQ_RCVTIMEO, &timeout, sizeof (int)));

    //  Send may succeed into the local queue; the receive on the server
    //  side must not deliver the message, because the handshake never
    //  completes.
    zmq_send (sc, "hello", 5, 0);

    char buf[16];
    int rc = zmq_recv (sb, buf, sizeof (buf), 0);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EAGAIN, errno);

    test_context_socket_close_zero_linger (sc);
    test_context_socket_close_zero_linger (sb);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_mtls_exposes_peer_cert);
    RUN_TEST (test_mtls_rejects_unauthenticated_client);
    return UNITY_END ();
}
#else
int main ()
{
    printf ("WSS mTLS unavailable, skipping test\n");
    return 77;
}
#endif
