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


//  A client certificate (CN=attacker) whose issuer is named CN=TestCA like
//  the trusted CA, but signed by a different key.
static const char *rogue_client_cert =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIC9DCCAdygAwIBAgIUR/CItckpBBtV8NmTLE810Vi+kXgwDQYJKoZIhvcNAQEL\n"
  "BQAwETEPMA0GA1UEAwwGVGVzdENBMB4XDTI2MTEyMzEyNDE0NFoXDTM2MTEyMDEy\n"
  "NDE0NFowEzERMA8GA1UEAwwIYXR0YWNrZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n"
  "DwAwggEKAoIBAQDEzsj2cZG7bjPe2m8yHjiNj0wSwFFSC4dO2fDPzBJ5zlOhMVO3\n"
  "BNys/kcSHfvFYBkjoJ2rM9hxd2hGdwrI44vOLjjjlj2+HuD1frE2ICCyfLexIVgS\n"
  "SrzCtavmVDpjY/3sFqp8E7BEjjFj6h+Nu9VNRC/Bk9L28kQglJp7lt5wwhkotZkn\n"
  "wIlbZLg7HP6CY5SXDRqlONnMvQr71jPpzf2i37Wm2oYOggF+hyDUQtYH7NwuQce/\n"
  "kWzQzCmykxRN3duG/OjOnO4DcqP0m/C2imp999RKT1yoIoMKysM1/t4m8HlPk2Nt\n"
  "5+7V767kN4wpi7rQjkSZqXA6fYaRLqM8d8OzAgMBAAGjQjBAMB0GA1UdDgQWBBR8\n"
  "5s92xvn7dH2gKicFlOknZzS2iDAfBgNVHSMEGDAWgBQCYFJ1/h8XqoO2FjNnEyMO\n"
  "vB8hFTANBgkqhkiG9w0BAQsFAAOCAQEAwilXhvpEa+QYT3LfwtsfTlbPPDULD+7b\n"
  "qwNgoxEZT76iZN5L/Z/Fh4bRU2xIHySWCddAoRU6blZE9xXN+BDDkLYD/TcEBbRp\n"
  "cJXEQ5oQR1v2auI3miHWfT0ZYw5GcmDafKkjByrnfHDoY+Wsd14wXI1H6rVc6Wek\n"
  "JpfKZyMt6m0XL3BK5AMZLDmxRvVPEG+ST/9vIu4cO6F19FionVWswzEVcZV2pvEe\n"
  "YwMRxuqkmLDFLSnTTxr1ERaCRODdpIJp9cEgte8Abt1rZIP3df8y96Q9ETEclfl9\n"
  "h8MeBESS/TWWfHlcDyNNRmzFYk7ruyF/vXdi1kyB/2HFTldRKUMd3w==\n"
  "-----END CERTIFICATE-----\n";

static const char *rogue_client_key =
  "-----BEGIN PRIVATE KEY-----\n"
  "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDEzsj2cZG7bjPe\n"
  "2m8yHjiNj0wSwFFSC4dO2fDPzBJ5zlOhMVO3BNys/kcSHfvFYBkjoJ2rM9hxd2hG\n"
  "dwrI44vOLjjjlj2+HuD1frE2ICCyfLexIVgSSrzCtavmVDpjY/3sFqp8E7BEjjFj\n"
  "6h+Nu9VNRC/Bk9L28kQglJp7lt5wwhkotZknwIlbZLg7HP6CY5SXDRqlONnMvQr7\n"
  "1jPpzf2i37Wm2oYOggF+hyDUQtYH7NwuQce/kWzQzCmykxRN3duG/OjOnO4DcqP0\n"
  "m/C2imp999RKT1yoIoMKysM1/t4m8HlPk2Nt5+7V767kN4wpi7rQjkSZqXA6fYaR\n"
  "LqM8d8OzAgMBAAECggEAPCqplmn+7wmQUwN9dhl2GZTi4WKpGceLfKg1LhnJ1jIl\n"
  "MATX/n4+hqaQDLJc66jm1pT+Tr4hYALsvoobInIqJgTMgItIYeynwnWScKUeyeJF\n"
  "+CFk/uaZUX9fx6EdXpBNqxT81sTgIP1FjTGgpuBzI9WCMhBisPs8p6c2mSz04Qxz\n"
  "sGidS/bcRkd0bUdOXRM/cfuo/QvExf6qpEQhdVvf0ekRon+bFkDtx9BvBxHLcaFu\n"
  "90fwBRiZ8BjDe8xZDhy+2w+kxp2dxhJZJ74tkB2k9/QIbcjNTsoutI3aH6CdEqek\n"
  "WaBD0TSWN+thZrLy8s7cP8xryvrQeKCQZMVhi3funQKBgQD7FKqi3TsfbrVT23No\n"
  "HWyanvsw78EDjvLmMKuf0liwIZ+9IwY6392dd0mQasE2Hr5rY5HCmDnyHxJ3PRT9\n"
  "R1UBEDr0EI0pgw/+xzG4kd9fBFciTcuBxAe2Osro6RYZ50iHv6HxGEyPRTE7ZDD6\n"
  "Qk5s4tDZftR7MIBL4Ts0FG/+zwKBgQDIqed1KZkvAazilcce1QbdYhnpcb0Xnpqp\n"
  "VWg0/x6bOcZk3ACi4zRkBM9f4KAMGpE7zSyLRtr9Seg2P/UtK0wnti8sGMty28Ef\n"
  "zNiXn9hiUkEfVkd33zyVVjSM7xufyP8ntyyoTmHwsk8HYkACLJ9tVvV/MstbDCku\n"
  "1qS9tPVF3QKBgQDk0WrIzjFpbe1WpPJB+j7Vkvl9GaKfaZE38zcVig9FRP9c0SSG\n"
  "VyqSrPmf4Yp/lfkXyUA3RZ/ZZjPf8wzD3lQ7id0QPF1JbaYQHNzVRit5Xm1CV/+V\n"
  "HV+h1WbCaFm59auF+0DMhcaP8xDw/VgdWnw6g2KuNAXU1ti1Tmg0CEQgxQKBgFfO\n"
  "sW/9ggCl1QdZz0ZYpaZedURH9xzM1JTgwLbgJH58a6pa8xRUI+rYh/5GhwKE5aSr\n"
  "haB0owNPQgPrPNhFKBAAkufS+cQLEZlexDClS8TKhaC22pND5njaviglwYrMI4s3\n"
  "hp0nn4f6Hsb2YVgSOrlX4hmFGqN+0M6kMnapJuMpAoGAMpRjcXO0ZobvFYO0xHXa\n"
  "7hVbf8ZLVY/STJu2QqTKH60gWBJ0wVsoWq2Cwqpa4tEhYI00NZKGl6d58kwhu9Sa\n"
  "nPUrDnpdxX7tekh3ZvtLwfF8c1TwkfEUHj53xMXATwl9jD0+FGo6xLGaEl/f8U97\n"
  "fPL5WWVKd/bMrJ4Nzas/P2A=\n"
  "-----END PRIVATE KEY-----\n";

//  Fixtures for the long-SAN test. The client certificate carries a
//  272-byte SAN URI followed by a DNS SAN. Exercises the resize path
//  in capture_peer_cert_properties (initial buffer 256 bytes) and
//  verifies the enumeration continues past the resized entry.

static const char *longsan_expected_uri =
  "spiffe://salt-cluster/very-long-identity-used-to-exercise-the-gnutls-"
  "short-memory-buffer-retry-path-in-capture-peer-cert-properties/"
  "organization-unit/subsystem-name/component/service/region/zone/"
  "cluster-id-abcdef0123456789/node-id-abcdef0123456789/"
  "replica-abcdef0123456789";

static const char *longsan_ca_pem =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIDCTCCAfGgAwIBAgIUJY2uxFuMjTW/IGIIEi0cmpK6msIwDQYJKoZIhvcNAQEL\n"
  "BQAwFDESMBAGA1UEAwwJTG9uZ1NhbkNBMB4XDTI2MTEyNDA5MTkwNVoXDTM2MTEy\n"
  "MTA5MTkwNVowFDESMBAGA1UEAwwJTG9uZ1NhbkNBMIIBIjANBgkqhkiG9w0BAQEF\n"
  "AAOCAQ8AMIIBCgKCAQEApM5t09iSSex1z8HILW45DGfOSR8sHA7RR5XRn2kv1RCp\n"
  "6s/7rMtDwYjQo5IrPx1Tv0CmXHYd+fAtClR9DTgl9QjGJy9epeecM+W7XKBJnRf4\n"
  "cKOMzj7HwjrudwYKa9f4wduyBQnmyJXBJPNSZWiwted+hzzYvbk6xLG+hyfGDCjs\n"
  "NS5l9O9ZnWXV3+Nz3w1mJXlLlHE7AGrv7hDcBn0AH2VF+FCuO4M5lAN7AsOBfX/r\n"
  "jgRuTJl0xK7CFNedmCcYpLDVMzF3bakQDEje9apLI//Eau85Aj+XpQig+RaQPt+9\n"
  "133mPq5u2GaeOjW8x1hrilpAtrH3X/ApK3RFwlmFNwIDAQABo1MwUTAdBgNVHQ4E\n"
  "FgQU3YnymfCudyCZkGSB/IFZF0QGrEQwHwYDVR0jBBgwFoAU3YnymfCudyCZkGSB\n"
  "/IFZF0QGrEQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEABw/u\n"
  "t0qQFdzg8Q27jfOo/sdGF8UrzwKJAXoAo0xqSKbQ5V0TAvteFWeJ9XpR8Vu7lAWy\n"
  "hsVw9L9SeITCUIjlr33MggxvvKcjxZmoKCCzV2mxuCF7gpp2L8aD9qaUaBIl6LLJ\n"
  "HhqXW6MjtpqWrxL5LZFlEjNroUGSN6OL3+iDOXO+dyC2aH4aC5jLNCeHc1O8bhiS\n"
  "FKunTTw+vBAQbqh0ZjmKPFhR7wL4mVNB2UpfG3K2rNX9j47IpFtplXFx1h/usChx\n"
  "96EARjEyB8jJ0Yy+ArFXnvNiC93zz1sqiMW+dTwQNNuHEZTLWuCJbEQaweRbR3Pe\n"
  "1Eku/hr9aNS10MRolw==\n"
  "-----END CERTIFICATE-----\n";

static const char *longsan_client_cert =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIEQjCCAyqgAwIBAgIUcYzRJB1Ksoqf/+GmDHjraT6eNmswDQYJKoZIhvcNAQEL\n"
  "BQAwFDESMBAGA1UEAwwJTG9uZ1NhbkNBMB4XDTI2MTEyNDA5MTkwNVoXDTM2MTEy\n"
  "MTA5MTkwNVowGTEXMBUGA1UEAwwObG9uZ3Nhbi1jbGllbnQwggEiMA0GCSqGSIb3\n"
  "DQEBAQUAA4IBDwAwggEKAoIBAQC3TmOAqRPJXmHziofoLSHL9fYlr41H+OYPUliW\n"
  "XANKhYJekZKsQdf9rGoFMTV0DY3yVmeMFEzFL5XxjYXW9koOgDGSIH89Z86gTHXQ\n"
  "txZMIo4UIi3rifY/Q+6YLqpj+vIfaHIiTBbgTGJo+rVoMMvJ4/iT+w9b9bjO20EJ\n"
  "pNgGe8w9Zxgo7NW5E8HfAZ1g4DJEaJ0j2J4AqFLR+j9/zUgSpQ0SU2Sbw3PfQ3ZJ\n"
  "SpJb5j15bvrQkCd5X+ObA97p3G8ZTZrau3z3WWL5nhEPzXXHtOQywXXZlJ5cT+cd\n"
  "OZUIQ/Boe/8u6LWleEU7ZptXwSc92trX4pAYLuShtV9JQU67AgMBAAGjggGFMIIB\n"
  "gTCCAT0GA1UdEQSCATQwggEwhoIBEHNwaWZmZTovL3NhbHQtY2x1c3Rlci92ZXJ5\n"
  "LWxvbmctaWRlbnRpdHktdXNlZC10by1leGVyY2lzZS10aGUtZ251dGxzLXNob3J0\n"
  "LW1lbW9yeS1idWZmZXItcmV0cnktcGF0aC1pbi1jYXB0dXJlLXBlZXItY2VydC1w\n"
  "cm9wZXJ0aWVzL29yZ2FuaXphdGlvbi11bml0L3N1YnN5c3RlbS1uYW1lL2NvbXBv\n"
  "bmVudC9zZXJ2aWNlL3JlZ2lvbi96b25lL2NsdXN0ZXItaWQtYWJjZGVmMDEyMzQ1\n"
  "Njc4OS9ub2RlLWlkLWFiY2RlZjAxMjM0NTY3ODkvcmVwbGljYS1hYmNkZWYwMTIz\n"
  "NDU2Nzg5ghpsb25nc2FuLWNsaWVudC5leGFtcGxlLmNvbTAdBgNVHQ4EFgQUnAhl\n"
  "BUdJmTCHhA+q7l0gAvynq1MwHwYDVR0jBBgwFoAU3YnymfCudyCZkGSB/IFZF0QG\n"
  "rEQwDQYJKoZIhvcNAQELBQADggEBABXckIrXdx91c2R4pfTl7bdy4ozCmLnsuX2x\n"
  "X+2WcR0waoFX0tDl9uI3CP9ZvrtGQZs1Bq0E1uSsbiyyEuhj+2GvKo3Ztt3/ZOAz\n"
  "XZxIvER6t+gAtJc40yii+c6ky6ViRz8tLzW1H74npeAn333jthlESsWON8xJFZSr\n"
  "p9oCynplc0fDkucNUSPfxPuoz54g5zJHNnmxkJChKZ/E56RDLBRRZxY7IxBypWfQ\n"
  "BNpcBSucIttJS4sHT6k19yQlVy+rmCfuQ7WQlOK9nbvMTkOa3x/U1iglKOpBHEcV\n"
  "cwUvbQ7a6bYgSlpxQSnvKb0AyqXC9dHbn4ZKjdTbVWupMapbH7Q=\n"
  "-----END CERTIFICATE-----\n";

static const char *longsan_client_key =
  "-----BEGIN PRIVATE KEY-----\n"
  "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3TmOAqRPJXmHz\n"
  "iofoLSHL9fYlr41H+OYPUliWXANKhYJekZKsQdf9rGoFMTV0DY3yVmeMFEzFL5Xx\n"
  "jYXW9koOgDGSIH89Z86gTHXQtxZMIo4UIi3rifY/Q+6YLqpj+vIfaHIiTBbgTGJo\n"
  "+rVoMMvJ4/iT+w9b9bjO20EJpNgGe8w9Zxgo7NW5E8HfAZ1g4DJEaJ0j2J4AqFLR\n"
  "+j9/zUgSpQ0SU2Sbw3PfQ3ZJSpJb5j15bvrQkCd5X+ObA97p3G8ZTZrau3z3WWL5\n"
  "nhEPzXXHtOQywXXZlJ5cT+cdOZUIQ/Boe/8u6LWleEU7ZptXwSc92trX4pAYLuSh\n"
  "tV9JQU67AgMBAAECggEAEauDSPxDdYZdH9prRnTPTLd9jl1xW45BMxnngzsEcDMV\n"
  "gaM7xdIlDYWIxM5dDj5eQA2XNrggPGPdaucPD003j1VJMgJi8ZrnnqkwNDnp8tXj\n"
  "50nyLkHi1G9qeQ4Ki8+9dkydr/OwwtdqJx9/zDbj9ia9KBqr/NvfgEU/bDwRPPKZ\n"
  "AC7Wvq5K3an9+BniSGHO3hxsv4gDLNrZ/GOUzq4KmT1G8tFXeODW9iCEp/9RwuLX\n"
  "+OjRREIpO4jXGUzDU3u89GO5jJGVYNMX3wvvSV8exaeZtphUN6Raqc6WHSnhisqi\n"
  "Ws+PCj+xXpul98sEQvYFhmxH61Vbf/1uiDaTM68/QQKBgQD18mwW1RW00/81gwKD\n"
  "rDHy12VShd0euLwU51BZr5+akEsk7vBhQ90gF5sS0iBRzQ6Ai657LoefQrctMfH3\n"
  "F5UqwPUx+I+khrmKNh4ATdVwa5zSwBQ0A0vN6JZ/hyUJabhkEAoXAXLdzplF6VQG\n"
  "kE9htMw+3f7CXAeXZv5Y9CjGewKBgQC+zH8XOqJJExQyzRmwEs93Sge8AB3z/Z+9\n"
  "+lKlJjF5wDF/ljHy8XJReLNmLgse2vWwlFPfCi3AknrQyOkyG/IH3D0E4faZ6uwK\n"
  "hPtsGloUR/WmVuWhohGHholouyNeRI7deTX1zQcmyPNwE5FFqPr7G7Hw6AdO2Guu\n"
  "qNSCGPFEwQKBgQCZ7ayaqahZMWmD20fikw3717VxbZiT1rjYOGGAkDtK6E4vgl/t\n"
  "8CRgJoYGxH431Cfkage8zsVQ9tdgMOcoZ5kTVgrfyJpWNX/AMdibBhu0rZVMDa1X\n"
  "VEzIRW6TyEh02Lbv4V3/QgfbLKefKsZNCVq1YwuFuTjt+d1Cc9JyZ/VxKwKBgELw\n"
  "mjI7Jw6+O9rq7HVC1DkE5xvFarzcobvUZER+1uLhVDxwJIwYu8Prtf1GcC5eIc7W\n"
  "62oYNx8WBTLVGkOzXEH3ugzJfmxX6IJ0T4WI5UuyR3QZjq0boEzNHc55wZnkMb9w\n"
  "NEdNrJGl9QrAQrqO46dP+ykLLu0xru3zW8NdHuDBAoGBAIG0x5P+eQD9/GWacN3j\n"
  "/obXwGAgbZBIEWIFomEVHtY9RMoRaGQNM0sLT0WxbI4VqD4i92qQtDXB1gR2VOAR\n"
  "NzX3N1XW39wrgAJnmklvL6pKdr2gI1r1EMnUBSh1MmWMNz1py56oYLVVfw5alXoT\n"
  "I9+RbzzvIOhUcFsgwgW2YzS8\n"
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

//  Negative path: server requires a client cert; client presents one that
//  does NOT chain to ZMQ_WSS_CLIENT_TRUST_PEM. The handshake must fail.
void test_mtls_rejects_untrusted_client_cert ()
{
    char connect_address[MAX_SOCKET_STRING + sizeof ("/mtls") - 1];
    size_t addr_length = sizeof (connect_address);

    void *sb = make_server (true);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "wss://127.0.0.1:*/mtls"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, connect_address, &addr_length));
    strcat (connect_address, "/mtls");

    void *sc = make_client (false);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      sc, ZMQ_WSS_CERT_PEM, rogue_client_cert, strlen (rogue_client_cert)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      sc, ZMQ_WSS_KEY_PEM, rogue_client_key, strlen (rogue_client_key)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, connect_address));

    int timeout = 500;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_SNDTIMEO, &timeout, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sb, ZMQ_RCVTIMEO, &timeout, sizeof (int)));

    zmq_send (sc, "hello", 5, 0);

    zmq_msg_t msg;
    zmq_msg_init (&msg);
    int rc = zmq_msg_recv (&msg, sb, 0);
    if (rc >= 0) {
        const char *cn = zmq_msg_gets (&msg, "Peer-Cert-Subject-CN");
        printf ("untrusted client accepted: Peer-Cert-Subject-CN=%s\n",
                cn ? cn : "(null)");
    }
    zmq_msg_close (&msg);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EAGAIN, errno);

    test_context_socket_close_zero_linger (sc);
    test_context_socket_close_zero_linger (sb);
}

//  SAN entries larger than the initial 256-byte buffer must trigger the
//  GNUTLS_E_SHORT_MEMORY_BUFFER retry path, and the enumeration must
//  continue past the resized entry so later SAN entries still arrive.
void test_mtls_handles_long_san_entry ()
{
    char connect_address[MAX_SOCKET_STRING + sizeof ("/mtls") - 1];
    size_t addr_length = sizeof (connect_address);

    void *sb = test_context_socket (ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sb, ZMQ_WSS_CERT_PEM, server_cert, strlen (server_cert)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sb, ZMQ_WSS_KEY_PEM, server_key, strlen (server_key)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      sb, ZMQ_WSS_CLIENT_TRUST_PEM, longsan_ca_pem, strlen (longsan_ca_pem)));
    int require = 1;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sb, ZMQ_WSS_REQUIRE_CLIENT_CERT,
                                               &require, sizeof (require)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "wss://127.0.0.1:*/mtls"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, connect_address, &addr_length));
    strcat (connect_address, "/mtls");

    void *sc = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_WSS_TRUST_PEM, ca_pem, strlen (ca_pem)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_WSS_HOSTNAME, "localhost", strlen ("localhost")));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      sc, ZMQ_WSS_CERT_PEM, longsan_client_cert, strlen (longsan_client_cert)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      sc, ZMQ_WSS_KEY_PEM, longsan_client_key, strlen (longsan_client_key)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, connect_address));

    TEST_ASSERT_EQUAL_INT (5, zmq_send (sc, "hello", 5, 0));

    zmq_msg_t msg;
    zmq_msg_init (&msg);
    TEST_ASSERT_EQUAL_INT (5, zmq_msg_recv (&msg, sb, 0));

    //  Full 272-byte URI survives the resize path, not truncated.
    const char *san_uri = zmq_msg_gets (&msg, "Peer-Cert-SAN-URI");
    TEST_ASSERT_NOT_NULL (san_uri);
    TEST_ASSERT_EQUAL_STRING (longsan_expected_uri, san_uri);

    //  DNS entry after the long URI proves enumeration continues.
    const char *san_dns = zmq_msg_gets (&msg, "Peer-Cert-SAN-DNS");
    TEST_ASSERT_NOT_NULL (san_dns);
    TEST_ASSERT_EQUAL_STRING ("longsan-client.example.com", san_dns);

    zmq_msg_close (&msg);

    TEST_ASSERT_EQUAL_INT (5, zmq_send (sb, "world", 5, 0));
    char reply[16];
    TEST_ASSERT_EQUAL_INT (5, zmq_recv (sc, reply, sizeof (reply), 0));

    test_context_socket_close_zero_linger (sc);
    test_context_socket_close_zero_linger (sb);
}

//  Misconfiguration: ZMQ_WSS_REQUIRE_CLIENT_CERT set without any client
//  trust bundle. bind() must fail with EINVAL instead of silently
//  rejecting every subsequent connection.
void test_mtls_require_without_trust_bundle_fails_bind ()
{
    void *sb = test_context_socket (ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sb, ZMQ_WSS_CERT_PEM, server_cert, strlen (server_cert)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sb, ZMQ_WSS_KEY_PEM, server_key, strlen (server_key)));
    int require = 1;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sb, ZMQ_WSS_REQUIRE_CLIENT_CERT,
                                               &require, sizeof (require)));
    //  Deliberately no ZMQ_WSS_CLIENT_TRUST_PEM / ZMQ_WSS_CLIENT_TRUST_SYSTEM.

    TEST_ASSERT_FAILURE_ERRNO (EINVAL, zmq_bind (sb, "wss://127.0.0.1:*/mtls"));

    test_context_socket_close_zero_linger (sb);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_mtls_exposes_peer_cert);
    RUN_TEST (test_mtls_rejects_unauthenticated_client);
    RUN_TEST (test_mtls_rejects_untrusted_client_cert);
    RUN_TEST (test_mtls_handles_long_san_entry);
    RUN_TEST (test_mtls_require_without_trust_bundle_fails_bind);
    return UNITY_END ();
}
#else
int main ()
{
    printf ("WSS mTLS unavailable, skipping test\n");
    return 77;
}
#endif
