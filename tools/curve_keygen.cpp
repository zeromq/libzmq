/* SPDX-License-Identifier: MPL-2.0 */

#include <stdlib.h>
#include <assert.h>
#include <zmq.h>

int main (void)
{
    puts ("This tool generates a CurveZMQ keypair, as two printable strings "
          "you can");
    puts ("use in configuration files or source code. The encoding uses Z85, "
          "which");
    puts (
      "is a base-85 format that is described in 0MQ RFC 32, and which has an");
    puts ("implementation in the z85_codec.h source used by this tool. The "
          "keypair");
    puts (
      "always works with the secret key held by one party and the public key");
    puts ("distributed (securely!) to peers wishing to connect to it.");

    char public_key[41];
    char secret_key[41];
    if (zmq_curve_keypair (public_key, secret_key)) {
        if (zmq_errno () == ENOTSUP)
            puts ("To use curve_keygen, please install libsodium and then "
                  "rebuild libzmq.");
        exit (1);
    }

    puts ("\n== CURVE PUBLIC KEY ==");
    puts (public_key);

    puts ("\n== CURVE SECRET KEY ==");
    puts (secret_key);

    exit (0);
}
