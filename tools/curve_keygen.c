/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    This tool generates a keypair for the libzmq CURVE security mechanism, 
    and encodes the keypair to give two printable strings that you can use 
    in configuration files or source code. The encoding uses Z85, which is 
    a base-85 format that is described in 0MQ RFC 32, and which has an 
    implementation in the Z85.c source used by this tool. The keypair 
    always works with the secret key held by one party and the public key 
    distributed (securely!) to peers wishing to connect to it. CURVE is 
    defined by http://rfc.zeromq.org/spec:25. Z85 is defined by 
    http://rfc.zeromq.org/spec:32.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sodium.h>
#include "z85_codec.h"

int main (void)
{
#   if crypto_box_PUBLICKEYBYTES != 32 \
    || crypto_box_SECRETKEYBYTES != 32
#   error "libsodium not built correctly"
#   endif
    
    puts ("This tool generates a keypair for the libzmq CURVE security mechanism,");
    puts ("and encodes the keypair to give two printable strings that you can use");
    puts ("in configuration files or source code. The encoding uses Z85, which is");
    puts ("a base-85 format that is described in 0MQ RFC 32, and which has an");
    puts ("implementation in the Z85.c source used by this tool. The keypair");
    puts ("always works with the secret key held by one party and the public key");
    puts ("distributed (securely!) to peers wishing to connect to it. CURVE is");
    puts ("defined by http://rfc.zeromq.org/spec:25. Z85 is defined by");
    puts ("http://rfc.zeromq.org/spec:32.");

    uint8_t public_key [32];
    uint8_t secret_key [32];

    int rc = crypto_box_keypair (public_key, secret_key);
    assert (rc == 0);
    
    char encoded [40];
    Z85_encode (encoded, public_key, 32);
    puts ("\n== CURVE PUBLIC KEY ==");
    puts (encoded);
    
    Z85_encode (encoded, secret_key, 32);
    puts ("\n== CURVE SECRET KEY ==");
    puts (encoded);

    exit (0);
}
