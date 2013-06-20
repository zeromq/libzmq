/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

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

int main (void)
{
#   if crypto_box_PUBLICKEYBYTES != 32 \
    || crypto_box_SECRETKEYBYTES != 32
#   error "libsodium not built correctly"
#   endif

    uint8_t public_key [32];
    uint8_t secret_key [32];

    int rc = crypto_box_keypair (public_key, secret_key);
    assert (rc == 0);
    int byte_nbr;
    printf ("public: ");
    for (byte_nbr = 0; byte_nbr < 32; byte_nbr++) 
        printf ("%02X", public_key [byte_nbr]);
    printf ("\n");
    printf ("secret: ");
    for (byte_nbr = 0; byte_nbr < 32; byte_nbr++) 
        printf ("%02X", secret_key [byte_nbr]);
    printf ("\n");
    exit (0);
}
