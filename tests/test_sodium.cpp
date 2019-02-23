/*
    Copyright (c) 2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "testutil.hpp"
#include "testutil_unity.hpp"

void setUp ()
{
}

void tearDown ()
{
}

// There is no way to test for correctness because of the embedded RNG.
void test__zmq_curve_keypair__always__success (void)
{
    errno = 0;
    char public_key[41] = {0};
    char secret_key[41] = {0};

    const int rc = zmq_curve_keypair (public_key, secret_key);

#if defined(ZMQ_HAVE_CURVE)
    TEST_ASSERT_SUCCESS_ERRNO (rc);
#else
    TEST_ASSERT_FAILURE_ERRNO (ENOTSUP, rc);
#endif
}

void test__zmq_curve_public__valid__success ()
{
    // These are paired according to hintjens.com/blog:45
    static const char public_key[] = "Yne@$w-vo<fVvi]a<NY6T1ed:M$fCG*[IaLV{hID";
    static const char secret_key[] = "D:)Q[IlAW!ahhC2ac:9*A}h:p?([4%wOTJ%JR%cs";

    errno = 0;
    char out_public[41] = {0};

    const int rc = zmq_curve_public (out_public, secret_key);

#if defined(ZMQ_HAVE_CURVE)
    TEST_ASSERT_SUCCESS_ERRNO (rc);
    TEST_ASSERT_EQUAL_STRING (public_key, out_public);
#else
    TEST_ASSERT_FAILURE_ERRNO (ENOTSUP, rc);
    (void) public_key;
#endif
}

// The key length must be evenly divisible by 5 or must fail with EINVAL.
void test__zmq_curve_public__invalid__failure (const char *secret_)
{
    errno = 0;
    char out_public[41] = {0};

    const int rc = zmq_curve_public (out_public, secret_);

#if defined(ZMQ_HAVE_CURVE)
    TEST_ASSERT_FAILURE_ERRNO (EINVAL, rc);
    TEST_ASSERT_EQUAL_STRING ("", out_public);
#else
    TEST_ASSERT_FAILURE_ERRNO (ENOTSUP, rc);
#endif
}

void test__zmq_curve_public__invalid__failure_short ()
{
    test__zmq_curve_public__invalid__failure ("42");
}

void test__zmq_curve_public__invalid__failure_long ()
{
    test__zmq_curve_public__invalid__failure (
      "0123456789012345678901234567890123456789.");
}

int main ()
{
    UNITY_BEGIN ();
    RUN_TEST (test__zmq_curve_keypair__always__success);

    RUN_TEST (test__zmq_curve_public__valid__success);
    RUN_TEST (test__zmq_curve_public__invalid__failure_short);
    RUN_TEST (test__zmq_curve_public__invalid__failure_long);

    return UNITY_END ();
}
