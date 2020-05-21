/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

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

void test_capabilities ()
{
#if defined(ZMQ_HAVE_IPC)
    TEST_ASSERT_TRUE (zmq_has ("ipc"));
#else
    TEST_ASSERT_TRUE (!zmq_has ("ipc"));
#endif

#if defined(ZMQ_HAVE_OPENPGM)
    TEST_ASSERT_TRUE (zmq_has ("pgm"));
#else
    TEST_ASSERT_TRUE (!zmq_has ("pgm"));
#endif

#if defined(ZMQ_HAVE_TIPC)
    TEST_ASSERT_TRUE (zmq_has ("tipc"));
#else
    TEST_ASSERT_TRUE (!zmq_has ("tipc"));
#endif

#if defined(ZMQ_HAVE_NORM)
    TEST_ASSERT_TRUE (zmq_has ("norm"));
#else
    TEST_ASSERT_TRUE (!zmq_has ("norm"));
#endif

#if defined(ZMQ_HAVE_CURVE)
    TEST_ASSERT_TRUE (zmq_has ("curve"));
#else
    TEST_ASSERT_TRUE (!zmq_has ("curve"));
#endif

#if defined(HAVE_LIBGSSAPI_KRB5)
    TEST_ASSERT_TRUE (zmq_has ("gssapi"));
#else
    TEST_ASSERT_TRUE (!zmq_has ("gssapi"));
#endif

#if defined(ZMQ_HAVE_VMCI)
    TEST_ASSERT_TRUE (zmq_has ("vmci"));
#else
    TEST_ASSERT_TRUE (!zmq_has ("vmci"));
#endif

#if defined(ZMQ_BUILD_DRAFT_API)
    TEST_ASSERT_TRUE (zmq_has ("draft"));
#else
    TEST_ASSERT_TRUE (!zmq_has ("draft"));
#endif
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_capabilities);
    return UNITY_END ();
}
