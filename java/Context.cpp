/*
    Copyright (c) 2007-2009 FastMQ Inc.

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "zmq.h"
#include "org_zmq_Context.h"

static jfieldID ctx_handle_fid = NULL;

static void
raise_exception (JNIEnv *env, int err)
{
    //  Get exception class.
    jclass exception_class = env->FindClass ("java/lang/Exception");
    assert (exception_class);

    //  Get text description of the exception.
    const char *err_msg = strerror (err);

    //  Raise the exception.
    int rc = env->ThrowNew (exception_class, err_msg);
    assert (rc == 0);

    //  Free the local ref.
    env->DeleteLocalRef (exception_class);
}

JNIEXPORT void JNICALL
Java_org_zmq_Context_construct (JNIEnv *env, jobject obj,
                                jint app_threads, jint io_threads)
{
    if (ctx_handle_fid == NULL) {
        jclass cls = env->GetObjectClass (obj);
        assert (cls);
        ctx_handle_fid = env->GetFieldID (cls, "contextHandle", "J");
        assert (ctx_handle_fid);
        env->DeleteLocalRef (cls);
    }

    void *ctx = zmq_init (app_threads, io_threads);
    if (ctx == NULL) {
        raise_exception (env, errno);
        return;
    }

    env->SetLongField (obj, ctx_handle_fid, (jlong) ctx);
}

JNIEXPORT void JNICALL
Java_org_zmq_Context_finalize (JNIEnv *env, jobject obj)
{
    void *ctx = (void*) env->GetLongField (obj, ctx_handle_fid);
    assert (ctx);

    int rc = zmq_term (ctx);
    assert (rc == 0);
}

JNIEXPORT jlong JNICALL
Java_org_zmq_Context_createSocket (JNIEnv *env, jobject obj, jint type)
{
    void *ctx = (void*) env->GetLongField (obj, ctx_handle_fid);
    assert (ctx);

    void *s = zmq_socket (ctx, type);
    if (s == NULL) {
        raise_exception (env, errno);
        return -1;
    }

    return (jlong) s;
}
