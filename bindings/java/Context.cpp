/*
    Copyright (c) 2007-2010 iMatix Corporation

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

#include <assert.h>
#include <errno.h>

#include "../c/zmq.h"

#include "org_zmq_Context.h"

static void *fetch_socket (JNIEnv *env, jobject socket);

/** Handle to Java's Context::contextHandle. */
static jfieldID ctx_handle_fid = NULL;

/**
 * Make sure we have a valid pointer to Java's Context::contextHandle.
 */
static void ensure_context (JNIEnv *env, jobject obj)
{
    if (ctx_handle_fid == NULL) {
        jclass cls = env->GetObjectClass (obj);
        assert (cls);
        ctx_handle_fid = env->GetFieldID (cls, "contextHandle", "J");
        assert (ctx_handle_fid);
        env->DeleteLocalRef (cls);
    }
}

/**
 * Get the value of Java's Context::contextHandle.
 */
static void *get_context (JNIEnv *env, jobject obj)
{
    ensure_context (env, obj);
    void *s = (void*) env->GetLongField (obj, ctx_handle_fid);
    return s;
}

/**
 * Set the value of Java's Context::contextHandle.
 */
static void put_context (JNIEnv *env, jobject obj, void *s)
{
    ensure_context (env, obj);
    env->SetLongField (obj, ctx_handle_fid, (jlong) s);
}

/**
 * Raise an exception that includes 0MQ's error message.
 */
static void raise_exception (JNIEnv *env, int err)
{
    //  Get exception class.
    jclass exception_class = env->FindClass ("java/lang/Exception");
    assert (exception_class);

    //  Get text description of the exception.
    const char *err_msg = zmq_strerror (err);

    //  Raise the exception.
    int rc = env->ThrowNew (exception_class, err_msg);
    env->DeleteLocalRef (exception_class);

    assert (rc == 0);
}

/**
 * Called to construct a Java Context object.
 */
JNIEXPORT void JNICALL Java_org_zmq_Context_construct (JNIEnv *env,
    jobject obj, jint app_threads, jint io_threads, jint flags)
{
    void *c = get_context (env, obj);
    assert (!c);

    c = zmq_init (app_threads, io_threads, flags);
    put_context (env, obj, c);

    if (!c) {
        raise_exception (env, errno);
        return;
    }
}

/**
 * Called to destroy a Java Context object.
 */
JNIEXPORT void JNICALL Java_org_zmq_Context_finalize (JNIEnv *env,
    jobject obj)
{
    void *c = get_context (env, obj);
    assert (c);

    int rc = zmq_term (c);
    put_context (env, obj, NULL);
    assert (rc == 0);
}

JNIEXPORT jlong JNICALL Java_org_zmq_Context_poll (JNIEnv *env,
    jobject obj,
    jobjectArray socket_0mq,
    jshortArray event_0mq,
    jshortArray revent_0mq,
    jlong timeout)
{
    jsize ls_0mq = 0;
    jsize le_0mq = 0;
    jsize lr_0mq = 0;

    if (socket_0mq)
        ls_0mq = env->GetArrayLength (socket_0mq);
    if (event_0mq)
        le_0mq = env->GetArrayLength (event_0mq);
    if (revent_0mq)
        lr_0mq = env->GetArrayLength (revent_0mq);

    if (ls_0mq != le_0mq || ls_0mq != lr_0mq)
        return 0;

    jsize ls = ls_0mq;
    if (ls <= 0)
        return 0;

    zmq_pollitem_t *pitem = new zmq_pollitem_t [ls];
    short pc = 0;
    int rc = 0;

    //  Add 0MQ sockets.
    if (ls_0mq > 0) {
        jshort *e_0mq = env->GetShortArrayElements (event_0mq, 0);
        if (e_0mq != NULL) {
            for (int i = 0; i < ls_0mq; ++i) {
                jobject s_0mq = env->GetObjectArrayElement (socket_0mq, i);
                if (!s_0mq)
                    continue;
                void *s = fetch_socket (env, s_0mq);
                if (!s)
                    continue;
                pitem [pc].socket = s;
                pitem [pc].fd = 0;
                pitem [pc].events = e_0mq [i];
                pitem [pc].revents = 0;
                ++pc;
            }
            env->ReleaseShortArrayElements(event_0mq, e_0mq, 0);
        }
    }

    if (pc == ls) {
        pc = 0;
        long tout = (long) timeout;
        rc = zmq_poll (pitem, ls, tout);
        int err = 0;
        const char *msg = "";
        if (rc < 0) {
            err = errno;
            msg = zmq_strerror (err);
        }
    }

    //  Set 0MQ results.
    if (ls_0mq > 0) {
        jshort *r_0mq = env->GetShortArrayElements (revent_0mq, 0);
        if (r_0mq) {
            for (int i = 0; i < ls_0mq; ++i) {
                r_0mq [i] = pitem [pc].revents;
                ++pc;
            }
            env->ReleaseShortArrayElements(revent_0mq, r_0mq, 0);
        }
    }

    delete [] pitem;
    return rc;
}
  
/**
 * Get the value of socketHandle for the specified Java Socket.
 */
static void *fetch_socket (JNIEnv *env, jobject socket)
{
    static jmethodID get_socket_handle_mid = NULL;

    if (get_socket_handle_mid == NULL) {
        jclass cls = env->GetObjectClass (socket);
        assert (cls);
        get_socket_handle_mid = env->GetMethodID (cls,
            "getSocketHandle", "()J");
        env->DeleteLocalRef (cls);
        assert (get_socket_handle_mid);
    }
  
    void *s = (void*) env->CallLongMethod (socket, get_socket_handle_mid);
    if (env->ExceptionCheck ()) {
        s = NULL;
    }
  
    assert (s);
    return s;
}

