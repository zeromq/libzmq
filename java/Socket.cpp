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
#include "org_zmq_Socket.h"

static jfieldID socket_handle_fid = NULL;
static jclass msg_class = NULL;
static jmethodID msg_constructor;
static jmethodID get_msg_handle_mid = NULL;
static jmethodID create_socket_mid = NULL;

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
Java_org_zmq_Socket_construct (JNIEnv *env, jobject obj, jobject context,
                               jint type)
{
    if (socket_handle_fid == NULL) {
        jclass cls = env->GetObjectClass (obj);
        assert (cls);
        socket_handle_fid = env->GetFieldID (cls, "socketHandle", "J");
        assert (socket_handle_fid);
        env->DeleteLocalRef (cls);
    }

    if (create_socket_mid == NULL) {
        jclass cls = env->FindClass ("org/zmq/Context");
        assert (cls);
        create_socket_mid = env->GetMethodID (cls, "createSocket", "(I)J");
        assert (create_socket_mid);
        env->DeleteLocalRef (cls);
    }

    if (msg_class == NULL) {
        jclass cls = env->FindClass ("org/zmq/Message");
        assert (cls);

        msg_constructor = env->GetMethodID (cls, "<init>", "()V");
        assert (msg_constructor);

        get_msg_handle_mid = env->GetMethodID (cls, "getMsgHandle", "()J");
        assert (get_msg_handle_mid);

        msg_class = (jclass) env->NewGlobalRef (cls);
        assert (msg_class);
        env->DeleteLocalRef (cls);
    }

    void *s = (void *) env->CallLongMethod (context, create_socket_mid, type);
    if (env->ExceptionCheck ())
        return;

    env->SetLongField (obj, socket_handle_fid, (jlong) s);
}

JNIEXPORT void JNICALL
Java_org_zmq_Socket_finalize (JNIEnv *env, jobject obj)
{
    void *s = (void*) env->GetLongField (obj, socket_handle_fid);
    assert (s);
    int rc = zmq_close (s);
    assert (rc == 0);
}

JNIEXPORT void JNICALL
Java_org_zmq_Socket_setHwm (JNIEnv *env, jobject obj, jlong hwm)
{
    void *s = (void*) env->GetLongField (obj, socket_handle_fid);
    assert (s);
    int rc = zmq_setsockopt (s, ZMQ_HWM, &hwm, sizeof hwm);
    if (rc == -1)
        raise_exception (env, errno);
}

JNIEXPORT void JNICALL
Java_org_zmq_Socket_setLwm (JNIEnv *env, jobject obj, jlong lwm)
{
    void *s = (void*) env->GetLongField (obj, socket_handle_fid);
    assert (s);

    int rc = zmq_setsockopt (s, ZMQ_LWM, &lwm, sizeof lwm);
    if (rc == -1)
        raise_exception (env, errno);
}

JNIEXPORT void JNICALL
Java_org_zmq_Socket_setSwap (JNIEnv *env, jobject obj, jlong swap_size)
{
    void *s = (void*) env->GetLongField (obj, socket_handle_fid);
    assert (s);

    int rc = zmq_setsockopt (s, ZMQ_SWAP, &swap_size, sizeof swap_size);
    if (rc == -1)
        raise_exception (env, errno);
}

JNIEXPORT void JNICALL
Java_org_zmq_Socket_setMask (JNIEnv *env, jobject obj, jlong mask)
{
    void *s = (void*) env->GetLongField (obj, socket_handle_fid);
    assert (s);

    int rc = zmq_setsockopt (s, ZMQ_MASK, &mask, sizeof mask);
    if (rc == -1)
        raise_exception (env, errno);
}

JNIEXPORT void JNICALL
Java_org_zmq_Socket_setAffinity (JNIEnv *env, jobject obj, jlong affinity)
{
    void *s = (void*) env->GetLongField (obj, socket_handle_fid);
    assert (s);

    int rc = zmq_setsockopt (s, ZMQ_AFFINITY, &affinity, sizeof affinity);
    if (rc == -1)
        raise_exception (env, errno);
}

JNIEXPORT void JNICALL
Java_org_zmq_Socket_setIdentity (JNIEnv *env, jobject obj, jstring identity)
{
    void *s = (void*) env->GetLongField (obj, socket_handle_fid);
    assert (s);

    if (identity == NULL) {
        raise_exception (env, EINVAL);
        return;
    }

    const char *c_identity = env->GetStringUTFChars (identity, NULL);
    if (c_identity == NULL)
        return;

    int rc = zmq_setsockopt (s, ZMQ_IDENTITY, c_identity, sizeof c_identity);
    env->ReleaseStringUTFChars (identity, c_identity);

    if (rc == -1)
        raise_exception (env, errno);
}

JNIEXPORT void JNICALL
Java_org_zmq_Socket_bind (JNIEnv *env, jobject obj, jstring addr)
{
    void *s = (void*) env->GetLongField (obj, socket_handle_fid);
    assert (s);

    if (addr == NULL) {
        raise_exception (env, EINVAL);
        return;
    }

    const char *c_addr = env->GetStringUTFChars (addr, NULL);
    if (c_addr == NULL)
        return;

    int rc = zmq_bind (s, c_addr);
    env->ReleaseStringUTFChars (addr, c_addr);

    if (rc == -1)
        raise_exception (env, errno);
}

JNIEXPORT void JNICALL
Java_org_zmq_Socket_connect (JNIEnv *env, jobject obj, jstring addr)
{
    void *s = (void*) env->GetLongField (obj, socket_handle_fid);
    assert (s);

    if (addr == NULL) {
        raise_exception (env, EINVAL);
        return;
    }

    const char *c_addr = env->GetStringUTFChars (addr, NULL);
    if (c_addr == NULL)
        return;

    int rc = zmq_connect (s, c_addr);
    env->ReleaseStringUTFChars (addr, c_addr);

    if (rc == -1)
        raise_exception (env, errno);
}

JNIEXPORT jint JNICALL
Java_org_zmq_Socket_send (JNIEnv *env, jobject obj, jobject msg, jlong flags)
{
    void *s = (void*) env->GetLongField (obj, socket_handle_fid);
    assert (s);

    zmq_msg_t *zmq_msg = (zmq_msg_t *)
        env->CallLongMethod (msg, get_msg_handle_mid);

    if (env->ExceptionCheck ())
        return -1;

    int rc = zmq_send (s, zmq_msg, (int) flags);
    if (rc == -1) {
        raise_exception (env, errno);
        return -1;
    }

    return rc;
}

JNIEXPORT void JNICALL
Java_org_zmq_Socket_flush (JNIEnv *env, jobject obj)
{
    void *s = (void*) env->GetLongField (obj, socket_handle_fid);
    assert (s);

    zmq_flush (s);
}

JNIEXPORT jobject JNICALL
Java_org_zmq_Socket_recv (JNIEnv *env, jobject obj, jlong flags)
{
    void *s = (void*) env->GetLongField (obj, socket_handle_fid);
    assert (s);

    jobject msg = env->NewObject (msg_class, msg_constructor);
    if (msg == NULL)
        return NULL;

    zmq_msg_t *zmq_msg = (zmq_msg_t*)
        env->CallLongMethod (msg, get_msg_handle_mid);

    if (env->ExceptionCheck ())
        return NULL;

    int rc = zmq_recv (s, zmq_msg, (int) flags);
    if (rc == -1) {
        raise_exception (env, errno);
        return NULL;
    }

    return msg;
}
