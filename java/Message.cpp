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
#include "org_zmq_Message.h"

static jfieldID msg_handle_fid = NULL;

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
Java_org_zmq_Message_construct (JNIEnv *env, jobject obj)
{
    if (msg_handle_fid == NULL) {
        jclass cls = env->GetObjectClass (obj);
        assert (cls != NULL);
        msg_handle_fid = env->GetFieldID (cls, "msgHandle", "J");
        assert (msg_handle_fid != NULL);
        env->DeleteLocalRef (cls);
    }

    zmq_msg_t *msg = (zmq_msg_t*) malloc (sizeof (zmq_msg_t));
    if (msg == NULL) {
        raise_exception (env, ENOMEM);
        return;
    }

    int rc = zmq_msg_init (msg);
    assert (rc == 0);
    env->SetLongField (obj, msg_handle_fid, (jlong) msg);
}

JNIEXPORT void JNICALL
Java_org_zmq_Message_constructWithData (JNIEnv *env, jobject obj,
                                        jbyteArray payload)
{
    if (msg_handle_fid == NULL) {
        jclass cls = env->GetObjectClass (obj);
        assert (cls != NULL);
        msg_handle_fid = env->GetFieldID (cls, "msgHandle", "J");
        assert (msg_handle_fid != NULL);
        env->DeleteLocalRef (cls);
    }

    zmq_msg_t *msg = (zmq_msg_t*) malloc (sizeof (zmq_msg_t));
    if (msg == NULL) {
        raise_exception (env, ENOMEM);
        return;
    }

    jsize array_size = env->GetArrayLength (payload);
    jbyte *array_data = env->GetByteArrayElements (payload, NULL);

    int rc = zmq_msg_init_size (msg, array_size);
    assert (rc == 0);

    memcpy (zmq_msg_data (msg), array_data, array_size);
    env->ReleaseByteArrayElements (payload, array_data, JNI_ABORT);

    env->SetLongField (obj, msg_handle_fid, (jlong) msg);
}

JNIEXPORT void JNICALL
Java_org_zmq_Message_finalize (JNIEnv *env, jobject obj)
{
    zmq_msg_t *msg = (zmq_msg_t*) env->GetLongField (obj, msg_handle_fid);
    assert (msg);

    int rc = zmq_msg_close (msg);
    assert (rc == 0);

    free (msg);
}

JNIEXPORT jbyteArray JNICALL
Java_org_zmq_Message_getMsgPayload (JNIEnv *env, jobject obj)
{
    zmq_msg_t *msg = (zmq_msg_t*) env->GetLongField (obj, msg_handle_fid);
    assert (msg);

    jsize msg_size = zmq_msg_size (msg);
    jbyte *msg_data = (jbyte*) zmq_msg_data (msg);

    jbyteArray payload = env->NewByteArray (msg_size);
    if (payload == NULL)
        return NULL;

    env->SetByteArrayRegion (payload, 0, msg_size, msg_data);
    assert (!env->ExceptionCheck ());

    return payload;
}

JNIEXPORT jint JNICALL
Java_org_zmq_Message_getMsgType (JNIEnv *env, jobject obj)
{
    zmq_msg_t *msg = (zmq_msg_t*) env->GetLongField (obj, msg_handle_fid);
    assert (msg);

    return (jint) zmq_msg_type (msg);
}
