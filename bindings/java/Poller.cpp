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

#include "org_zmq_Poller.h"

static void *fetch_socket (JNIEnv *env, jobject socket);

JNIEXPORT jlong JNICALL Java_org_zmq_Poller_run_1poll (JNIEnv *env,
                                                       jobject obj,
                                                       jint count,
                                                       jobjectArray socket_0mq,
                                                       jshortArray event_0mq,
                                                       jshortArray revent_0mq,
                                                       jlong timeout)
{
    int ls = (int) count;
    if (ls <= 0)
        return 0;
    
    int ls_0mq = 0;
    int le_0mq = 0;
    int lr_0mq = 0;

    if (socket_0mq)
        ls_0mq = env->GetArrayLength (socket_0mq);
    if (event_0mq)
        le_0mq = env->GetArrayLength (event_0mq);
    if (revent_0mq)
        lr_0mq = env->GetArrayLength (revent_0mq);

    if (ls > ls_0mq || ls > le_0mq || ls > ls_0mq)
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
 * TODO: move this to a single util.h file.
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
