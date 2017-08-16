/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ysstream.cpp
 * Author: chengye.ke
 * 
 * Created on 2017年7月31日, 下午3:09
 */



#include <iostream>
#include <string>

#include "precompiled.hpp"
#include "macros.hpp"
#include "ysstream.hpp"
//#include "stream.hpp"
#include "pipe.hpp"
#include "wire.hpp"
#include "random.hpp"
#include "likely.hpp"
#include "err.hpp"
using namespace std;

zmq::ysstream_t::ysstream_t(zmq::ctx_t *parent_, uint32_t tid_, int sid)
: zmq::stream_t(parent_, tid_, sid)
, cmd_msg_sent(false)
, cmd_(0)
, send_all(false) {
    options.type = ZMQ_YSSTREAM;
    prefetched_body_msg.init();
    msg_to_send.init();
}

int zmq::ysstream_t::prepare_package(msg_t& srcmsg_
        , unsigned short cmd_, void* msg_body, size_t body_size, bool send_all) {

    if(send_all && outpipes.empty())
        return 0;
    
    unsigned int nPackCount = 0;
    if (0 == body_size % RMQ_MAX_PACKET_SIZE) {
        nPackCount = body_size / RMQ_MAX_PACKET_SIZE;
    } else {
        nPackCount = (body_size / RMQ_MAX_PACKET_SIZE) + 1;
    }

    NtPkgHead mHead;
    memset((void *) &mHead, 0, sizeof (NtPkgHead));
    mHead.bStartFlag = 0xFF;
    mHead.bEncryptFlag = '0';
    mHead.bVer = '0';
    mHead.dwSID = htonl(0);
    mHead.wCmd = htons(cmd_);
    mHead.wSeq = htons(0);

    if (1 < nPackCount) {
        mHead.bFrag = 1;
    }
    mHead.wTotal = htons(nPackCount);

    int nIndexCount = 0;
    for (size_t nIndex = 0; nIndex < body_size;) {
        msg_t msg_;
        msg_.init_size(sizeof (NtPkgHead) + body_size);
        msg_.set_flags(srcmsg_.flags());
        unsigned int uiBufLen = body_size - nIndex;
        if (uiBufLen > RMQ_MAX_PACKET_SIZE)
            uiBufLen = RMQ_MAX_PACKET_SIZE;

        mHead.wLen = htons(sizeof (NtPkgHead) + uiBufLen);
        mHead.wCurSeq = htons(nIndexCount);
        nIndexCount++;

        std::string strRequest;
        strRequest.append((const char *) &mHead, sizeof (NtPkgHead));
        strRequest.append((char*) msg_body + nIndex, uiBufLen);
        memcpy(msg_.data(), strRequest.c_str(), strRequest.size());
        //msg_.init((void*)strRequest.c_str(),strRequest.size(),NULL,NULL);

        if(!send_all) {
            zmq_assert(current_out);
            bool ok = current_out->write(&msg_);
            if (likely(ok))
                current_out->flush();
        } else {
            for(outpipes_t::iterator it = outpipes.begin(); it != outpipes.end(); it++) {
                bool ok = it->second.pipe->write(&msg_);
                if (likely(ok))
                    it->second.pipe->flush();
            }
        }
        
        

        //注意这条msg不能close,否刚导致对端PIPE获取不到数据
        //msg_.close();
        nIndex += uiBufLen;
    }
    return 0;

}

int zmq::ysstream_t::xsend(zmq::msg_t* msg_) {
    //  If this is the first part of the message it's the ID of the
    //  peer to send the message to.
    if (!more_out) {
        zmq_assert(!current_out);

        //  If we have malformed message (prefix with no subsequent message)
        //  then just silently ignore it.
        //  TODO: The connections should be killed instead.
        if (msg_->flags() & msg_t::more) {

            //  Find the pipe associated with the identity stored in the prefix.
            //  If there's no such pipe return an error
            if(msg_->size() == 0) {
                send_all = true;
                
            } else {
                blob_t identity((unsigned char*) msg_->data(), msg_->size());
                outpipes_t::iterator it = outpipes.find(identity);

                if (it != outpipes.end()) {
                    current_out = it->second.pipe;
                    if (!current_out->check_write()) {
                        it->second.active = false;
                        current_out = NULL;
                        errno = EAGAIN;
                        return -1;
                    }
                } else {
                    errno = EHOSTUNREACH;
                    return -1;
                }
            }
        }

        //  Expect one more message frame.
        more_out = true;

        int rc = msg_->close();
        errno_assert(rc == 0);
        rc = msg_->init();
        errno_assert(rc == 0);
        return 0;
    }

    //  Ignore the MORE flag
    //msg_->reset_flags(msg_t::more);
    if (msg_->flags() & msg_t::more) {
        cmd_ = *(uint16_t*) msg_->data();
        int rc = msg_->close();
        errno_assert(rc == 0);
        rc = msg_->init();
        errno_assert(rc == 0);
        return 0;
    }




    //  This is the last part of the message.
    more_out = false;

    //  Push the message into the pipe. If there's no out pipe, just drop it.
    if (current_out) {

        // Close the remote connection if user has asked to do so
        // by sending zero length message.
        // Pending messages in the pipe will be dropped (on receiving term- ack)
        if (msg_->size() == 0) {
            current_out->terminate(false);
            int rc = msg_->close();
            errno_assert(rc == 0);
            rc = msg_->init();
            errno_assert(rc == 0);
            current_out = NULL;
            return 0;
        }

        prepare_package(*msg_, cmd_, msg_->data(), msg_->size(), false);

        int rc = msg_->close();
        errno_assert(rc == 0);
        
        current_out = NULL;
    } else if(send_all) {
        
        // Close the remote connection if user has asked to do so
        // by sending zero length message.
        // Pending messages in the pipe will be dropped (on receiving term- ack)
        if (msg_->size() == 0) {
            for(outpipes_t::iterator it = outpipes.begin(); it != outpipes.end(); it++) {
                it->second.pipe->terminate(false);
            }
            int rc = msg_->close();
            errno_assert(rc == 0);
            rc = msg_->init();
            errno_assert(rc == 0);
            send_all = false;
            return 0;
        }
        prepare_package(*msg_, cmd_, msg_->data(), msg_->size(), send_all);

        int rc = msg_->close();
        errno_assert(rc == 0);
        send_all = false;
        
    } else {
        int rc = msg_->close();
        errno_assert(rc == 0);
    }

    //  Detach the message from the data buffer.
    int rc = msg_->init();
    errno_assert(rc == 0);

    return 0;
}

int zmq::ysstream_t::xrecv(zmq::msg_t* msg_) {
    if (prefetched) {
        if (!identity_sent) {
            int rc = msg_->move(prefetched_id);
            errno_assert(rc == 0);
            identity_sent = true;
        } else
            if (!cmd_msg_sent) {
            int rc = msg_->move(prefetched_msg);
            errno_assert(rc == 0);
            cmd_msg_sent = true;
        } else {
            int rc = msg_->move(prefetched_body_msg);
            errno_assert(rc == 0);
            prefetched = false;
            cmd_msg_sent = false;
        }
        return 0;
    }

    pipe_t *pipe = NULL;
    int rc = fq.recvpipe(&prefetched_msg, &pipe);
    if (rc != 0)
        return -1;

    rc = fq.recvpipe(&prefetched_body_msg, &pipe);
    if (rc != 0)
        return -1;

    zmq_assert(pipe != NULL);
    zmq_assert((prefetched_msg.flags() & msg_t::more) != 0);

    //  We have received a frame with TCP data.
    //  Rather than sending this frame, we keep it in prefetched
    //  buffer and send a frame with peer's ID.
    blob_t identity = pipe->get_identity();
    rc = msg_->close();
    errno_assert(rc == 0);
    rc = msg_->init_size(identity.size());
    errno_assert(rc == 0);

    // forward metadata (if any)
    metadata_t *metadata = prefetched_msg.metadata();
    if (metadata)
        msg_->set_metadata(metadata);

    memcpy(msg_->data(), identity.data(), identity.size());
    msg_->set_flags(msg_t::more);

    prefetched = true;
    identity_sent = true;

    return 0;
}

bool zmq::ysstream_t::xhas_in() {
    //  We may already have a message pre-fetched.
    if (prefetched)
        return true;

    //  Try to read the next message.
    //  The message, if read, is kept in the pre-fetch buffer.
    pipe_t *pipe = NULL;
    int rc = fq.recvpipe (&prefetched_msg, &pipe);
    if (rc != 0)
        return false;
    rc = fq.recvpipe(&prefetched_body_msg, &pipe);
    if (rc != 0)
        return false;

    zmq_assert (pipe != NULL);
    zmq_assert ((prefetched_msg.flags () & msg_t::more) != 0);
    zmq_assert ((prefetched_body_msg.flags () & msg_t::more) == 0);

    blob_t identity = pipe->get_identity ();
    rc = prefetched_id.init_size (identity.size ());
    errno_assert (rc == 0);

    // forward metadata (if any)
    metadata_t *metadata = prefetched_msg.metadata();
    if (metadata)
        prefetched_id.set_metadata(metadata);

    memcpy (prefetched_id.data (), identity.data (), identity.size ());
    prefetched_id.set_flags (msg_t::more);

    prefetched = true;
    identity_sent = false;

    return true;
}

zmq::ysstream_t::~ysstream_t() {
}

zmq::ysstream_session_t::ysstream_session_t(zmq::io_thread_t* io_thread_, bool connect_, zmq::socket_base_t* socket_, const options_t& options_, address_t* addr_)
: session_base_t(io_thread_, connect_, socket_, options_, addr_) {
    left = 0;
    last_left = 0;
    buffer = new char[8192 * 8];
    pos = buffer;
}

zmq::ysstream_session_t::~ysstream_session_t() {

}

int zmq::ysstream_session_t::push_msg(msg_t* msg_) {
    //todo
    int ret = 0;
    size_t size = msg_->size();
    int body_size = 0;
    if (size == 0) {
        msg_t msg_1;
            msg_1.init_size(sizeof (unsigned short));
            unsigned short cmd = 0;
            msg_1.set_flags(msg_t::more);
            memcpy(msg_1.data(), &cmd, sizeof (unsigned short));
            ret = session_base_t::push_msg(&msg_1);
            //msg_1.close();
            if (ret == 0) {
                session_base_t::push_msg(msg_);
            }
        msg_->close();
        return 0;
    }

    memcpy(buffer + last_left, msg_->data(), msg_->size());
    char* tail = buffer + last_left + msg_->size();
    while (pos < tail) {
        //assert(*pos == 0xff);
        //if (pos == tail) {
            //int i = 0;
        //}

        if (tail - pos < (int)sizeof (NtPkgHead)) {
            break;
        }
        NtPkgHead* phead = (NtPkgHead*) pos;
        body_size = ntohs(phead->wLen);
        //unsigned char c = phead->bStartFlag;
        //if (c != 255) {
            //int i = 0;
        //}

        if (pos + body_size > tail)
            break;
        else {
            msg_t msg_1;
            msg_1.init_size(sizeof (phead->wCmd));
            // forward metadata (if any)
            metadata_t *metadata = msg_->metadata();
            if (metadata)
                msg_1.set_metadata(metadata);

            unsigned short cmd = ntohs(phead->wCmd);
            msg_1.set_flags(msg_t::more);
            memcpy(msg_1.data(), &cmd, sizeof (unsigned short));
            ret = session_base_t::push_msg(&msg_1);
            if (ret == -1) {
                msg_1.close();
                break;
            }

            msg_t msg_2;
            msg_2.init_size(body_size - sizeof (NtPkgHead));
            if (metadata)
                msg_2.set_metadata(metadata);
            msg_2.set_flags(msg_->flags());

            memcpy(msg_2.data(), pos + sizeof (NtPkgHead), body_size - sizeof (NtPkgHead));
            
            if ((unsigned char) *pos == 255)
                ret = session_base_t::push_msg(&msg_2);
            else {
                printf("s");
            }
            //msg_2.close();
            if (ret == -1) {
                break;
            }
            pos += body_size;
        }

    }
    left = tail - pos;
    assert(left >= 0);
    if (ret == -1) {
        //left = last_left;
        pipe_rollback();
    } else {
        memmove((void*) buffer, (void*) pos, left);
        pos = buffer;
        last_left = left;
        msg_->close();
    }
    return ret;
}

