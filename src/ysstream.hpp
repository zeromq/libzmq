/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ysstream.h
 * Author: chengye.ke
 *
 * Created on 2017年7月31日, 下午3:09
 */

#ifndef YSSTREAM_H
#define YSSTREAM_H
#include "../include/zmq.h"
#include "stream.hpp"
namespace zmq {

    // 与总线通讯的协议包头

    struct NtPkgHead {
        unsigned char bStartFlag; // 协议包起始标志 0xFF
        unsigned char bVer; // 版本号
        unsigned char bEncryptFlag; // 加密标志(如果不加密,则为0)
        unsigned char bFrag; // 是否有包分片(1:有包分片 0:无包分片)
        unsigned short wLen; // 总包长 (网络字节序)
        unsigned short wCmd; // 命令号 (网络字节序)
        unsigned short wSeq; // 包的序列号,业务使用
        unsigned short wCrc; // Crc16校验码
        unsigned int dwSID; // 会话ID
        unsigned short wTotal; // 有包分片时，分片总数
        unsigned short wCurSeq; // 有包分片时，分片序号
    } __attribute__ ((packed));

    #define RMQ_MAX_PACKET_SIZE (8000)

    class ysstream_t : public zmq::stream_t {
    public:
        ysstream_t(zmq::ctx_t *parent_, uint32_t tid_, int sid);

        virtual int xsend(zmq::msg_t *msg_);

        virtual int xrecv(zmq::msg_t* msg_);

        virtual ~ysstream_t();
    private:
        int prepare_package(msg_t& msg_, unsigned short cmd_, void* msg_body, size_t body_size);

        msg_t prefetched_body_msg;

        bool cmd_msg_sent;

        msg_t msg_to_send;
        
        uint16_t cmd_;
    };

    class ysstream_session_t : public session_base_t {
    public:

        ysstream_session_t(zmq::io_thread_t *io_thread_, bool connect_,
                zmq::socket_base_t *socket_, const options_t &options_,
                address_t *addr_);
        ~ysstream_session_t();

        //  Overrides of the functions from session_base_t.
        int push_msg(msg_t *msg_);
        //int pull_msg (msg_t *msg_);
        //void reset ();

        //int pull_msg(msg_t* msg_);

    private:
        int left;
        int last_left;
        char* buffer;
        char* pos;

        ysstream_session_t(const ysstream_session_t&);
        const ysstream_session_t &operator=(const ysstream_session_t&);
    };
}
#endif /* YSSTREAM_H */

