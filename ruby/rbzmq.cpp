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

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <ruby.h>

#include "../c/zmq.h"

static void context_free (void *ctx)
{
    if (ctx) {
       int rc = zmq_term (ctx);
       assert (rc == 0);
    }
}

static VALUE context_alloc (VALUE class_)
{
    return rb_data_object_alloc (class_, NULL, 0, context_free);
}

static VALUE context_initialize (VALUE self_, VALUE app_threads_,
    VALUE io_threads_)
{
    assert (!DATA_PTR (self_));
    void *ctx = zmq_init (NUM2INT (app_threads_), NUM2INT (io_threads_));
    if (!ctx) {
        rb_raise (rb_eRuntimeError, strerror (errno));
        return Qnil;
    }

    DATA_PTR (self_) = (void*) ctx;
    return self_;
}

static void socket_free (void *s)
{
    if (s) {
       int rc = zmq_close (s);
       assert (rc == 0);
    }
}

static VALUE socket_alloc (VALUE class_)
{
    return rb_data_object_alloc (class_, NULL, 0, socket_free);
}

static VALUE socket_initialize (VALUE self_, VALUE context_, VALUE type_)
{
    assert (!DATA_PTR (self_));

    if (strcmp (rb_obj_classname (context_), "Context") != 0) {
        rb_raise (rb_eArgError, "expected Context object");
        return Qnil;
    }

    void *s = zmq_socket (DATA_PTR (context_), NUM2INT (type_));
    if (!s) {
        rb_raise (rb_eRuntimeError, strerror (errno));
        return Qnil;
    }

    DATA_PTR (self_) = (void*) s;
    return self_;
}

/*
static VALUE rb_setsockopt (VALUE self_, VALUE socket_, VALUE option_,
    VALUE optval_)
{
	//  Get the socket.
    void* socket;
    Data_Get_Struct (socket_, void*, socket);
    
    int rc = 0;

	if (TYPE (optval_) == T_STRING) {

		//  Forward the code to native 0MQ library.
		rc = zmq_setsockopt (socket, NUM2INT (option_), 
			(void *) StringValueCStr (optval_), RSTRING_LEN (optval_));	
	
	}
	else if (TYPE (optval_) == T_FLOAT) {

		double optval = NUM2DBL (optval_);
		
		//  Forward the code to native 0MQ library.
		rc = zmq_setsockopt (socket, NUM2INT (option_), 
			(void*) &optval, 8);	
	}
	
	else if (TYPE (optval_) == T_FIXNUM) {

		long optval = FIX2LONG (optval_);
		
		//  Forward the code to native 0MQ library.
		rc = zmq_setsockopt (socket, NUM2INT (option_), 
			(void *) &optval, 4);	
	
	}
	
	else if (TYPE (optval_) == T_BIGNUM) {

		long optval = NUM2LONG (optval_);
		
		//  Forward the code to native 0MQ library.
		rc = zmq_setsockopt (socket, NUM2INT (option_), 
			(void *) &optval, 4);	
	
	}
	else if (TYPE (optval_) == T_ARRAY) {

		//  Forward the code to native 0MQ library.
		rc = zmq_setsockopt (socket, NUM2INT (option_), 
			(void *) RARRAY_PTR (optval_), RARRAY_LEN (optval_));	
	
	}
	
	else if (TYPE (optval_) == T_STRUCT) {

		//  Forward the code to native 0MQ library.
		rc = zmq_setsockopt (socket, NUM2INT (option_), 
			(void *) RSTRUCT_PTR (optval_), RSTRUCT_LEN (optval_));	
	
	}
	else 
		rb_raise(rb_eRuntimeError, "Unknown type");    			
    
    assert (rc == 0);
    
    return self_;
}
*/

static VALUE socket_bind (VALUE self_, VALUE addr_)
{
    assert (DATA_PTR (self_));

    int rc = zmq_bind (DATA_PTR (self_), rb_string_value_cstr (&addr_));
    if (rc != 0) {
        rb_raise (rb_eRuntimeError, strerror (errno));
        return Qnil;
    }

    return Qnil;
}

static VALUE socket_connect (VALUE self_, VALUE addr_)
{
    assert (DATA_PTR (self_));

    int rc = zmq_connect (DATA_PTR (self_), rb_string_value_cstr (&addr_));
    if (rc != 0) {
        rb_raise (rb_eRuntimeError, strerror (errno));
        return Qnil;
    }

    return Qnil;
}

static VALUE socket_send (VALUE self_, VALUE msg_, VALUE flags_)
{
    assert (DATA_PTR (self_));

    Check_Type (msg_, T_STRING);

    zmq_msg_t msg;
    int rc = zmq_msg_init_size (&msg, RSTRING_LEN (msg_));
    if (rc != 0) {
        rb_raise (rb_eRuntimeError, strerror (errno));
        return Qnil;
    }
    memcpy (zmq_msg_data (&msg), RSTRING_PTR (msg_), RSTRING_LEN (msg_));
 
    rc = zmq_send (DATA_PTR (self_), &msg, NUM2INT (flags_));
    if (rc != 0 && errno == EAGAIN) {
        rc = zmq_msg_close (&msg);
        assert (rc == 0);
        return Qfalse;
    }

    if (rc != 0) {
        rb_raise (rb_eRuntimeError, strerror (errno));
        rc = zmq_msg_close (&msg);
        assert (rc == 0);
        return Qnil;
    }

    rc = zmq_msg_close (&msg);
    assert (rc == 0);
    return Qtrue;
}

static VALUE socket_flush (VALUE self_)
{
    assert (DATA_PTR (self_));

    int rc = zmq_flush (DATA_PTR (self_));
    if (rc != 0) {
        rb_raise (rb_eRuntimeError, strerror (errno));
        return Qnil;
    }

    return Qnil;
}

static VALUE socket_recv (VALUE self_, VALUE flags_)
{
    assert (DATA_PTR (self_));

    zmq_msg_t msg;
    int rc = zmq_msg_init (&msg);
    assert (rc == 0);

    rc = zmq_recv (DATA_PTR (self_), &msg, NUM2INT (flags_));
    if (rc != 0 && errno == EAGAIN) {
        rc = zmq_msg_close (&msg);
        assert (rc == 0);
        return Qnil;
    }

    if (rc != 0) {
        rb_raise (rb_eRuntimeError, strerror (errno));
        rc = zmq_msg_close (&msg);
        assert (rc == 0);
        return Qnil;
    }

    VALUE message = rb_str_new ((char*) zmq_msg_data (&msg),
        zmq_msg_size (&msg));
    rc = zmq_msg_close (&msg);
    assert (rc == 0);
    return message;
}

extern "C" void Init_librbzmq ()
{	
    VALUE context_type = rb_define_class ("Context", rb_cObject);
    rb_define_alloc_func (context_type, context_alloc);
    rb_define_method (context_type, "initialize",
        (VALUE(*)(...)) context_initialize, 2);

    VALUE socket_type = rb_define_class ("Socket", rb_cObject);
    rb_define_alloc_func (socket_type, socket_alloc);
    rb_define_method (socket_type, "initialize",
        (VALUE(*)(...)) socket_initialize, 2);
//    rb_define_method (socket_type, "setsockopt",
//        (VALUE(*)(...)) socket_setsockopt, 2);
    rb_define_method (socket_type, "bind",
        (VALUE(*)(...)) socket_bind, 1);
    rb_define_method (socket_type, "connect",
        (VALUE(*)(...)) socket_connect, 1);
    rb_define_method (socket_type, "send",
        (VALUE(*)(...)) socket_send, 2);
    rb_define_method (socket_type, "flush",
        (VALUE(*)(...)) socket_flush, 0);
    rb_define_method (socket_type, "recv",
        (VALUE(*)(...)) socket_recv, 1);

    rb_define_global_const ("HWM", INT2NUM (ZMQ_HWM));
    rb_define_global_const ("LWM", INT2NUM (ZMQ_LWM));
    rb_define_global_const ("SWAP", INT2NUM (ZMQ_SWAP));
    rb_define_global_const ("AFFINITY", INT2NUM (ZMQ_AFFINITY));
    rb_define_global_const ("IDENTITY", INT2NUM (ZMQ_IDENTITY));

    rb_define_global_const ("NOBLOCK", INT2NUM (ZMQ_NOBLOCK));
    rb_define_global_const ("NOFLUSH", INT2NUM (ZMQ_NOFLUSH));

    rb_define_global_const ("P2P", INT2NUM (ZMQ_P2P));
    rb_define_global_const ("SUB", INT2NUM (ZMQ_SUB));
    rb_define_global_const ("PUB", INT2NUM (ZMQ_PUB));
    rb_define_global_const ("REQ", INT2NUM (ZMQ_REQ));
    rb_define_global_const ("REP", INT2NUM (ZMQ_REP));
}
