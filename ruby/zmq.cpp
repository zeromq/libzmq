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

#include <zmq.h>
#include <zmq/err.hpp>
#include <ruby.h>

//  Class rb_zmq.
static VALUE rb_zmq;

//  Structure to return received data.
static VALUE rb_data;

static void rb_free (void *p)
{
   	
} 

static VALUE rb_alloc (VALUE self_)
{
    VALUE obj;
    obj = Data_Wrap_Struct (self_, 0, rb_free, NULL);
	
    return obj;
}

static VALUE rb_msg_init (VALUE self_)
{
	zmq_msg_t *msg;
	msg = new zmq_msg_t;
	VALUE obj;
	
	int rc = zmq_msg_init (msg);
	if (rc == -1) {
        assert (errno == ENOMEM);
        rb_raise(rb_eRuntimeError, "Out of memory"); 
    }	
	
	obj = Data_Wrap_Struct (rb_zmq, 0, rb_free, msg);
	return obj;
}

static VALUE rb_msg_init_size (VALUE self_, VALUE size_)
{
	zmq_msg_t *msg;
	msg = new zmq_msg_t;
	VALUE obj;

	//  Forward the code to zmq library.	
	int rc = zmq_msg_init_size (msg, NUM2INT (size_));
	if (rc == -1) {
        assert (errno == ENOMEM);
        rb_raise(rb_eRuntimeError, "Out of memory"); 
    }	

	obj = Data_Wrap_Struct (rb_zmq, 0, rb_free, msg);
	return obj;
}

static VALUE rb_msg_init_data (VALUE self_, VALUE data_, VALUE size_)
{
	//  Get the message.
	zmq_msg_t *msg;
	VALUE obj;
	msg = new zmq_msg_t;

	//  Forward the code to zmq library.		
	int rc = zmq_msg_init_data (msg, StringValueCStr (data_), 
		NUM2INT (size_), rb_free);
	assert (rc == 0);
	
	obj = Data_Wrap_Struct (rb_zmq, 0, rb_free, msg);
	return obj;
}

static VALUE rb_msg_close (VALUE self_, VALUE msg_)
{
	//  Get the message.
    zmq_msg_t* msg;
    Data_Get_Struct (msg_, zmq_msg_t, msg);

	//  Forward the code to zmq library.    
	int rc = zmq_close (msg);
	assert (rc == 0);
	
	return self_;
}

static VALUE rb_msg_move (VALUE self_, VALUE src_)
{
    //  Get the message.
    zmq_msg_t* src;
    Data_Get_Struct (src_, zmq_msg_t, src);
	
	zmq_msg_t *dest;
	dest = new zmq_msg_t;
	VALUE obj;

	//  Forward the code to zmq library.	
	int rc = zmq_msg_move (dest, src);
	assert (rc == 0);
	
	obj = Data_Wrap_Struct (rb_zmq, 0, rb_free, dest);
	return obj;
}


static VALUE rb_msg_copy (VALUE self_, VALUE src_)
{
    //  Get the message.
    zmq_msg_t* src;
    Data_Get_Struct (src_, zmq_msg_t, src);
	
	zmq_msg_t *dest;
	dest = new zmq_msg_t;
	VALUE obj;

	//  Forward the code to zmq library.	
	int rc = zmq_msg_copy (dest, src);
	assert (rc == 0);
	
	obj = Data_Wrap_Struct (rb_zmq, 0, rb_free, dest);
	return obj;
}

static VALUE rb_msg_data (VALUE self_, VALUE msg_)
{
    //  Get the message.
    zmq_msg_t* msg;
    Data_Get_Struct (msg_, zmq_msg_t, msg);

	const char* data;

	//  Forward the code to zmq library.
	data = (const char*) zmq_msg_data (msg);
	
	return rb_str_new (data, zmq_msg_size (msg));
}

static VALUE rb_msg_size (VALUE self_, VALUE msg_)
{
    //  Get the message.
    zmq_msg_t* msg;
    Data_Get_Struct (msg_, zmq_msg_t, msg);
    
   	//  Forward the code to zmq library.
	return INT2NUM (zmq_msg_size (msg));
}

static VALUE rb_msg_type (VALUE self_, VALUE msg_)
{
    //  Get the message.
    zmq_msg_t* msg;
    Data_Get_Struct (msg_, zmq_msg_t, msg);

	//  Forward the code to zmq library.    
	return INT2NUM (zmq_msg_type (msg));
}

static VALUE rb_init (VALUE self_)
{
	return self_;
}

static VALUE rb_context (VALUE self_, VALUE app_threads_, VALUE io_threads_)
{
	void *context;
	VALUE obj;

	//  Forward the code to zmq library.	
	context = zmq_init (NUM2INT (app_threads_), NUM2INT (io_threads_));	
	if (context == NULL) {
        assert (errno == EINVAL);
        rb_raise(rb_eRuntimeError, "Invalid argument"); 
    }

	obj = Data_Wrap_Struct (rb_zmq, 0, free, context);
    return self_;
}

static VALUE rb_term (VALUE self_, VALUE context_)
{
	//  Get the context.
    void* context;
    Data_Get_Struct (context_, void*, context);

	//  Forward the code to zmq library.    
   	int rc = zmq_term ((void*) context);
   	assert (rc == 0);
   	
    return self_;
}

static VALUE rb_socket (VALUE self_, VALUE context_, VALUE type_)
{
	//  Get the context.
    void* context;
    Data_Get_Struct (context_, void*, context);
    
    void* socket = NULL;
    VALUE obj;

    //  Forward the call to native 0MQ library.
	socket = zmq_socket(context, NUM2INT (type_));
	if (socket == NULL) {
        assert (errno == EMFILE || errno == EINVAL);
        if (errno == EMFILE)
	        rb_raise(rb_eRuntimeError, "Too many threads"); 
        else
	        rb_raise(rb_eRuntimeError, "Invalid argument"); 
    }
	
    obj = Data_Wrap_Struct(rb_zmq, 0, free, socket);
    return obj;
}

static VALUE rb_close (VALUE self_, VALUE socket_)
{
    //  Get the message.
    void* socket;
    Data_Get_Struct (socket_, void*, socket);
    
    //  Forward the call to native 0MQ library.
    int rc = zmq_close (socket);
    assert (rc == 0);
    return self_;
}	

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

static VALUE rb_bind (VALUE self_, VALUE socket_, VALUE addr_)
{
	//  Get the socket.
    void* socket;
    Data_Get_Struct (socket_, void*, socket);
    
   	//  Forward the code to native 0MQ library.    
    int rc = zmq_bind (socket, StringValueCStr (addr_));
    if (rc == -1) {
        assert (errno == EINVAL || errno == EADDRINUSE);
        if (errno == EINVAL)
            rb_raise(rb_eRuntimeError, "Invalid argument"); 
        else
            rb_raise(rb_eRuntimeError, "Address in use"); 
    }
    
    return self_;
}

static VALUE rb_connect (VALUE self_, VALUE socket_, VALUE addr_)
{
	//  Get the socket.
    void* socket;
    Data_Get_Struct (socket_, void*, socket);

   	//  Forward the code to native 0MQ library.
	int rc = zmq_connect (socket, StringValueCStr (addr_));
    if (rc == -1) {
        assert (errno == EINVAL || errno == EADDRINUSE);
        if (errno == EINVAL)
            rb_raise(rb_eRuntimeError, "Invalid argument"); 
        else
             rb_raise(rb_eRuntimeError, "Address in use");
    }
    return self_;
}

static VALUE rb_send (VALUE self_, VALUE socket_, VALUE msg_, VALUE flags_)
{
	//  Get the socket.
    void* socket;
    Data_Get_Struct (socket_, void*, socket);
    
    //  Get the message.
    zmq_msg_t *msg;
    Data_Get_Struct (msg_, zmq_msg_t, msg);

   	//  Forward the code to native 0MQ library.    
    int rc = zmq_send (socket, msg, NUM2INT (flags_));
    assert (rc == 0 || (rc == -1 && errno == EAGAIN));

    return INT2NUM (rc);
}

static VALUE rb_flush (VALUE self_, VALUE socket_)
{
	//  Get the socket.
    void* socket;
    Data_Get_Struct (socket_, void*, socket);

   	//  Forward the code to native 0MQ library.    
    int rc = zmq_flush (socket);
    assert (rc == 0);
    
    return self_;
}

static VALUE rb_recv (VALUE self_, VALUE socket_, VALUE flags_)
{
	//  Get the socket.
    void* socket;
    Data_Get_Struct (socket_, void*, socket);
    
    //  Get the message.
    zmq_msg_t* msg;
    msg = new zmq_msg_t;
    VALUE obj;

   	//  Forward the code to native 0MQ library.       
	int rc = zmq_recv (socket, msg, NUM2INT (flags_));
	assert (rc == 0 || (rc == -1 && errno == EAGAIN));

	obj = Data_Wrap_Struct(rb_data, 0, rb_free, msg);
	    
    return rb_struct_new (obj, rc, NULL);
}

extern "C"
void Init_librbzmq() {
	
	//  Define the rb_zmq class.
    rb_zmq = rb_define_class ("Zmq", rb_cObject);
	
	//  Define allocation function for rb_zmq class.
    rb_define_alloc_func (rb_zmq, rb_alloc);
    
    //  Parameters: <name_of_class> <name_of_method_aaccessible_from_ruby>
    //  <name_of_method_in_the_class> <number_of_arguments> 
    //  number of arguments is alqays except for the 'VALUE self_' argument 
    //  (this pointer).
    rb_define_method (rb_zmq, "msg_init", (VALUE(*)(...)) rb_msg_init, 0);
    rb_define_method (rb_zmq, "msg_init_size", (VALUE(*)(...)) 
    	rb_msg_init_size, 1);
    rb_define_method (rb_zmq, "msg_init_data", (VALUE(*)(...)) 
    	rb_msg_init_data, 3);
    rb_define_method (rb_zmq, "msg_close", (VALUE(*)(...)) rb_msg_close, 1);
    rb_define_method (rb_zmq, "msg_move", (VALUE(*)(...)) rb_msg_move, 1);
    rb_define_method (rb_zmq, "msg_copy", (VALUE(*)(...)) rb_msg_copy, 1);
    rb_define_method (rb_zmq, "msg_data", (VALUE(*)(...)) rb_msg_data, 1);
    rb_define_method (rb_zmq, "msg_size", (VALUE(*)(...)) rb_msg_size, 1);
    rb_define_method (rb_zmq, "msg_type", (VALUE(*)(...)) rb_msg_type, 1);
  
    rb_define_method (rb_zmq, "initialize", (VALUE(*)(...)) rb_init, 0);
	rb_define_method (rb_zmq, "term", (VALUE(*)(...)) rb_term, 1);  
    rb_define_method (rb_zmq, "free", (VALUE(*)(...)) rb_free, 0); 
	
	rb_define_method (rb_zmq, "context", (VALUE(*)(...)) rb_context, 2);
    rb_define_method (rb_zmq, "socket", (VALUE(*)(...)) rb_socket, 2);
    rb_define_method (rb_zmq, "close", (VALUE(*)(...)) rb_close, 1);
    rb_define_method (rb_zmq, "setsockopt", (VALUE(*)(...)) rb_setsockopt, 3);    
    rb_define_method (rb_zmq, "bind", (VALUE(*)(...)) rb_bind, 2);
    rb_define_method (rb_zmq, "connect", (VALUE(*)(...)) rb_connect, 2);
    rb_define_method (rb_zmq, "send", (VALUE(*)(...)) rb_send, 3);
    rb_define_method (rb_zmq, "flush", (VALUE(*)(...)) rb_flush, 1);
    rb_define_method (rb_zmq, "recv", (VALUE(*)(...)) rb_recv, 2);
  
	//  Define structure to hold data that are returned from receive function.
    rb_data = rb_struct_define (NULL, "msg", "rc", NULL);
    rb_define_const (rb_zmq, "DATA", rb_data);

	//  Define global constants.
    rb_define_global_const ("ZMQ_MAX_VSM_SIZE", INT2NUM (ZMQ_MAX_VSM_SIZE));
    rb_define_global_const ("ZMQ_GAP", INT2NUM (ZMQ_GAP));
    rb_define_global_const ("ZMQ_DELIMITER", INT2NUM (ZMQ_DELIMITER));
    rb_define_global_const ("ZMQ_VSM", INT2NUM (ZMQ_VSM));
    rb_define_global_const ("ZMQ_HWM", INT2NUM (ZMQ_HWM));
    rb_define_global_const ("ZMQ_SWAP", INT2NUM (ZMQ_SWAP));
    rb_define_global_const ("ZMQ_MASK", INT2NUM (ZMQ_MASK));
    rb_define_global_const ("ZMQ_AFFINITY", INT2NUM (ZMQ_AFFINITY));
    rb_define_global_const ("ZMQ_IDENTITY", INT2NUM (ZMQ_IDENTITY));
    rb_define_global_const ("ZMQ_NOBLOCK", INT2NUM (ZMQ_NOBLOCK));
    rb_define_global_const ("ZMQ_NOFLUSH", INT2NUM (ZMQ_NOFLUSH));
    rb_define_global_const ("ZMQ_P2P", INT2NUM (ZMQ_P2P));
    rb_define_global_const ("ZMQ_SUB", INT2NUM (ZMQ_SUB));
    rb_define_global_const ("ZMQ_PUB", INT2NUM (ZMQ_PUB));
    rb_define_global_const ("ZMQ_REQ", INT2NUM (ZMQ_REQ));
    rb_define_global_const ("ZMQ_REP", INT2NUM (ZMQ_REP));

}
