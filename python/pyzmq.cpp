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

#include <Python.h>

#include <zmq.hpp>

struct pyZMQ
{
    PyObject_HEAD
    
};

void pyZMQ_dealloc (pyZMQ *self)
{  

    self->ob_type->tp_free ((PyObject*) self);
}

PyObject *pyZMQ_new (PyTypeObject *type, PyObject *args, PyObject *kwdict)
{
    pyZMQ *self = (pyZMQ*) type->tp_alloc (type, 0);

    return (PyObject*) self;
}

PyObject *pyZMQ_term (PyTypeObject *type, PyObject *args, PyObject *kwdict)
{
    pyZMQ *self = (pyZMQ*) type->tp_alloc (type, 0);
    
    static const char *kwlist [] = {"context", NULL};
    PyObject *context;
    
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "O", (char**) kwlist,
         &context))
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");

	int rc = zmq_term ((void *) context);
	assert (rc != 0);
	
    return (PyObject*) self;
}

int pyZMQ_init  (pyZMQ *self, PyObject *args, PyObject *kwdict)
{
    return 0;
}

PyObject *pyZMQ_context  (pyZMQ *self, PyObject *args, PyObject *kwdict)
{
    static const char *kwlist [] = {"app_threads", "io_threads", NULL};

    int app_threads;
    int io_threads;
   
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "ii", (char**) kwlist,
         &app_threads, &io_threads))
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");
        	
    void *context = zmq_init (app_threads, io_threads);
    if (context == NULL) {
        assert (errno == EINVAL);
        PyErr_SetString (PyExc_ValueError, "Invalid argument");
    }
    
    return (PyObject*) context;
}

PyObject *pyZMQ_msg_init (pyZMQ *self, PyObject *args, PyObject *kwdict)
{
    zmq_msg *msg;

    int rc = zmq_msg_init (msg);
	
	if (rc == -1) {
		assert (rc == ENOMEM);
		PyErr_SetString( PyExc_MemoryError, "Out of memory");
	}
	
    return (PyObject*) msg;
}


PyObject *pyZMQ_msg_init_size (pyZMQ *self, PyObject *args, PyObject *kwdict)
{
    static const char *kwlist [] = {"size", NULL};

    zmq_msg *msg;
    int size;

    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "i", (char**) kwlist,
          &size))
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");

    int rc = zmq_msg_init_size (msg, size);
    
    if (rc == -1) {
		assert (rc == ENOMEM);
		PyErr_SetString( PyExc_ValueError, "Out of memory");
	}
	
    return (PyObject*) msg;
}

PyObject *pyZMQ_msg_init_data (pyZMQ *self, PyObject *args, PyObject *kwdict)
{
    static const char *kwlist [] = {"data", "size", "ffn", NULL};
    
    PyObject *data = PyString_FromStringAndSize (NULL, 0);
    zmq_msg *msg;
    PyObject *ffn;
    int size;

    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "SiO", (char**) kwlist,
          &data, &size, &ffn))
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");

    int rc = zmq_msg_init_data (msg, data, size, NULL);
    assert (rc == 0);
    
    return (PyObject*) msg;
}

PyObject *pyZMQ_msg_close (pyZMQ *self, PyObject *args, PyObject *kwdict)
{
    static const char *kwlist [] = {"msg", NULL};
    
    PyObject *msg;
   
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "O", (char**) kwlist,
          &msg))
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");

    int rc = zmq_msg_close ((zmq_msg *) msg);
    assert (rc == 0);

    return (PyObject*) self;
}

PyObject *pyZMQ_msg_move (pyZMQ *self, PyObject *args, PyObject *kwdict)
{
    static const char *kwlist [] = {"src", NULL};
    
    zmq_msg *dest;
    PyObject *src;
   
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "O", (char**) kwlist,
          &src))
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");

    int rc = zmq_msg_move (dest, (zmq_msg*) src);
    assert (rc == 0);

    return (PyObject*) dest;
}

PyObject *pyZMQ_msg_copy (pyZMQ *self, PyObject *args, PyObject *kwdict)
{
    static const char *kwlist [] = {"src", NULL};
    
    PyObject *dest;
    PyObject *src;
   
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "O", (char**) kwlist,
          &src))
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");

    int rc = zmq_msg_copy ((zmq_msg*) dest, (zmq_msg*) src);
    assert (rc == 0);
 
    return (PyObject*) dest;
}

PyObject *pyZMQ_msg_data (pyZMQ *self, PyObject *args, PyObject *kwdict)
{
    static const char *kwlist [] = {"msg", NULL};
    
    PyObject *msg;
    PyObject *data = PyString_FromStringAndSize (NULL, 0);
   
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "O", (char**) kwlist,
          &msg))
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");

	data = (PyObject *) zmq_msg_data ((zmq_msg *) msg);
 
    return (PyObject*) data;
}

int pyZMQ_msg_size (pyZMQ *self, PyObject *args, PyObject *kwdict)
{
    static const char *kwlist [] = {"msg", NULL};
    
    PyObject *msg;
   	int size;
   	
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "O", (char**) kwlist,
          &msg))
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");

	size = zmq_msg_size ((zmq_msg*) msg);

    return size;
}

int pyZMQ_msg_type (pyZMQ *self, PyObject *args, PyObject *kwdict)
{
    static const char *kwlist [] = {"msg", NULL};
    
    PyObject *msg;
   	int type;
   	
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "O", (char**) kwlist,
          &msg))
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");

	type = zmq_msg_type ((zmq_msg*) msg);

    return type;
}

PyObject *pyZMQ_socket (pyZMQ *self, PyObject *args, PyObject *kwdict)
{
    static const char *kwlist [] = {"context", "type", NULL};
    void* context;
    int type;

    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "Oi", (char**) kwlist,
          &context, &type))
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");
	
    void *socket = zmq_socket ((void *) context, type);
    
    if (socket == NULL) {
        assert (errno == EMFILE || errno == EINVAL);
        if (errno == EMFILE)
            PyErr_SetString (PyExc_MemoryError, "Too many threads");
        else
            PyErr_SetString (PyExc_ValueError, "Invalid argument");
    }

    return (PyObject*) socket;
}

PyObject *pyZMQ_close (pyZMQ *self, PyObject *args, PyObject *kwdict)
{
    static const char *kwlist [] = {"socket", NULL};
    
    PyObject* socket;
    
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "O", (char**) kwlist,
          &socket))
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");


    int rc = zmq_close ((void *)socket);
    assert (rc == 0);

    return (PyObject *) self;
}

PyObject *pyZMQ_setsockopt (pyZMQ *self, PyObject *args, PyObject *kwdict)
{
    static const char *kwlist [] = {"socket", "option", "optval", NULL};
	printf ("setsockopt\n");
    PyObject* socket;
    int option;
    PyObject* optval;
    int optvallen;
    int rc;
    
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "OiO", (char**) kwlist,
          &socket, &option, &optval))
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");
        
	if (PyInt_Check (optval))
	    rc = zmq_setsockopt ((void *) socket, option, (void *) optval, 
    		4);
	if (PyBool_Check (optval))
	    rc = zmq_setsockopt ((void *) socket, option, (void *) optval, 
    		1);
	if (PyFloat_Check (optval))
	    rc = zmq_setsockopt ((void *) socket, option, (void *) optval, 
    		4);
	if (PyString_Check (optval))
	    rc = zmq_setsockopt ((void *) socket, option, (void *) optval, 
    		PyString_Size (optval));    		

    assert (rc == 0);

    return (PyObject *) self;
}

PyObject *pyZMQ_bind (pyZMQ *self, PyObject *args, PyObject *kwdict)
{
    char const *addr = NULL;
    PyObject* socket;
   
    static const char *kwlist [] = {"socket", "addr", NULL};

    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "Os", (char**) kwlist, 
        &socket, &addr))
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");
    
    int rc = zmq_bind ((void*) socket, addr);
	if (rc == -1) {
        assert (errno == EINVAL || errno == EADDRINUSE);
        if (errno == EINVAL)
            PyErr_SetString (PyExc_ValueError, "Invalid argument");
        else
            PyErr_SetString (PyExc_ValueError, "Address in use");
    }

    return (PyObject *) self;
}
PyObject *pyZMQ_connect (pyZMQ *self, PyObject *args, PyObject *kw)
{
    char const *addr = NULL;
    PyObject* socket;
   
    static const char* kwlist [] = {"socket", "addr", NULL};

    if (!PyArg_ParseTupleAndKeywords (args, kw, "Os", (char**) kwlist,
          &socket, &addr)) 
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");

    int rc = zmq_connect ((void *) socket, addr);
    if (rc == -1) {
        assert (errno == EINVAL || errno == EADDRINUSE);
        if (errno == EINVAL)
            PyErr_SetString (PyExc_ValueError, "Invalid argument");
        else
            PyErr_SetString (PyExc_ValueError, "Address in use");
    }

    return (PyObject *) self;
}

PyObject *pyZMQ_flush (pyZMQ *self, PyObject *args, PyObject *kwdict)
{

	static const char *kwlist [] = {"socket", NULL};
	PyObject *socket;
	
	if (!PyArg_ParseTupleAndKeywords (args, kwdict, "O", (char**) kwlist,
          &socket)) 
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");
        
    int rc = zmq_flush ((void*) socket);
    assert (rc == 0);

    return (PyObject *) self;
}

PyObject *pyZMQ_send (pyZMQ *self, PyObject *args, PyObject *kwdict)
{
    PyObject *msg;
    PyObject *socket;
    int flags = 0;
  
    static const char *kwlist [] = {"socket", "msg", "flags", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwdict, "OOi", (char**) kwlist,
          &socket, &msg, &flags))
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");
    
    int rc = zmq_send ((void*) socket, (zmq_msg*) msg, flags);
    assert (rc == 0 || (rc == -1 && errno == EAGAIN));

    return (PyObject *) self;
}

PyObject *pyZMQ_receive (pyZMQ *self, PyObject *args, PyObject *kwdict)
{
    zmq_msg *msg;
    zmq_msg_init (msg);
    PyObject *socket;
    
    int flags = 0;
    static const char *kwlist [] = {"socket", "flags", NULL};

    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "Oi", (char**) kwlist,
          &socket, &flags))
        PyErr_SetString (PyExc_SystemError, 
        	"PyArg_ParseTupleAndKeywords error");

    int rc = zmq_recv (socket, msg, flags);
    assert (rc == 0 || (rc == -1 && errno == EAGAIN));
    
    PyObject *py_message = PyString_FromStringAndSize (NULL, 0);
    py_message = (PyObject *) zmq_msg_data (msg);
    int py_message_size = zmq_msg_size (msg);
    int py_message_type = zmq_msg_type (msg);
    
    zmq_msg_close (msg);
    
    return Py_BuildValue ("isi", rc, py_message,
        py_message_size, py_message_type);
}

static PyMethodDef pyZMQ_methods [] =
{
    {
        "context",
        (PyCFunction) pyZMQ_context,
        METH_VARARGS | METH_KEYWORDS, 
        "context (app_threads, io_threads) -> None\n\n"
        "Creates new context\n\n" 
        "app_threads is the number of application threads.\n\n"
        "io_threads is the number of io threads.\n\n"
        
    },
    {
        "msg_init",
        (PyCFunction) pyZMQ_msg_init,
        METH_VARARGS | METH_KEYWORDS, 
        "msg_init () -> None\n\n"
        "Creates new message\n\n" 
        
    },
    {
        "msg_init_size",
        (PyCFunction) pyZMQ_msg_init_size,
        METH_VARARGS | METH_KEYWORDS, 
        "msg_init_size (size) -> None\n\n"
        "Creates new message of a specified size.\n\n" 
        "size if integer specifying the size of the message to be created.\n\n"
       
    },
    {
        "msg_init_data",
        (PyCFunction) pyZMQ_msg_init_data,
        METH_VARARGS | METH_KEYWORDS, 
        "msg_init_data (data, size, ffn) -> None\n\n"
        "Initialises new message with data\n\n"
        "data is pointer to the data of the message\n\n"
        "size is integer specifying size of data\n\n"
        "ffn is function to free alocated data\n\n"
      
    }, 
    
     {
        "msg_close",
        (PyCFunction) pyZMQ_msg_close,
        METH_VARARGS | METH_KEYWORDS, 
        "msg_close (msg) -> None\n\n"
        "Deletes the message.\n\n"
        "msg is the message the be freed\n\n"
      
    }, 
     {
        "msg_move",
        (PyCFunction) pyZMQ_msg_move,
        METH_VARARGS | METH_KEYWORDS, 
        "msg_move (src) -> dest\n\n"
        "Move the content of the message from 'src' to 'dest'.\n\n"
        "The content isn't copied, just moved. 'src' is an empty\n\n"
        "message after the call. Original content of 'dest' message\n\n"
        "is deallocated.\n\n"
              
    }, 
     {
        "msg_copy",
        (PyCFunction) pyZMQ_msg_copy,
        METH_VARARGS | METH_KEYWORDS, 
        "msg_copy (src) -> dest\n\n"
        "Copy the 'src' message to 'dest'. The content isn't copied, \n\n"
        "instead reference count is increased. Don't modify the message \n\n"
        "data after the call as they are shared between two messages.\n\n"
        "Original content of 'dest' message is deallocated.\n\n"
      
    }, 
     {
        "msg_data",
        (PyCFunction) pyZMQ_msg_data,
        METH_VARARGS | METH_KEYWORDS, 
        "msg_data (msg) -> data\n\n"
        "Returns pointer to message data.\n\n"
      
    }, 
    {
        "msg_size",
        (PyCFunction) pyZMQ_msg_size,
        METH_VARARGS | METH_KEYWORDS, 
        "msg_size (msg) -> size\n\n"
        "Returns size of a message.\n\n"
      
    }, 
    {
        "msg_type",
        (PyCFunction) pyZMQ_msg_type,
        METH_VARARGS | METH_KEYWORDS, 
        "msg_type (msg) -> type\n\n"
        "Returns type of a message.\n\n"
      
    }, 
    {
        "term",
        (PyCFunction) pyZMQ_term,
        METH_VARARGS | METH_KEYWORDS, 
        "term (context) -> None\n\n"
        "Deinitialise 0SOCKETS context including all the open sockets.\n\n"
        "Closing sockets after zmq_term has been called will result in\n\n"
        "undefined behaviour.\n\n"
      
    }, 
    {
        "close",
        (PyCFunction) pyZMQ_close,
        METH_VARARGS | METH_KEYWORDS, 
        "close (socket) -> None\n\n"
        "Close the socket.\n\n"
      
    }, 
    
    {
        "socket",
        (PyCFunction) pyZMQ_socket,
        METH_VARARGS | METH_KEYWORDS, 
        "socket (context, type) -> None\n\n"
        "Creates new socket.\n\n" 
        "'context' is a context_t object.\n"
        "'type' is one of 'ZMQ_NOBLOCK', 'ZMQ_NOFLUSH', 'ZMQ_P2P', 'ZMQ_PUB', "
        " 'ZMQ_SUB', 'ZMQ_REQ ZMQ_REP'\n"
    },
    {
        "setsockopt",
        (PyCFunction) pyZMQ_setsockopt,
        METH_VARARGS | METH_KEYWORDS, 
        "setsockopt (socket, option, value) -> None\n\n"
        "Set socket options."
        "Possible options are: 'ZMQ_HWM', 'ZMQ_LWM', 'ZMQ_SWAP', 'ZMQ_MASK', "
		"'ZMQ_AFFINITY', 'ZMQ_IDENTITY'."
    },
    {
        "bind",
        (PyCFunction) pyZMQ_bind,
        METH_VARARGS | METH_KEYWORDS, 
        "bind (addr) -> None\n\n"
        "Bind socket to specified address."
    },
    {
        "connect",
        (PyCFunction) pyZMQ_connect,
        METH_VARARGS | METH_KEYWORDS, 
        "connect (addr) -> None\n\n"
        "connect socket to specified address."
    },
    {
        "flush",
        (PyCFunction) pyZMQ_flush,
        METH_VARARGS | METH_KEYWORDS, 
        "flush (addr) -> None\n\n"
        "flush "
    },
    {
        "send",
        (PyCFunction) pyZMQ_send,
        METH_VARARGS | METH_KEYWORDS, 
        "send (message, flags) -> sent\n\n"
        "Send a message to within the socket, "
        "returns integer specifying if the message was sent.\n"
        "'message' is message to be sent.\n"
        "'flags' is integer specifying send options.\n"
    },
    {
        "receive",
        (PyCFunction) pyZMQ_receive,
        METH_VARARGS | METH_KEYWORDS, 
        "receive (flags) -> (received, message, type)\n\n"
        "Receive a message."
        "'flags' is integer specifying receive options.\n"
        "'message' is string storing the message received.\n"
        "'type' is type of the message received.\n"

    },
    {
        NULL
    }
};

static const char* pyZMQ_ZMQ_doc =  
    "0MQ messaging session\n\n"
    "Available functions:\n"
    "  context\n"
    "  socket\n"
    "  setsockopt\n"
    "  bind\n"
    "  send\n"
    "  flush\n"
    "  receive\n\n";

static PyTypeObject pyZMQType =
{
    PyObject_HEAD_INIT (NULL)
    0,
    "libpyzmq.Zmq",            /* tp_name (This will appear in the default 
                               textual representation of our objects and 
                               in some error messages)*/
    sizeof (pyZMQ),            /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor) pyZMQ_dealloc,/* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_compare */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,        /* tp_flags */
    (char*) pyZMQ_ZMQ_doc,     /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    pyZMQ_methods,             /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc) pyZMQ_init,     /* tp_init */
    0,                         /* tp_alloc */
    pyZMQ_new,                 /* tp_new */
};

static PyMethodDef module_methods[] =
{
    { NULL, NULL, 0, NULL }
};

#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC void
#endif

static const char* pyZMQ_doc =
    "0MQ Python Module\n\n"
    "Constructor:\n"
    "  z = libpyzmq.Zmq ()\n"
    "Available functions:\n"
	"  context\n"
    "  socket\n"
    "  setsockopt\n"
    "  bind\n"
    "  send\n"
    "  flush\n"
    "  receive\n"
    "\n"
    "For more information see http://www.zeromq.org.\n"
    "\n"
    "0MQ is distributed under GNU Lesser General Public License v3\n";

PyMODINIT_FUNC initlibpyzmq (void)
{
    if (PyType_Ready (&pyZMQType) < 0)
        return;

    PyObject *m = Py_InitModule3 ("libpyzmq", module_methods,
        (char*) pyZMQ_doc);
    if (!m)
        return;

    Py_INCREF (&pyZMQType);

    PyModule_AddObject (m, "Zmq", (PyObject*) &pyZMQType);
    
    PyObject *d = PyModule_GetDict (m);
    
           
	PyObject *t = PyInt_FromLong (ZMQ_NOBLOCK);
    PyDict_SetItemString (d, "ZMQ_NOBLOCK", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_NOFLUSH);
    PyDict_SetItemString (d, "ZMQ_NOFLUSH", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_P2P);
    PyDict_SetItemString (d, "ZMQ_P2P", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_PUB);
    PyDict_SetItemString (d, "ZMQ_PUB", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_SUB);
    PyDict_SetItemString (d, "ZMQ_SUB", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_REQ);
    PyDict_SetItemString (d, "ZMQ_REQ", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_REP);
    PyDict_SetItemString (d, "ZMQ_REP", t);
    Py_DECREF (t);
    
    t = PyInt_FromLong (ZMQ_HWM);
    PyDict_SetItemString (d, "ZMQ_HWM", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_LWM);
    PyDict_SetItemString (d, "ZMQ_LWM", t);
    Py_DECREF (t);        
    t = PyInt_FromLong (ZMQ_SWAP);
    PyDict_SetItemString (d, "ZMQ_SWAP", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_MASK);
    PyDict_SetItemString (d, "ZMQ_MASK", t);
    Py_DECREF (t);        
    t = PyInt_FromLong (ZMQ_AFFINITY);
    PyDict_SetItemString (d, "ZMQ_AFFINITY", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_IDENTITY);
    PyDict_SetItemString (d, "ZMQ_IDENTITY", t);
    Py_DECREF (t);        
    
       
}
