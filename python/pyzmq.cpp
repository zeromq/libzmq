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

#include <stddef.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <Python.h>

#include "../c/zmq.h"

struct context_t
{
    PyObject_HEAD
    void *handle;
};

PyObject *context_new (PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    context_t *self = (context_t*) type->tp_alloc (type, 0);

    if (self)
        self->handle = NULL;

    return (PyObject*) self;
}


int context_init (context_t *self, PyObject *args, PyObject *kwdict)
{
    int app_threads;
    int io_threads;
    static const char *kwlist [] = {"app_threads", "io_threads", NULL};
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "ii", (char**) kwlist,
          &app_threads, &io_threads)) {
        PyErr_SetString (PyExc_SystemError, "invalid arguments");
        return -1; // ?
    }

    assert (!self->handle);
    self->handle = zmq_init (app_threads, io_threads);
    if (!self->handle) {
        PyErr_SetString (PyExc_SystemError, strerror (errno));
        return -1; // ?
    }

    return 0;
}

void context_dealloc (context_t *self)
{
    if (self->handle) {
        int rc = zmq_term (self->handle);
        if (rc != 0)
            PyErr_SetString (PyExc_SystemError, strerror (errno));
    }

    self->ob_type->tp_free ((PyObject*) self);
}

struct socket_t
{
    PyObject_HEAD
    void *handle;
};

PyObject *socket_new (PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    socket_t *self = (socket_t*) type->tp_alloc (type, 0);

    if (self)
        self->handle = NULL;

    return (PyObject*) self;
}

int socket_init (socket_t *self, PyObject *args, PyObject *kwdict)
{
    context_t *context;
    int socket_type;
    static const char *kwlist [] = {"context", "type", NULL};
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "Oi", (char**) kwlist,
          &context, &socket_type)) {
        PyErr_SetString (PyExc_SystemError, "invalid arguments");
        return NULL;
    }
    //  TODO: Check whether 'context' is really a libpyzmq.Context object.
	
    assert (!self->handle);
    self->handle = zmq_socket (context->handle, socket_type);
    if (!self->handle) {
        PyErr_SetString (PyExc_SystemError, strerror (errno));
        return -1; // ?
    }

    return 0;
}

void socket_dealloc (socket_t *self)
{
    if (self->handle) {
        int rc = zmq_close (self->handle);
        if (rc != 0)
            PyErr_SetString (PyExc_SystemError, strerror (errno));
    }

    self->ob_type->tp_free ((PyObject*) self);
}

PyObject *socket_setsockopt (socket_t *self, PyObject *args, PyObject *kwdict)
{
    int option;
    PyObject* optval;
    static const char *kwlist [] = {"option", "optval", NULL};
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "iO", (char**) kwlist,
          &option, &optval)) {
        PyErr_SetString (PyExc_SystemError, "invalid arguments");
        return NULL;
    }

    int rc;
	if (PyInt_Check (optval)) {
        int val = PyInt_AsLong (optval);
	    rc = zmq_setsockopt (self->handle, option, &val, sizeof (int));
    }
	if (PyString_Check (optval))
	    rc = zmq_setsockopt (self->handle, option, PyString_AsString (optval), 
    		PyString_Size (optval));
    else {
        rc = -1;
        errno = EINVAL;
    }

    if (rc != 0) {
        PyErr_SetString (PyExc_SystemError, strerror (errno));
        return NULL;
    }

    Py_INCREF (Py_None);
    return Py_None;
}

PyObject *socket_bind (socket_t *self, PyObject *args, PyObject *kwdict)
{
    char const *addr;
    static const char *kwlist [] = {"addr", NULL};
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "s", (char**) kwlist,
          &addr)) {
        PyErr_SetString (PyExc_SystemError, "invalid arguments");
        return NULL;
    }

    int rc = zmq_bind (self->handle, addr);
    if (rc != 0) {
        PyErr_SetString (PyExc_SystemError, strerror (errno));
        return NULL;
    }

    Py_INCREF (Py_None);
    return Py_None;
}

PyObject *socket_connect (socket_t *self, PyObject *args, PyObject *kwdict)
{
    char const *addr;
    static const char *kwlist [] = {"addr", NULL};
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "s", (char**) kwlist,
          &addr)) {
        PyErr_SetString (PyExc_SystemError, "invalid arguments");
        return NULL;
    }

    int rc = zmq_connect (self->handle, addr);
    if (rc != 0) {
        PyErr_SetString (PyExc_SystemError, strerror (errno));
        return NULL;
    }

    Py_INCREF (Py_None);
    return Py_None;
}

PyObject *socket_send (socket_t *self, PyObject *args, PyObject *kwdict)
{
    PyObject *msg; /* = PyString_FromStringAndSize (NULL, 0); */
    int flags = 0;
    static const char *kwlist [] = {"msg", "flags", NULL};
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "S|i", (char**) kwlist,
          &msg, &flags)) {
        PyErr_SetString (PyExc_SystemError, "invalid arguments");
        return NULL;
    }

    zmq_msg_t data;
    int rc = zmq_msg_init_size (&data, PyString_Size (msg));
    if (rc != 0) {
        PyErr_SetString (PyExc_SystemError, strerror (errno));
        return NULL;
    }
    memcpy (zmq_msg_data (&data), PyString_AsString (msg),
        zmq_msg_size (&data));

    rc = zmq_send (self->handle, &data, flags);
    int rc2 = zmq_msg_close (&data);
    assert (rc2 == 0);

    if (rc != 0 && errno == EAGAIN)
        return PyBool_FromLong (0);

    if (rc != 0) {
        PyErr_SetString (PyExc_SystemError, strerror (errno));
        return NULL;
    }

    return PyBool_FromLong (1);
}

PyObject *socket_flush (socket_t *self, PyObject *args, PyObject *kwdict)
{
    static const char *kwlist [] = {NULL};
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "", (char**) kwlist)) {
        PyErr_SetString (PyExc_SystemError, "invalid arguments");
        return NULL;
    }

    int rc = zmq_flush (self->handle);
    if (rc != 0) {
        PyErr_SetString (PyExc_SystemError, strerror (errno));
        return NULL;
    }

    Py_INCREF (Py_None);
    return Py_None;
}

PyObject *socket_recv (socket_t *self, PyObject *args, PyObject *kwdict)
{
    int flags = 0;
    static const char *kwlist [] = {"flags", NULL};
    if (!PyArg_ParseTupleAndKeywords (args, kwdict, "|i", (char**) kwlist,
          &flags)) {
        PyErr_SetString (PyExc_SystemError, "invalid arguments");
        return NULL;
    }

    zmq_msg_t msg;
    int rc = zmq_msg_init (&msg);
    assert (rc == 0);

    rc = zmq_recv (self->handle, &msg, flags);

    if (rc != 0 && errno == EAGAIN) {
        Py_INCREF (Py_None);
        return Py_None;
    }

    if (rc != 0) {
        PyErr_SetString (PyExc_SystemError, "invalid arguments");
        return NULL;
    }

    PyObject *result = PyString_FromStringAndSize ((char*) zmq_msg_data (&msg),
        zmq_msg_size (&msg));
    rc = zmq_msg_close (&msg);
    assert (rc == 0);
    return result;
}

static PyMethodDef context_methods [] =
{
    {
        NULL
    }
};

static PyTypeObject context_type =
{
    PyObject_HEAD_INIT (NULL)
    0,
    "libpyzmq.Context",              /* tp_name */
    sizeof (context_t),              /* tp_basicsize */
    0,                               /* tp_itemsize */
    (destructor) context_dealloc,    /* tp_dealloc */
    0,                               /* tp_print */
    0,                               /* tp_getattr */
    0,                               /* tp_setattr */
    0,                               /* tp_compare */
    0,                               /* tp_repr */
    0,                               /* tp_as_number */
    0,                               /* tp_as_sequence */
    0,                               /* tp_as_mapping */
    0,                               /* tp_hash */
    0,                               /* tp_call */
    0,                               /* tp_str */
    0,                               /* tp_getattro */
    0,                               /* tp_setattro */
    0,                               /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,              /* tp_flags */
    "",                              /* tp_doc */
    0,                               /* tp_traverse */
    0,                               /* tp_clear */
    0,                               /* tp_richcompare */
    0,                               /* tp_weaklistoffset */
    0,                               /* tp_iter */
    0,                               /* tp_iternext */
    context_methods,                 /* tp_methods */
    0,                               /* tp_members */
    0,                               /* tp_getset */
    0,                               /* tp_base */
    0,                               /* tp_dict */
    0,                               /* tp_descr_get */
    0,                               /* tp_descr_set */
    0,                               /* tp_dictoffset */
    (initproc) context_init,         /* tp_init */
    0,                               /* tp_alloc */
    context_new                      /* tp_new */
};

static PyMethodDef socket_methods [] =
{
    {
        "setsockopt",
        (PyCFunction) socket_setsockopt,
        METH_VARARGS | METH_KEYWORDS, 
        "setsockopt (option, optval) -> None\n\n"
    },
    {
        "bind",
        (PyCFunction) socket_bind,
        METH_VARARGS | METH_KEYWORDS, 
        "bind (addr) -> None\n\n"
    },
    {
        "connect",
        (PyCFunction) socket_connect,
        METH_VARARGS | METH_KEYWORDS, 
        "connect (addr) -> None\n\n"
    },
    {
        "send",
        (PyCFunction) socket_send,
        METH_VARARGS | METH_KEYWORDS, 
        "send (msg, [flags]) -> Bool\n\n"
    },
    {
        "flush",
        (PyCFunction) socket_flush,
        METH_VARARGS | METH_KEYWORDS, 
        "flush () -> None\n\n"
    },
    {
        "recv",
        (PyCFunction) socket_recv,
        METH_VARARGS | METH_KEYWORDS, 
        "recv ([flags]) -> String\n\n"
    },
    {
        NULL
    }
};

static PyTypeObject socket_type =
{
    PyObject_HEAD_INIT (NULL)
    0,
    "libpyzmq.Socket",               /* tp_name */
    sizeof (socket_t),               /* tp_basicsize */
    0,                               /* tp_itemsize */
    (destructor) socket_dealloc,     /* tp_dealloc */
    0,                               /* tp_print */
    0,                               /* tp_getattr */
    0,                               /* tp_setattr */
    0,                               /* tp_compare */
    0,                               /* tp_repr */
    0,                               /* tp_as_number */
    0,                               /* tp_as_sequence */
    0,                               /* tp_as_mapping */
    0,                               /* tp_hash */
    0,                               /* tp_call */
    0,                               /* tp_str */
    0,                               /* tp_getattro */
    0,                               /* tp_setattro */
    0,                               /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,              /* tp_flags */
    "",                              /* tp_doc */
    0,                               /* tp_traverse */
    0,                               /* tp_clear */
    0,                               /* tp_richcompare */
    0,                               /* tp_weaklistoffset */
    0,                               /* tp_iter */
    0,                               /* tp_iternext */
    socket_methods,                  /* tp_methods */
    0,                               /* tp_members */
    0,                               /* tp_getset */
    0,                               /* tp_base */
    0,                               /* tp_dict */
    0,                               /* tp_descr_get */
    0,                               /* tp_descr_set */
    0,                               /* tp_dictoffset */
    (initproc) socket_init,          /* tp_init */
    0,                               /* tp_alloc */
    socket_new                       /* tp_new */
};

static PyMethodDef module_methods [] = {{ NULL, NULL, 0, NULL }};

static const char* libpyzmq_doc =
    "Python API for 0MQ lightweight messaging kernel.\n"
    "For more information see http://www.zeromq.org.\n"
    "0MQ is distributed under GNU Lesser General Public License v3.\n";

#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC void
#endif

PyMODINIT_FUNC initlibpyzmq ()
{
    int rc = PyType_Ready (&context_type);
    assert (rc == 0);
    rc = PyType_Ready (&socket_type);
    assert (rc == 0);

    PyObject *module = Py_InitModule3 ("libpyzmq", module_methods,
        libpyzmq_doc);
    if (!module)
        return;

    Py_INCREF (&context_type);
    PyModule_AddObject (module, "Context", (PyObject*) &context_type);
    Py_INCREF (&socket_type);
    PyModule_AddObject (module, "Socket", (PyObject*) &socket_type);

    PyObject *dict = PyModule_GetDict (module);
    assert (dict);
	PyObject *t;
    t = PyInt_FromLong (ZMQ_NOBLOCK);
    PyDict_SetItemString (dict, "NOBLOCK", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_NOFLUSH);
    PyDict_SetItemString (dict, "NOFLUSH", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_P2P);
    PyDict_SetItemString (dict, "P2P", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_PUB);
    PyDict_SetItemString (dict, "PUB", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_SUB);
    PyDict_SetItemString (dict, "SUB", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_REQ);
    PyDict_SetItemString (dict, "REQ", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_REP);
    PyDict_SetItemString (dict, "REP", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_HWM);
    PyDict_SetItemString (dict, "HWM", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_LWM);
    PyDict_SetItemString (dict, "LWM", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_SWAP);
    PyDict_SetItemString (dict, "SWAP", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_MASK);
    PyDict_SetItemString (dict, "MASK", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_AFFINITY);
    PyDict_SetItemString (dict, "AFFINITY", t);
    Py_DECREF (t);
    t = PyInt_FromLong (ZMQ_IDENTITY);
    PyDict_SetItemString (dict, "IDENTITY", t);
    Py_DECREF (t);    
}
