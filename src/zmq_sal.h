/* SPDX-License-Identifier: MPL-2.0 */

/*  *************************************************************************
    Provides a set of annotations to describe how a function uses its
    parameters - the assumptions it makes about them, and the guarantees it
    makes upon finishing.
    
    These annotations are used by the static analysis tools to check for
    common programming errors, such as null pointer dereferences and buffer
    overruns.
    
    They are also used by the compiler to generate more efficient code,
    and by the IDE to provide better intellisense.

    Code analysis is enabled by adding /analyze to the compiler command line.
    *************************************************************************
*/

#ifndef __ZMQ_SAL_H_INCLUDED__
#define __ZMQ_SAL_H_INCLUDED__

#include "../include/zmq_sal.h"

#endif
