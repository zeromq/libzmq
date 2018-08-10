
/******************************************************************************/
/*  0MQ Internal Use                                                          */
/******************************************************************************/

#define LIBZMQ_UNUSED(object) (void) object
#define LIBZMQ_DELETE(p_object)                                                \
    {                                                                          \
        delete p_object;                                                       \
        p_object = 0;                                                          \
    }

/******************************************************************************/

#if !defined ZMQ_NOEXCEPT
#if defined ZMQ_HAVE_NOEXCEPT
#define ZMQ_NOEXCEPT noexcept
#else
#define ZMQ_NOEXCEPT
#endif
#endif
