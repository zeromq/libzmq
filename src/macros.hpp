
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

#if !defined ZMQ_OVERRIDE
#if defined ZMQ_HAVE_NOEXCEPT
#define ZMQ_OVERRIDE override
#else
#define ZMQ_OVERRIDE
#endif
#endif

#if !defined ZMQ_FINAL
#if defined ZMQ_HAVE_NOEXCEPT
#define ZMQ_FINAL final
#else
#define ZMQ_FINAL
#endif
#endif

#if !defined ZMQ_DEFAULT
#if defined ZMQ_HAVE_NOEXCEPT
#define ZMQ_DEFAULT = default;
#else
#define ZMQ_DEFAULT                                                            \
    {                                                                          \
    }
#endif
#endif

#if !defined ZMQ_NON_COPYABLE_NOR_MOVABLE
#if defined ZMQ_HAVE_NOEXCEPT
#define ZMQ_NON_COPYABLE_NOR_MOVABLE(classname)                                \
  public:                                                                      \
    classname (const classname &) = delete;                                    \
    classname &operator= (const classname &) = delete;                         \
    classname (classname &&) = delete;                                         \
    classname &operator= (classname &&) = delete;
#else
#define ZMQ_NON_COPYABLE_NOR_MOVABLE(classname)                                \
  private:                                                                     \
    classname (const classname &);                                             \
    classname &operator= (const classname &);
#endif
#endif
