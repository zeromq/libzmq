
#include "platform.hpp"

#if defined ZMQ_HAVE_NORM

#include "norm_engine.hpp"
#include "session_base.hpp"
#include "v2_protocol.hpp"

zmq::norm_engine_t::norm_engine_t(io_thread_t*     parent_,
                                  const options_t& options_)
 : io_object_t(parent_), zmq_session(NULL), options(options_),
   norm_instance(NORM_INSTANCE_INVALID), norm_session(NORM_SESSION_INVALID),
   is_sender(false), is_receiver(false),
   zmq_encoder(0), norm_tx_stream(NORM_OBJECT_INVALID),
   tx_first_msg(true), tx_more_bit(false),
   zmq_output_ready(false), norm_tx_ready(false),
   tx_index(0), tx_len(0),
   zmq_input_ready(false)
{
    int rc = tx_msg.init();
    errno_assert(0 == rc);
}

zmq::norm_engine_t::~norm_engine_t()
{
    shutdown();  // in case it was not already called
}


int zmq::norm_engine_t::init(const char* network_, bool send, bool recv)
{
    // Parse the "network_" address int "iface", "addr", and "port"
    // norm endpoint format: [id,][<iface>;]<addr>:<port>
    // First, look for optional local NormNodeId
    // (default NORM_NODE_ANY causes NORM to use host IP addr for NormNodeId)
    NormNodeId localId = NORM_NODE_ANY;
    const char* ifacePtr = strchr(network_, ',');
    if (NULL != ifacePtr)
    {
        size_t idLen = ifacePtr - network_;
        if (idLen > 31) idLen = 31;
        char idText[32];
        strncpy(idText, network_, idLen);
        idText[idLen] = '\0';
        localId = (NormNodeId)atoi(idText);
        ifacePtr++;
    }
    else
    {
        ifacePtr = network_;
    }

    // Second, look for optional multicast ifaceName
    char ifaceName[256];
    const char* addrPtr = strchr(ifacePtr, ';');
    if (NULL != addrPtr)
    {
        size_t ifaceLen = addrPtr - ifacePtr;
        if (ifaceLen > 255) ifaceLen = 255;  // return error instead?
        strncpy(ifaceName, ifacePtr, ifaceLen);
        ifaceName[ifaceLen] = '\0';
        ifacePtr = ifaceName;
        addrPtr++;
    }
    else
    {
        addrPtr = ifacePtr;
        ifacePtr = NULL;
    }

    // Finally, parse IP address and port number
    const char* portPtr = strrchr(addrPtr, ':');
    if (NULL == portPtr)
    {
        errno = EINVAL;
        return -1;
    }

    char addr[256];
    size_t addrLen = portPtr - addrPtr;
    if (addrLen > 255) addrLen = 255;
    strncpy(addr, addrPtr, addrLen);
    addr[addrLen] = '\0';
    portPtr++;
    unsigned short portNumber = atoi(portPtr);

    if (NORM_INSTANCE_INVALID == norm_instance)
    {
        if (NORM_INSTANCE_INVALID == (norm_instance = NormCreateInstance()))
        {
            // errno set by whatever caused NormCreateInstance() to fail
            return -1;
        }
    }

    // TBD - What do we use for our local NormNodeId?
    //       (for now we use automatic, IP addr based assignment or passed in 'id')
    //       a) Use ZMQ Identity somehow?
    //       b) Add function to use iface addr
    //       c) Randomize and implement a NORM session layer
    //          conflict detection/resolution protocol

    norm_session = NormCreateSession(norm_instance, addr, portNumber, localId);
    if (NORM_SESSION_INVALID == norm_session)
    {
        int savedErrno = errno;
        NormDestroyInstance(norm_instance);
        norm_instance = NORM_INSTANCE_INVALID;
        errno = savedErrno;
        return -1;
    }
    // There's many other useful NORM options that could be applied here
    if (NormIsUnicastAddress(addr))
    {
        NormSetDefaultUnicastNack(norm_session, true);
    }
    else
    {
        // These only apply for multicast sessions
        //NormSetTTL(norm_session, options.multicast_hops);  // ZMQ default is 1
        NormSetTTL(norm_session, 255);  // since the ZMQ_MULTICAST_HOPS socket option isn't well-supported
        NormSetRxPortReuse(norm_session, true);  // port reuse doesn't work for non-connected unicast
        NormSetLoopback(norm_session, true);  // needed when multicast users on same machine
        if (NULL != ifacePtr)
        {
            // Note a bad interface may not be caught until sender or receiver start
            // (Since sender/receiver is not yet started, this always succeeds here)
            NormSetMulticastInterface(norm_session, ifacePtr);
        }
    }

    if (recv)
    {
        // The alternative NORM_SYNC_CURRENT here would provide "instant"
        // receiver sync to the sender's _current_ message transmission.
        // NORM_SYNC_STREAM tries to get everything the sender has cached/buffered
        NormSetDefaultSyncPolicy(norm_session, NORM_SYNC_STREAM);
        if (!NormStartReceiver(norm_session, 2*1024*1024))
        {
            // errno set by whatever failed
            int savedErrno = errno;
            NormDestroyInstance(norm_instance); // session gets closed, too
            norm_session = NORM_SESSION_INVALID;
            norm_instance = NORM_INSTANCE_INVALID;
            errno = savedErrno;
            return -1;
        }
        is_receiver = true;
    }

    if (send)
    {
        // Pick a random sender instance id (aka norm sender session id)
        NormSessionId instanceId = NormGetRandomSessionId();
        // TBD - provide "options" for some NORM sender parameters
        if (!NormStartSender(norm_session, instanceId, 2*1024*1024, 1400, 16, 4))
        {
            // errno set by whatever failed
            int savedErrno = errno;
            NormDestroyInstance(norm_instance); // session gets closed, too
            norm_session = NORM_SESSION_INVALID;
            norm_instance = NORM_INSTANCE_INVALID;
            errno = savedErrno;
            return -1;
        }
        NormSetCongestionControl(norm_session, true);
        norm_tx_ready = true;
        is_sender = true;
        if (NORM_OBJECT_INVALID == (norm_tx_stream = NormStreamOpen(norm_session, 2*1024*1024)))
        {
            // errno set by whatever failed
            int savedErrno = errno;
            NormDestroyInstance(norm_instance); // session gets closed, too
            norm_session = NORM_SESSION_INVALID;
            norm_instance = NORM_INSTANCE_INVALID;
            errno = savedErrno;
            return -1;
        }
    }

    //NormSetMessageTrace(norm_session, true);
    //NormSetDebugLevel(3);
    //NormOpenDebugLog(norm_instance, "normLog.txt");

    return 0;  // no error
}  // end zmq::norm_engine_t::init()

void zmq::norm_engine_t::shutdown()
{
    // TBD - implement a more graceful shutdown option
    if (is_receiver)
    {
        NormStopReceiver(norm_session);

        // delete any active NormRxStreamState
        rx_pending_list.Destroy();
        rx_ready_list.Destroy();
        msg_ready_list.Destroy();

        is_receiver = false;
    }
    if (is_sender)
    {
        NormStopSender(norm_session);
        is_sender = false;
    }
    if (NORM_SESSION_INVALID != norm_session)
    {
        NormDestroySession(norm_session);
        norm_session = NORM_SESSION_INVALID;
    }
    if (NORM_INSTANCE_INVALID != norm_instance)
    {
        NormStopInstance(norm_instance);
        NormDestroyInstance(norm_instance);
        norm_instance = NORM_INSTANCE_INVALID;
    }
}  // end zmq::norm_engine_t::shutdown()

void zmq::norm_engine_t::plug (io_thread_t* io_thread_, session_base_t *session_)
{
    // TBD - we may assign the NORM engine to an io_thread in the future???
    zmq_session = session_;
    if (is_sender) zmq_output_ready = true;
    if (is_receiver) zmq_input_ready = true;

    fd_t normDescriptor = NormGetDescriptor(norm_instance);
    norm_descriptor_handle = add_fd(normDescriptor);
    // Set POLLIN for notification of pending NormEvents
    set_pollin(norm_descriptor_handle);

    if (is_sender) send_data();

}  // end zmq::norm_engine_t::init()

void zmq::norm_engine_t::unplug()
{
    rm_fd(norm_descriptor_handle);

    zmq_session = NULL;
}  // end zmq::norm_engine_t::unplug()

void zmq::norm_engine_t::terminate()
{
    unplug();
    shutdown();
    delete this;
}

void zmq::norm_engine_t::restart_output()
{
    // There's new message data available from the session
    zmq_output_ready = true;
    if (norm_tx_ready) send_data();

}  // end zmq::norm_engine_t::restart_output()

void zmq::norm_engine_t::send_data()
{
    // Here we write as much as is available or we can
    while (zmq_output_ready && norm_tx_ready)
    {
        if (0 == tx_len)
        {
            // Our tx_buffer needs data to send
            // Get more data from encoder
            size_t space = BUFFER_SIZE;
            unsigned char* bufPtr = (unsigned char*)tx_buffer;
            tx_len = zmq_encoder.encode(&bufPtr, space);
            if (0 == tx_len)
            {
                if (tx_first_msg)
                {
                    // We don't need to mark eom/flush until a message is sent
                    tx_first_msg = false;
                }
                else
                {
                    // A prior message was completely written to stream, so
                    // mark end-of-message and possibly flush (to force packet transmission,
                    // even if it's not a full segment so message gets delivered quickly)
                    // NormStreamMarkEom(norm_tx_stream);  // the flush below marks eom
                    // Note NORM_FLUSH_ACTIVE makes NORM fairly chatty for low duty cycle messaging
                    // but makes sure content is delivered quickly.  Positive acknowledgements
                    // with flush override would make NORM more succinct here
                    NormStreamFlush(norm_tx_stream, true, NORM_FLUSH_ACTIVE);
                }
                // Need to pull and load a new message to send
                if (-1 == zmq_session->pull_msg(&tx_msg))
                {
                    // We need to wait for "restart_output()" to be called by ZMQ
                    zmq_output_ready = false;
                    break;
                }
                zmq_encoder.load_msg(&tx_msg);
                // Should we write message size header for NORM to use? Or expect NORM
                // receiver to decode ZMQ message framing format(s)?
                // OK - we need to use a byte to denote when the ZMQ frame is the _first_
                //      frame of a message so it can be decoded properly when a receiver
                //      'syncs' mid-stream.  We key off the the state of the 'more_flag'
                //      I.e.,If  more_flag _was_ false previously, this is the first
                //      frame of a ZMQ message.
                if (tx_more_bit)
                    tx_buffer[0] = (char)0xff;  // this is not first frame of message
                else
                    tx_buffer[0] = 0x00;  // this is first frame of message
                tx_more_bit = (0 != (tx_msg.flags() & msg_t::more));
                // Go ahead an get a first chunk of the message
                bufPtr++;
                space--;
                tx_len = 1 + zmq_encoder.encode(&bufPtr, space);
                tx_index = 0;
            }
        }
        // Do we have data in our tx_buffer pending
        if (tx_index < tx_len)
        {
            // We have data in our tx_buffer to send, so write it to the stream
            tx_index += NormStreamWrite(norm_tx_stream, tx_buffer + tx_index, tx_len - tx_index);
            if (tx_index < tx_len)
            {
                // NORM stream buffer full, wait for NORM_TX_QUEUE_VACANCY
                norm_tx_ready = false;
                break;
            }
            tx_len = 0;  // all buffered data was written
        }
    }  // end while (zmq_output_ready && norm_tx_ready)
}  // end zmq::norm_engine_t::send_data()

void zmq::norm_engine_t::in_event()
{
    // This means a NormEvent is pending, so call NormGetNextEvent() and handle
    NormEvent event;
    if (!NormGetNextEvent(norm_instance, &event))
    {
        // NORM has died before we unplugged?!
        zmq_assert(false);
        return;
    }

    switch(event.type)
    {
        case NORM_TX_QUEUE_VACANCY:
        case NORM_TX_QUEUE_EMPTY:
            if (!norm_tx_ready)
            {
                norm_tx_ready = true;
                send_data();
            }
            break;

        case NORM_RX_OBJECT_NEW:
            //break;
        case NORM_RX_OBJECT_UPDATED:
            recv_data(event.object);
            break;

        case NORM_RX_OBJECT_ABORTED:
        {
            NormRxStreamState* rxState = (NormRxStreamState*)NormObjectGetUserData(event.object);
            if (NULL != rxState)
            {
                // Remove the state from the list it's in
                // This is now unnecessary since deletion takes care of list removal
                // but in the interest of being clear ...
                NormRxStreamState::List* list = rxState->AccessList();
                if (NULL != list) list->Remove(*rxState);
            }
            delete rxState;
            break;
        }
        case NORM_REMOTE_SENDER_INACTIVE:
            // Here we free resources used for this formerly active sender.
            // Note w/ NORM_SYNC_STREAM, if sender reactivates, we may
            //  get some messages delivered twice.  NORM_SYNC_CURRENT would
            // mitigate that but might miss data at startup. Always tradeoffs.
            // Instead of immediately deleting, we could instead initiate a
            // user configurable timeout here to wait some amount of time
            // after this event to declare the remote sender truly dead
            // and delete its state???
            NormNodeDelete(event.sender);
            break;

        default:
            // We ignore some NORM events
            break;
    }
}  // zmq::norm_engine_t::in_event()

void zmq::norm_engine_t::restart_input()
{
    // TBD - should we check/assert that zmq_input_ready was false???
    zmq_input_ready = true;
    // Process any pending received messages
    if (!msg_ready_list.IsEmpty())
        recv_data(NORM_OBJECT_INVALID);

}  // end zmq::norm_engine_t::restart_input()

void zmq::norm_engine_t::recv_data(NormObjectHandle object)
{
    if (NORM_OBJECT_INVALID != object)
    {
        // Call result of NORM_RX_OBJECT_UPDATED notification
        // This is a rx_ready indication for a new or existing rx stream
        // First, determine if this is a stream we already know
        zmq_assert(NORM_OBJECT_STREAM == NormObjectGetType(object));
        // Since there can be multiple senders (publishers), we keep
        // state for each separate rx stream.
        NormRxStreamState* rxState = (NormRxStreamState*)NormObjectGetUserData(object);
        if (NULL == rxState)
        {
            // This is a new stream, so create rxState with zmq decoder, etc
            rxState = new NormRxStreamState(object, options.maxmsgsize);
            if (!rxState->Init())
            {
                errno_assert(false);
                delete rxState;
                return;
            }
            NormObjectSetUserData(object, rxState);
        }
        else if (!rxState->IsRxReady())
        {
            // Existing non-ready stream, so remove from pending
            // list to be promoted to rx_ready_list ...
            rx_pending_list.Remove(*rxState);
        }
        if (!rxState->IsRxReady())
        {
            // TBD - prepend up front for immediate service?
            rxState->SetRxReady(true);
            rx_ready_list.Append(*rxState);
        }
    }
    // This loop repeats until we've read all data available from "rx ready" inbound streams
    // and pushed any accumulated messages we can up to the zmq session.
    while (!rx_ready_list.IsEmpty() || (zmq_input_ready && !msg_ready_list.IsEmpty()))
    {
        // Iterate through our rx_ready streams, reading data into the decoder
        // (This services incoming "rx ready" streams in a round-robin fashion)
        NormRxStreamState::List::Iterator iterator(rx_ready_list);
        NormRxStreamState* rxState;
        while (NULL != (rxState = iterator.GetNextItem()))
        {
            switch(rxState->Decode())
            {
                case 1:  // msg completed
                    // Complete message decoded, move this stream to msg_ready_list
                    // to push the message up to the session below.  Note the stream
                    // will be returned to the "rx_ready_list" after that's done
                    rx_ready_list.Remove(*rxState);
                    msg_ready_list.Append(*rxState);
                    continue;

                case -1: // decoding error (shouldn't happen w/ NORM, but ...)
                    // We need to re-sync this stream (decoder buffer was reset)
                    rxState->SetSync(false);
                    break;

                default:  // 0 - need more data
                    break;
            }
            // Get more data from this stream
            NormObjectHandle stream = rxState->GetStreamHandle();
            // First, make sure we're in sync ...
            while (!rxState->InSync())
            {
                // seek NORM message start
                if (!NormStreamSeekMsgStart(stream))
                {
                    // Need to wait for more data
                    break;
                }
                // read message 'flag' byte to see if this it's a 'final' frame
                char syncFlag;
                unsigned int numBytes = 1;
                if (!NormStreamRead(stream, &syncFlag, &numBytes))
                {
                    // broken stream (shouldn't happen after seek msg start?)
                    zmq_assert(false);
                    continue;
                }
                if (0 == numBytes)
                {
                    // This probably shouldn't happen either since we found msg start
                    // Need to wait for more data
                    break;
                }
                if (0 == syncFlag) rxState->SetSync(true);
                // else keep seeking ...
            }  // end while(!rxState->InSync())
            if (!rxState->InSync())
            {
                // Need more data for this stream, so remove from "rx ready"
                // list and iterate to next "rx ready" stream
                rxState->SetRxReady(false);
                // Move from rx_ready_list to rx_pending_list
                rx_ready_list.Remove(*rxState);
                rx_pending_list.Append(*rxState);
                continue;
            }
            // Now we're actually ready to read data from the NORM stream to the zmq_decoder
            // the underlying zmq_decoder->get_buffer() call sets how much is needed.
            unsigned int numBytes = rxState->GetBytesNeeded();
            if (!NormStreamRead(stream, rxState->AccessBuffer(), &numBytes))
            {
                // broken NORM stream, so re-sync
                rxState->Init();  // TBD - check result
                // This will retry syncing, and getting data from this stream
                // since we don't increment the "it" iterator
                continue;
            }
            rxState->IncrementBufferCount(numBytes);
            if (0 == numBytes)
            {
                // All the data available has been read
                // Need to wait for NORM_RX_OBJECT_UPDATED for this stream
                rxState->SetRxReady(false);
                // Move from rx_ready_list to rx_pending_list
                rx_ready_list.Remove(*rxState);
                rx_pending_list.Append(*rxState);
            }
        }  // end while(NULL != (rxState = iterator.GetNextItem()))

        if (zmq_input_ready)
        {
            // At this point, we've made a pass through the "rx_ready" stream list
            // Now make a pass through the "msg_pending" list (if the zmq session
            // ready for more input).  This may possibly return streams back to
            // the "rx ready" stream list after their pending message is handled
            NormRxStreamState::List::Iterator iterator(msg_ready_list);
            NormRxStreamState* rxState;
            while (NULL != (rxState = iterator.GetNextItem()))
            {
                msg_t* msg = rxState->AccessMsg();
                int rc = zmq_session->push_msg(msg);
                if (-1 == rc)
                {
                    if (EAGAIN == errno)
                    {
                        // need to wait until session calls "restart_input()"
                        zmq_input_ready = false;
                        break;
                    }
                    else
                    {
                        // session rejected message?
                        // TBD - handle this better
                        zmq_assert(false);
                    }
                }
                // else message was accepted.
                msg_ready_list.Remove(*rxState);
                if (rxState->IsRxReady())  // Move back to "rx_ready" list to read more data
                    rx_ready_list.Append(*rxState);
                else  // Move back to "rx_pending" list until NORM_RX_OBJECT_UPDATED
                    msg_ready_list.Append(*rxState);
            }  // end while(NULL != (rxState = iterator.GetNextItem()))
        }  // end if (zmq_input_ready)
    }  // end while ((!rx_ready_list.empty() || (zmq_input_ready && !msg_ready_list.empty()))

    // Alert zmq of the messages we have pushed up
    zmq_session->flush();

}  // end zmq::norm_engine_t::recv_data()

zmq::norm_engine_t::NormRxStreamState::NormRxStreamState(NormObjectHandle normStream,
                                                         int64_t          maxMsgSize)
 : norm_stream(normStream), max_msg_size(maxMsgSize),
   in_sync(false), rx_ready(false), zmq_decoder(NULL), skip_norm_sync(false),
   buffer_ptr(NULL), buffer_size(0), buffer_count(0),
   prev(NULL), next(NULL), list(NULL)
{
}

zmq::norm_engine_t::NormRxStreamState::~NormRxStreamState()
{
    if (NULL != zmq_decoder)
    {
        delete zmq_decoder;
        zmq_decoder = NULL;
    }
    if (NULL != list)
    {
        list->Remove(*this);
        list = NULL;
    }
}

bool zmq::norm_engine_t::NormRxStreamState::Init()
{
    in_sync = false;
    skip_norm_sync = false;
    if (NULL != zmq_decoder) delete zmq_decoder;
    // Note "in_batch_size" comes from config.h
    zmq_decoder = new (std::nothrow) v2_decoder_t (in_batch_size, max_msg_size);
    alloc_assert (zmq_decoder);
    if (NULL != zmq_decoder)
    {
        buffer_count = 0;
        buffer_size = 0;
        zmq_decoder->get_buffer(&buffer_ptr, &buffer_size);
        return true;
    }
    else
    {
        return false;
    }
}  // end zmq::norm_engine_t::NormRxStreamState::Init()

// This decodes any pending data sitting in our stream decoder buffer
// It returns 1 upon message completion, -1 on error, 1 on msg completion
int zmq::norm_engine_t::NormRxStreamState::Decode()
{
    // If we have pending bytes to decode, process those first
    while (buffer_count > 0)
    {
        // There's pending data for the decoder to decode
        size_t processed = 0;

        // This a bit of a kludgy approach used to weed
        // out the NORM ZMQ message transport "syncFlag" byte
        // from the ZMQ message stream being decoded (but it works!)
        if (skip_norm_sync)
        {
            buffer_ptr++;
            buffer_count--;
            skip_norm_sync = false;
        }

        int rc = zmq_decoder->decode(buffer_ptr, buffer_count, processed);
        buffer_ptr += processed;
        buffer_count -= processed;
        switch (rc)
        {
            case 1:
                // msg completed
                if (0 == buffer_count)
                {
                    buffer_size = 0;
                    zmq_decoder->get_buffer(&buffer_ptr, &buffer_size);
                }
                skip_norm_sync = true;
                return 1;
            case -1:
                // decoder error (reset decoder and state variables)
                in_sync = false;
                skip_norm_sync = false;  // will get consumed by norm sync check
                Init();
                break;

            case 0:
                // need more data, keep decoding until buffer exhausted
                break;
        }
    }
    // Reset buffer pointer/count for next read
    buffer_count = 0;
    buffer_size = 0;
    zmq_decoder->get_buffer(&buffer_ptr, &buffer_size);
    return 0;  //  need more data

}  // end zmq::norm_engine_t::NormRxStreamState::Decode()

zmq::norm_engine_t::NormRxStreamState::List::List()
 : head(NULL), tail(NULL)
{
}

zmq::norm_engine_t::NormRxStreamState::List::~List()
{
    Destroy();
}

void zmq::norm_engine_t::NormRxStreamState::List::Destroy()
{
    NormRxStreamState* item = head;
    while (NULL != item)
    {
        Remove(*item);
        delete item;
        item = head;
    }
}  // end zmq::norm_engine_t::NormRxStreamState::List::Destroy()

void zmq::norm_engine_t::NormRxStreamState::List::Append(NormRxStreamState& item)
{
    item.prev = tail;
    if (NULL != tail)
        tail->next = &item;
    else
        head = &item;
    item.next = NULL;
    tail = &item;
    item.list = this;
}  // end zmq::norm_engine_t::NormRxStreamState::List::Append()

void zmq::norm_engine_t::NormRxStreamState::List::Remove(NormRxStreamState& item)
{
    if (NULL != item.prev)
        item.prev->next = item.next;
    else
        head = item.next;
    if (NULL != item.next)
        item.next ->prev = item.prev;
    else
        tail = item.prev;
    item.prev = item.next = NULL;
    item.list = NULL;
}  // end zmq::norm_engine_t::NormRxStreamState::List::Remove()

zmq::norm_engine_t::NormRxStreamState::List::Iterator::Iterator(const List& list)
 : next_item(list.head)
{
}

zmq::norm_engine_t::NormRxStreamState* zmq::norm_engine_t::NormRxStreamState::List::Iterator::GetNextItem()
{
    NormRxStreamState* nextItem = next_item;
    if (NULL != nextItem) next_item = nextItem->next;
    return nextItem;
}  // end zmq::norm_engine_t::NormRxStreamState::List::Iterator::GetNextItem()


#endif // ZMQ_HAVE_NORM
