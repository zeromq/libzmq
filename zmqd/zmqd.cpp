/*
    Copyright (c) 2007-2010 iMatix Corporation

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

#include <vector>
#include <string>
#include <memory>

#include "../include/zmq.hpp"
#include "../foreign/xmlParser/xmlParser.cpp"

namespace {

    class device_cfg_t
    {

        enum endpoint_direction {connect, bind};

        typedef std::pair<endpoint_direction, std::string> sock_details_t;

        typedef std::vector<sock_details_t> vsock_dets_t;

    public:

        explicit device_cfg_t(int type)
                : device_type(type) , context(0) 
                , in_socket(0), out_socket(0)
        {
        }

        virtual ~device_cfg_t()
        {
            delete out_socket;
            delete in_socket;
        }

        bool  init(XMLNode& device)
        {

            XMLNode in_node = device.getChildNode ("in");
            if (in_node.isEmpty ()) {
                fprintf (stderr, "'in' node is missing in the configuration file\n");
                return false;
            }

            XMLNode out_node = device.getChildNode ("out");
            if (out_node.isEmpty ()) {
                fprintf (stderr, "'out' node is missing in the configuration file\n");
                return false;
            }

            if (!process_node(in_node,true,device_cfg_t::bind))
                return false;
            if (!process_node(in_node,true,device_cfg_t::connect))
                return false;
            if (!process_node(out_node,false,device_cfg_t::bind))
                return false;
            if (!process_node(out_node,false,device_cfg_t::connect))
                return false;

            return true;
        }

        void set_context(zmq::context_t* context_)
        {
            context = context_;
        }

        zmq::context_t *get_context() const
        {
            return context;
        }

        virtual bool make_sockets() = 0;

        bool set_up_connections()
        {
            for (vsock_dets_t::const_iterator i = in.begin() ; i != in.end();
                  ++i) {

                switch (i->first)
                {
                    case device_cfg_t::connect :
                        in_socket->connect(i->second.c_str());
                        break;
                    case device_cfg_t::bind :
                        in_socket->bind(i->second.c_str());
                }
            
            }

            for (vsock_dets_t::const_iterator i = out.begin() ; i != out.end();
                  ++i) {

                switch (i->first)
                {
                    case device_cfg_t::connect :
                        out_socket->connect(i->second.c_str());
                        break;
                    case device_cfg_t::bind :
                        out_socket->bind(i->second.c_str());
                }

            }
            return true;
        }

        void run() 
        {
            zmq::device(device_type, *in_socket, *out_socket);
        }


    protected:

        bool make_sockets(int in_type, int out_type)
        {
            in_socket = new (std::nothrow) zmq::socket_t(*context, in_type);
            if (!in_socket) 
                return false;
            out_socket = new (std::nothrow) zmq::socket_t(*context, out_type);
            if (!out_socket) {
                return false;
            }
            return true;
        }

        int process_node(XMLNode& target_, bool in_,
            device_cfg_t::endpoint_direction ept_)
        {

            const char * name =
                (ept_ == device_cfg_t::connect) ? "connect" : "bind";
            int n = 0;
            while (true) {
                XMLNode connect = target_.getChildNode (name, n);
                if (connect.isEmpty ())
                    break;
                const char *addr = connect.getAttribute ("addr");
                if (!addr) {
                    fprintf (stderr, "'%s' node is missing 'addr' attribute\n",
                        name);
                    return 0;
                }

                if (in_) 
                    in.push_back( sock_details_t(ept_, addr));
                else
                    out.push_back( sock_details_t(ept_, addr));

                n++;
            }

            return 1;
        }


    protected:

        int device_type;
        zmq::context_t* context;
        vsock_dets_t in;
        vsock_dets_t out;
        zmq::socket_t* in_socket;
        zmq::socket_t* out_socket;

    private:
        void operator = (device_cfg_t const &);
        device_cfg_t(device_cfg_t const &);
    };



    class queue_device_cfg_t : public device_cfg_t
    {
    public:
        queue_device_cfg_t()
                : device_cfg_t(ZMQ_QUEUE)
        {}
        virtual bool make_sockets(){
            return device_cfg_t::make_sockets(ZMQ_XREP, ZMQ_XREQ);
        }
    };


    class streamer_device_cfg_t : public device_cfg_t
    {
    public:
        streamer_device_cfg_t()
                : device_cfg_t(ZMQ_STREAMER)
        {}
        virtual bool make_sockets () {
            return device_cfg_t::make_sockets(ZMQ_UPSTREAM, ZMQ_DOWNSTREAM);
        }
    };

    class forwarder_device_cfg_t : public device_cfg_t
    {
    public:
        forwarder_device_cfg_t()
                : device_cfg_t(ZMQ_FORWARDER)
        {}
        virtual bool make_sockets() {
            if (!device_cfg_t::make_sockets(ZMQ_SUB, ZMQ_PUB) ) {
                return false;
            }
            in_socket->setsockopt (ZMQ_SUBSCRIBE, "", 0);
            return true;
        }
    };


    device_cfg_t* make_device_config(XMLNode& device)
    {
        const char *dev_type = device.getAttribute ("type");

        if (!dev_type) {
            fprintf (stderr, "'device' node is missing 'type' attribute\n");
            return NULL;
        }

        if (strcmp (dev_type, "forwarder") == 0) {
            return new (std::nothrow) forwarder_device_cfg_t;
        }
        else if (strcmp (dev_type, "streamer") == 0) {
            return new (std::nothrow) streamer_device_cfg_t;
        }
        else if (strcmp (dev_type, "queue") == 0) {
            return new (std::nothrow) queue_device_cfg_t;
        }
        
        fprintf (stderr, "type attribute in the device configuration file "
                 "should be named 'forwarder', 'streamer' or 'queue'\n");

        return NULL;
    }


    extern "C" void* worker_function(void *arg)
    {

        if (!arg) {
            fprintf (stderr, "arg is null, returning \n");
            return 0;
        }

        std::auto_ptr<device_cfg_t> cfg ( (device_cfg_t*) arg );

        zmq::context_t* ctx = cfg->get_context();

        if (!ctx) {
            fprintf (stderr, "no context, returning \n");
            return 0;
        }

        if (! cfg->make_sockets()) {
            fprintf (stderr, "failed to make sockets, returning \n");
            return 0;
        }


        if (! cfg->set_up_connections()) {
            fprintf (stderr, "failed to set up connections, returning \n");
            return 0;         
        }

        cfg->run();

        return 0;

    }


}


int main (int argc, char *argv [])
{
    if (argc != 2) {
        fprintf (stderr, "usage: zmqd <config-file>\n");
        return 1;
    }

    XMLNode root = XMLNode::parseFile (argv [1]);

    if (root.isEmpty ()) {
        fprintf (stderr, "configuration file not found or not an XML file\n");
        return 1;
    }

    if (strcmp (root.getName (), "config") != 0) {
        fprintf (stderr, "root element in the configuration file should be "
            "named 'config'\n");
        return 1;
    }


    std::vector<device_cfg_t*> vdev;

    while (true) {

        XMLNode device = root.getChildNode ("device", vdev.size());

        if (device.isEmpty())
            break;

        device_cfg_t* dev = make_device_config(device);

        if (!dev) {
            fprintf(stderr, "failed to create device config\n");
            return 1;
        }
        
        if (! dev->init(device) ) {

            fprintf(stderr,"error with initialising device configuration\n");
            delete dev;
            return 1;
        }
    
        vdev.push_back(dev);
    }

    std::vector<device_cfg_t*>::size_type num_devices = vdev.size();

    if ( num_devices == 0 ) {
        fprintf(stderr,"no devices in the config file\n");
        return 1;
    }


    zmq::context_t ctx (num_devices,1);


    for (unsigned int i = 0 ; i < num_devices ; ++i) {

        vdev[i]->set_context(&ctx);
        
        if (i)  {
            pthread_t worker;
            int rc = pthread_create (&worker, NULL, &worker_function,
                (void*) vdev[i]);
            assert (rc == 0);
        }
    }


    worker_function((void*)vdev[0]);


    return 0;
}

