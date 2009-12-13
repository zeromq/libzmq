if BUILD_FORWARDER
FORWARDER_DIR = zmq_forwarder
endif

if BUILD_STREAMER
STREAMER_DIR = zmq_streamer
endif

if BUILD_QUEUE
QUEUE_DIR = zmq_queue
endif

SUBDIRS = $(FORWARDER_DIR) $(STREAMER_DIR) $(QUEUE_DIR)
DIST_SUBDIRS = zmq_forwarder zmq_streamer zmq_queue
