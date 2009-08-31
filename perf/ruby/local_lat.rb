#
#    Copyright (c) 2007-2009 FastMQ Inc.
#
#    This file is part of 0MQ.
#
#    0MQ is free software; you can redistribute it and/or modify it under
#    the terms of the Lesser GNU General Public License as published by
#    the Free Software Foundation; either version 3 of the License, or
#    (at your option) any later version.
#
#    0MQ is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    Lesser GNU General Public License for more details.
#
#    You should have received a copy of the Lesser GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

require 'librbzmq'

class AssertionFailure < StandardError
end

def assert(bool, message = 'assertion failure')
    raise AssertionFailure.new(message) unless bool
end

	if ARGV.length != 4
		puts "usage: local_lat <in-interface> <out-interface> <message-size>
		<roundtrip-count>"
		Process.exit
    end
        
	in_interface = ARGV[0]
	out_interface = ARGV[1]
	message_size = ARGV[2]
	roundtrip_count = ARGV[3]
				
	#  Print out the test parameters.
    puts "message size: #{message_size} [B]"
    puts "roundtrip count: #{roundtrip_count}"

	#  Create 0MQ transport.
    rb_zmq = Zmq.new()
    
    #  Create the wiring.
    context = rb_zmq.context(1,1)
    in_socket = rb_zmq.socket(context, ZMQ_SUB)
    out_socket = rb_zmq.socket(context, ZMQ_PUB)
    
    #  Bind.
    rb_zmq.bind(in_socket, in_interface.to_s)
    rb_zmq.bind(out_socket, out_interface.to_s)

    #  Create message data to send.
	out_msg = rb_zmq.msg_init_size(message_size.to_i)
		
   	#  Get initial timestamp.
    start_time = Time.now

	#  The message loop.
    for i in 0...roundtrip_count.to_i do
		rb_zmq.send(out_socket, out_msg, ZMQ_NOBLOCK)
		in_buf = rb_zmq.recv(in_socket, ZMQ_NOBLOCK)
        assert(rb_zmq.msg_size(in_buf.msg) == message_size.to_i)
   	end

    #  Get final timestamp.
  	end_time = Time.now

    #  Compute and print out the latency.
    latency = (end_time.to_f - start_time.to_f) *1000000 / 
    	roundtrip_count.to_i / 2
    puts "Your average latency is " +  "%0.2f" % latency  + "[us]"
    
