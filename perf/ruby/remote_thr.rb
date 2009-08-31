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

	if ARGV.length != 3
		puts "usage: remote_thr <out-interface> <message-size> <message-count>"
		Process.exit
    end
        
	out_interface = ARGV[0]
	message_size = ARGV[1]
	message_count = ARGV[2]
				
	#  Create 0MQ transport.
    rb_zmq = Zmq.new();
    
    #  Create the wiring.
    context = rb_zmq.context(1,1);
    out_socket = rb_zmq.socket(context, ZMQ_PUB);
    rb_zmq.bind(out_socket, out_interface.to_s);
	    
    #  Create message data to send.
	out_msg = rb_zmq.msg_init_size(message_size.to_s);
	
	#  The message loop.
    for i in 0...message_count.to_i + 1 do
    	rb_zmq.send(out_socket, out_msg, ZMQ_NOBLOCK);
   	end
   	
    #  Wait till all messages are sent.
    sleep 2
    
