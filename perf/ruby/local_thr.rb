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
class Context
end

class Socket
end

class AssertionFailure < StandardError
end

def assert(bool, message = 'assertion failure')
    raise AssertionFailure.new(message) unless bool
end

	if ARGV.length != 3
		puts "usage: local_thr <in-interface> <message-size>" + \
		" <message-count>"
        Process.exit
    end

	in_interface = ARGV[0]
   	message_size = ARGV[1]
	message_count = ARGV[2]
	
	#  Print out the test parameters.
    puts "message size: " + message_size.to_s + " [B]"
	puts "message count: " + message_count.to_s
						
	#  Create 0MQ transport.
    rb_zmq = Zmq.new();
    
    #  Create context.
	context = rb_zmq.context(1, 1);    
    	    
    #  Create the socket.
	in_socket = rb_zmq.socket(context, ZMQ_SUB);
		
   	#  Connect.
   	rb_zmq.connect(in_socket, in_interface.to_s);
   	
   	#  Receive first message
    data = rb_zmq.recv(in_socket, ZMQ_NOBLOCK);
    assert(rb_zmq.msg_size(data.msg) == message_size.to_i)
	    
    #  Get initial timestamp.
    start_time = Time.now
       
    #  The message loop.
    for i in 0...message_count.to_i-1 do
    	data = rb_zmq.recv(in_socket, ZMQ_NOBLOCK);
    	assert(rb_zmq.msg_size(data.msg) == message_size.to_i)
    end
 
    #  Get terminal timestamp.
    end_time = Time.now
    
    #  Compute and print out the throughput.
    if end_time.to_f - start_time.to_f != 0
    	message_throughput = message_count.to_i / 
    		(end_time.to_f - start_time.to_f);
    else
    	message_throughput = message_count.to_i
    end
    
    megabit_throughput = message_throughput.to_f * message_size.to_i * 8 /
       1000000;
    puts "Your average throughput is " + "%0.2f" % message_throughput.to_s + 
    	" [msg/s]"
    puts "Your average throughput is " + "%0.2f" % megabit_throughput.to_s + 
    	" [Mb/s]"    


