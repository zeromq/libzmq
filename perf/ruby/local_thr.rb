#
#    Copyright (c) 2007-2010 iMatix Corporation
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

if ARGV.length != 3
	puts "usage: local_thr <bind-to> <message-size> <message-count>"
    Process.exit
end

bind_to = ARGV[0]
message_size = ARGV[1].to_i
message_count = ARGV[2].to_i
					
ctx = Context.new(1, 1, 0)
s = Socket.new(ctx, SUB);
s.setsockopt(SUBSCRIBE, "*");

#  Add your socket options here.
#  For example ZMQ_RATE, ZMQ_RECOVERY_IVL and ZMQ_MCAST_LOOP for PGM.

s.bind(bind_to);

msg = s.recv(0)
    
start_time = Time.now
   
for i in 1...message_count.to_i do
    msg = s.recv(0)
end

end_time = Time.now

elapsed = (end_time.to_f - start_time.to_f) * 1000000
if elapsed == 0
    elapsed = 1
end

throughput = message_count * 1000000 / elapsed
megabits = throughput * message_size * 8 / 1000000

puts "message size: %i [B]" % message_size
puts "message count: %i" % message_count
puts "mean throughput: %i [msg/s]" % throughput
puts "mean throughput: %.3f [Mb/s]" % megabits

