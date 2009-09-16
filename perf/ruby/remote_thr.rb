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

if ARGV.length != 3
	puts "usage: remote_thr <connect-to> <message-size> <message-count>"
	Process.exit
end
    
connect_to = ARGV[0]
message_size = ARGV[1].to_i
message_count = ARGV[2].to_i
			
ctx = Context.new(1, 1)
s = Socket.new(ctx, PUB);

#  Add your socket options here.
#  For example ZMQ_RATE, ZMQ_RECOVERY_IVL and ZMQ_MCAST_LOOP for PGM.

s.connect(connect_to);

msg = "#{'0'*message_size}"

for i in 0...message_count do
	s.send(msg, 0)
end

sleep 10

