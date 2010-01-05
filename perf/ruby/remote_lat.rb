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
	puts "usage: remote_lat <connect-to> <message-size> <roundtrip-count>"
    Process.exit
end

connect_to = ARGV[0]
message_size = ARGV[1].to_i
roundtrip_count = ARGV[2].to_i
					
ctx = Context.new(1, 1, 0)
s = Socket.new(ctx, REQ);
s.connect(connect_to);

msg = "#{'0'*message_size}"

start_time = Time.now

for i in 0...roundtrip_count do
    s.send(msg, 0)
    msg = s.recv(0)
end

end_time = Time.now

elapsed = (end_time.to_f - start_time.to_f) * 1000000
latency = elapsed / roundtrip_count / 2

puts "message size: %i [B]" % message_size
puts "roundtrip count: %i" % roundtrip_count
puts "mean latency: %.3f [us]" % latency



