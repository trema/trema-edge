#
# Copyright (C) 2008-2013 NEC Corporation
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

module Trema
  module Messages
    class GroupMultipartReply < Message
      unsigned_int16 :length, presence: true
      unsigned_int32 :group_id, :ref_count, presence: true
      unsigned_int64 :packet_count, :byte_count, presence: true
      unsigned_int32 :duration_sec, :duration_nsec, presence: true
      array :bucket_stats
    end
  end

  GroupMultipartReply = Messages::GroupMultipartReply
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
