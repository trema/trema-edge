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
  #
  # @abstract
  #

  class Tasks
    def initialize
      @lock = Mutex.new
      @wakeup, @waker = IO.pipe
      @tasks = []

      queue_readable(@wakeup.fileno)
    end

    def close
      unqueue_readable(@wakeup.fileno)
      @wakeup.close
      @waker.close
    end

    def pass_task(&block)
      return if block.nil?

      @lock.synchronize do
        @tasks << block
        @waker.write('\0') if @tasks.size < 2
      end
    end

    private

    def consume_tasks
      current_tasks = nil

      @lock.synchronize do
        current_tasks = @tasks
        @tasks = []
        @wakeup.read(1)
      end

      current_tasks.each(&:call)
    end
  end
end
