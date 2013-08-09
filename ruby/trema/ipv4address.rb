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
  # IPv4 Address
  #
  class IPv4Address
    require "ipaddr"
    require "forwardable"
    extend Forwardable


    #
    # @return [IPAddr] value object instance of proxied IPAddr.
    #
    attr_reader :value


    #
    # Creates a {IP} instance object as a proxy to IPAddr class.
    #
    # @overload initialize(ipv4address)
    #
    # @param [String] ipv4address
    #   an IPv4 address specified either as a String or Number.
    #
    # @raise [ArgumentError] invalid address if supplied argument is invalid
    #   IPv4 address.
    #
    # @return [IP] self
    #   a proxy to IPAddr.
    #
    def initialize ipv4address
      if !ipv4address.kind_of? String
        @value = IPAddr.new( ipv4address, Socket::AF_INET )
      else
        @value = IPAddr.new( ipv4address )
      end
    end


    #
    # @return [String] the IPv4 address in its text representation.
    #
    def_delegator :value, :to_s


    #
    # @return [Number] the IPv4 address in its numeric representation.
    #
    def_delegator :value, :to_i


    #
    # @return [Array]
    #    an array of decimal numbers converted from IPv4 address.
    #
    def to_a
      to_s.split( "." ).collect do | each |
        each.to_i
      end
    end
    alias :to_array :to_a


    #
    # @return [IPv4Address]
    #   Returns the IPv4 address masked with masklen.
    #
    def mask! masklen
      @value = @value.mask( masklen )
      return self
    end
    alias :prefix! :mask!


    #
    # @return [IPv4Address]
    #   Returns the IPv4 address masked with masklen.
    #
    def mask masklen
      self.clone.mask!( masklen )
    end
    alias :prefix :mask


    #
    # @return [bool]
    #   Returns true if the address belongs to class A.
    #
    def class_a?
      mask( 1 ).to_s == "0.0.0.0"
    end


    #
    # @return [bool]
    #   Returns true if the address belongs to class B.
    #
    def class_b?
      mask( 2 ).to_s == "128.0.0.0"
    end


    #
    # @return [bool]
    #   Returns true if the address belongs to class C.
    #
    def class_c?
      mask( 3 ).to_s == "192.0.0.0"
    end


    #
    # @return [bool]
    #   Returns true if the address belongs to class D.
    #
    def class_d?
      mask( 4 ).to_s == "224.0.0.0"
    end
    alias :multicast? :class_d?


    #
    # @return [bool]
    #   Returns true if the address belongs to class E.
    #
    def class_e?
      mask( 4 ).to_s == "240.0.0.0"
    end


    #
    # @return [bool]
    #   Returns true if the address is unicast address.
    #
    def unicast?
      class_a? or class_b? or class_c?
    end
  end
end


### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
