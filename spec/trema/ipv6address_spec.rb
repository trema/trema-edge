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


require File.join( File.dirname( __FILE__ ), "..", "spec_helper" )
require "trema/ipv6address"


module Trema
  describe IPv6Address do
    context "creates" do
      subject { IPv6Address.new( ipv6_address ) }

      context %{when "2001:db8::1"} do
        let( :ipv6_address ) { "2001:db8::1" }

        its( :to_s ) { should == "2001:db8::1" }
        its( :to_i ) { should == 42540766411282592856903984951653826561 }
        its( :to_array ) { should == [ 0x20, 0x01, 0x0d, 0xb8,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x01 ] }
        its( :unspecified? ) { should == false }
        its( :loopback? ) { should == false }
        its( :multicast? ) { should == false }
        its( :link_local_unicast? ) { should == false }
        its( :global_unicast? ) { should == true }
        its( :unicast? ) { should == true }
      end
    end


    context "masks" do
      subject { IPv6Address.new( ipv6_address ).prefix( prefixlen ) }

      context %{when "2001:db8:dead:beef::1"} do
        let( :ipv6_address ) { "2001:db8:dead:beef::1" }
        let( :prefixlen ) { 32 }

        its( :to_s ) { should == "2001:db8::" }
        its( :to_i ) { should == 42540766411282592856903984951653826560 }
        its( :to_array ) { should == [ 0x20, 0x01, 0x0d, 0xb8,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00 ] }
      end
    end


    context "addressing" do
      subject { IPv6Address.new( ipv6_address ) }

      context %{when unspecified address} do
        let( :ipv6_address ) { "::" }

        its( :to_s ) { should == "::" }
        its( :to_i ) { should == 0 }
        its( :to_array ) { should == [ 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00 ] }
        its( :unspecified? ) { should == true }
        its( :loopback? ) { should == false }
        its( :multicast? ) { should == false }
        its( :link_local_unicast? ) { should == false }
        its( :global_unicast? ) { should == false }
        its( :unicast? ) { should == false }
      end


      context %{when loopback address} do
        let( :ipv6_address ) { "::1" }

        its( :to_s ) { should == "::1" }
        its( :to_i ) { should == 1 }
        its( :to_array ) { should == [ 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x01 ] }
        its( :unspecified? ) { should == false }
        its( :loopback? ) { should == true }
        its( :multicast? ) { should == false }
        its( :link_local_unicast? ) { should == false }
        its( :global_unicast? ) { should == false }
        its( :unicast? ) { should == false }
      end


      context %{when multicast address} do
        let( :ipv6_address ) { "ff02::1" }

        its( :to_s ) { should == "ff02::1" }
        its( :to_array ) { should == [ 0xff, 0x02, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x01 ] }
        its( :unspecified? ) { should == false }
        its( :loopback? ) { should == false }
        its( :multicast? ) { should == true }
        its( :link_local_unicast? ) { should == false }
        its( :global_unicast? ) { should == false }
        its( :unicast? ) { should == false }
      end


      context %{when link-local address} do
        let( :ipv6_address ) { "fe80::1:1" }

        its( :to_s ) { should == "fe80::1:1" }
        its( :to_array ) { should == [ 0xfe, 0x80, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x01, 0x00, 0x01 ] }
        its( :unspecified? ) { should == false }
        its( :loopback? ) { should == false }
        its( :multicast? ) { should == false }
        its( :link_local_unicast? ) { should == true }
        its( :global_unicast? ) { should == false }
        its( :unicast? ) { should == true }
      end
    end
  end
end


### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
