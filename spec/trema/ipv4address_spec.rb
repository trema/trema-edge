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
require "trema/ipv4address"


describe IPv4Address, ".new( ip_address )" do
  subject { IPv4Address.new( ip_address ) }


  context "when 10.1.1.1" do
    let( :ip_address ) { "10.1.1.1" }

    its( :to_s ) { should == "10.1.1.1" }
    its( :to_i ) { should == ( ( 10 * 256 + 1 ) * 256 + 1 ) * 256 + 1 }
    its( :to_array ) { should == [ 0x0a, 0x01, 0x01, 0x01 ] }
    its( :class_a? ) { should == true }
    its( :class_b? ) { should == false }
    its( :class_c? ) { should == false }
    its( :class_d? ) { should == false }
    its( :class_e? ) { should == false }
    its( :unicast? ) { should == true }
    its( :multicast? ) { should == false }
  end


  context "when 172.20.1.1" do
    let( :ip_address ) { "172.20.1.1" }

    its( :to_s ) { should == "172.20.1.1" }
    its( :to_i ) { should == ( ( 172 * 256 + 20 ) * 256 + 1 ) * 256 + 1 }
    its( :to_array ) { should == [ 0xac, 0x14, 0x01, 0x01 ] }
    its( :class_a? ) { should == false }
    its( :class_b? ) { should == true }
    its( :class_c? ) { should == false }
    its( :class_d? ) { should == false }
    its( :class_e? ) { should == false }
    its( :unicast? ) { should == true }
    its( :multicast? ) { should == false }
  end


  context "when 192.168.1.1" do
    let( :ip_address ) { "192.168.1.1" }

    its( :to_s ) { should == "192.168.1.1" }
    its( :to_i ) { should == 3232235777 }
    its( :to_array ) { should == [ 0xc0, 0xa8, 0x01, 0x01 ] }
    its( :class_a? ) { should == false }
    its( :class_b? ) { should == false }
    its( :class_c? ) { should == true }
    its( :class_d? ) { should == false }
    its( :class_e? ) { should == false }
    its( :unicast? ) { should == true }
    its( :multicast? ) { should == false }
  end


  context "when 234.1.1.1" do
    let( :ip_address ) { "234.1.1.1" }

    its( :to_s ) { should == "234.1.1.1" }
    its( :to_i ) { should == ( ( 234 * 256 + 1 ) * 256 + 1 ) * 256 + 1 }
    its( :to_array ) { should == [ 0xea, 0x01, 0x01, 0x01 ] }
    its( :class_a? ) { should == false }
    its( :class_b? ) { should == false }
    its( :class_c? ) { should == false }
    its( :class_d? ) { should == true }
    its( :class_e? ) { should == false }
    its( :unicast? ) { should == false }
    its( :multicast? ) { should == true }
  end
end


describe IPv4Address, ".mask!( mask )" do
  subject { IPv4Address.new( ip_address ).mask!( mask ) }

  let( :ip_address ) { "10.1.1.1" }
  let( :mask ) { 8 }

  its( :to_s ) { should == "10.0.0.0" }
  its( :to_i ) { should == 10 * 256 * 256 * 256 }
  its( :to_array ) { should == [ 0x0a, 0x00, 0x00, 0x00 ] }
  its( :class_a? ) { should == true }
  its( :class_b? ) { should == false }
  its( :class_c? ) { should == false }
  its( :class_d? ) { should == false }
  its( :class_e? ) { should == false }
  its( :unicast? ) { should == true }
  its( :multicast? ) { should == false }
end


### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
