# Directory structure

New to trema-edge are the following subdirectories containing implementation files
for the Ruby controller. Because retrospection is used for method dispatching
or for defining accessor attributes the contents of those files should not carelessly modified.
All classes can be referenced by prefixing the full module name or by just their name.
For example `Trema::Instructions::WriteAction` is equivalent to `WriteAction`.

## Messages
All messages that the Ruby controller supports can be found under
the directory `messages`. Messages are logically separated into requests and
replies. For each message there is a ruby class file that holds the attributes
describing it. This message object can be instantiated by calling its constructor
supplying a hash of key/value arguments. An equivalent message C file provides
pack and unpack functions to be able to transmit and receive the message
to/from the lower layers. A user can send a message by calling the `send_message`
method passing an instantiated message instance to be sent. Or alternative using its helper
method. In this case the user supplies message arguments using a hash if required.
A single message request may span into multiple replies and is left to the user to aggregate
those replies in whatever manner it wishes. A message attribute in a form of a flag
signals the last message reception that can be inspected and take appropriate action.
For all multipart reply messages the Ruby controller would deliver a separate handler for
each type.


### Message example
For example to enable the controller to receive all lldp messages from port 1
you would create a flow that might look like the following:

```
action = SendOutPort.new( port_number: OFPP_CONTROLLER, max_len: OFPCML_NO_BUFFER ) 
apply_ins = ApplyAction.new( actions:  [ action ] ) 
match = Match.new( in_port: 1, eth_type: 0x88cc )
send_flow_mod_add( datapath_id,
                   priority: OFP_LOW_PRIORITY,
                   buffer_id: OFP_NO_BUFFER,
                   match: match,
                   instructions: [ apply_ins ] )
```
To receive the packet in just declare the handler:

```
def packet_in datapath_id, message
  # dumping the lldp packet
  puts message.inspect
  #<Trema::Messages::PacketIn:0xab42710 @datapath_id=2748, @buffer_id=1, @total_len=153, @reason=1, @table_id=0, @cookie=1, 
  @match=#<Trema::Match:0xab23428 @in_port=1, @eth_type=35020>, 
  @data=[1, 128, ...], @packet_info=#<Trema::Messages::PacketInfo:0xab32a18 
  @eth_src=a2:85:d8:f9:d1:ce, @eth_dst=01:80:c2:00:00:0e, @eth_type=35020, 
  @ip_dscp=nil, @ip_ecn=nil, @vtag=false, @ipv4=false, @ipv6=false, @arp=false, @mpls=false, @pbb=false>>
end
```
Other messages can be created in similar manner.

## Actions
This directory contains a list of all of what we call basic and flexible actions.
The basic actions map to actions of type `OFPAT_xxx` and flexible actions are
the extensible actions of `OXM_xxx` type.
Action objects can be instantiated and passed as argements to instructions or
match objects.

## Instructions
This directory contains a list of all instructions. Please note although the
`meter` instruction is defined its implementation is not supported.
