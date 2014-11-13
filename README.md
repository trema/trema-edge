Welcome to Trema-Edge
=====================

[![Build Status](https://travis-ci.org/trema/trema-edge.png?branch=master)](https://travis-ci.org/trema/trema-edge)
[![Code Climate](https://codeclimate.com/github/trema/trema-edge.png)](https://codeclimate.com/github/trema/trema-edge)
[![Dependency Status](https://gemnasium.com/trema/trema-edge.png)](https://gemnasium.com/trema/trema-edge)
[![Coverage Status](https://coveralls.io/repos/trema/trema-edge/badge.png?branch=master)](https://coveralls.io/r/trema/trema-edge)

This is a temporary repository that we create in order to receive some
valuable feedback from our users. In the future we are planning to
merge this repository into the current trema repository.


## Trema for OpenFlow 1.3.X

We have already developed source that implements the OpenFlow 1.3.0
specification and the newest OpenFlow version 1.3.1.
The current implementation was C only but we also releasing a Ruby
implementation.
Trema for OpenFlow 1.3.X does not support OpenFlow version 1.0.

Implementation status:

* `trema command`: works, all irrelevant commands have been removed.
* `ruby/trema`: works Ruby controller
* `libtrema`: works
* `switch_manager, switch daemon`: works
* `tremashark`: not yet implemented
* `src/examples/dumper`: works (C only)
* `src/examples/hello_trema`: works (both C and Ruby)
* `src/examples/list_switches`: works (C only)
* `src/examples/learning_switch`: works (both C and Ruby)
* `src/examples/multi_learning_switch`: works (both C and Ruby)
* `src/examples/openflow_message`: works (C only)
* `src/examples/packet_in`: works (both C and Ruby)
* `src/examples/repeater_hub`: works (both C and Ruby)
* `src/examples/simple_router`: works (Ruby only)
* `src/examples/switch_info`: works (both C and Ruby)
* `src/examples/switch_monitor`: works (C only)
* `src/examples/traffic_monitor`: works (both C and Ruby)
* `trema apps`: not work
* `features`: not work
* `spec`: not work

The `./trema ruby` not updated yet to include trema edge's API documentation and
currently displays the trema's API documentation.

The Ruby controller implements most of the messages except the following:

* Experimenter
* Queue-get-config/request/reply
* Role-request/reply
* Get-async-requet/reply
* Meter-mod


## Tested platforms

* Ruby 2.0.0 (1.8.x is NOT supported)
* Ubuntu 12.04 (amd64)

It may also run on other GNU/Linux distributions but is not tested.


## Required Packages

### Ruby

This repository has only been tested with ruby 2.0.0 (maybe with
1.9.3) and will not work with 1.8.x. We recommend installation of the
rvm program for easy installation of ruby 2.0.0.


### Other packages

    % sudo apt-get install gcc make libpcap-dev libssl-dev

## Build Trema

    % gem install bundler
    % bundle install
    % rake


## Run the Ruby learning switch

    % ./trema run src/examples/learning_switch/learning-switch.rb -c src/examples/learning_switch/learning_switch.conf


## How to build your own Ruby controller application

    % mkdir work
    % cd work
    % vi sample.rb
    ..
    % cat sample.rb
    class Sample < Controller
      def switch_ready datapath_id
        # as an example create a flow to receive all packet-ins from port 1
        redirect_action = SendOutPort.new( port_number: OFPP_CONTROLLER, max_len: OFPCML_NO_BUFFER )
        apply_ins = ApplyAction.new( actions:  [ redirect_action ] )
        match = Match.new( in_port: 1 )
        send_flow_mod_add( datapath_id,
                           priority: OFP_LOW_PRIORITY,
                           buffer_id: OFP_NO_BUFFER,
                           match: match,
                           instructions: [ apply_ins ] )
    
      end
      def packet_in datapath_id, message
        # print the packet-in message instance
        puts message.inspect
      end
    end
    
    % cat sample.conf
    trema_switch( "lsw" ) {
      datapath_id "0xabc"
    }
    
    vhost ("host1") {
      ip "192.168.0.1"
      netmask "255.255.0.0"
      mac "00:00:00:01:00:01"
    }
    
    vhost ("host2") {
      ip "192.168.0.2"
      netmask "255.255.0.0"
      mac "00:00:00:01:00:02"
    }
    
    link "host1", "lsw:1"
    link "host2", "lsw:2"

The above DSL would create 2 ports and link each port to learning trema switch.
Since trema switch doesn't depend on an existence of a virtual network to function
it is possible to define trema switch's ports explicitly by using the ports attribute
in the trema_switch directive block.

    % cat sample.conf
    trema_switch( "lsw" ) {
      datapath_id "0xabc"
      ports "eth0,eth1"
    }

Define the above syntax only if you are not using a virtual network for your testing
otherwise use the link directive to define trema switch's virtual ports dynamically
which is the effortless and easy way.


## To run the controller

    % ./trema run work/sample.rb -c work/sample.conf


## How to build your own C controller application

### To build

    % mkdir work
    % cd work
    % vi sample.c
    ..
    % cat sample.c
    #include <inttypes.h>
    #include "trema.h"
    
    static void
    handle_switch_ready( uint64_t datapath_id, void *user_data ) {
      info( "Hello %#" PRIx64 " from %s!", datapath_id, user_data );
      stop_trema();
    }
    
    int
    main( int argc, char *argv[] ) {
      init_trema( &argc, &argv );
    
      set_switch_ready_handler( handle_switch_ready, argv[ 0 ] );
    
      start_trema();
    
      return 0;
    }
    % cc `../trema-config -c` -o sample sample.c `../trema-config -l`
    
    % cat sample.conf
    trema_switch( "lsw" ) {
      datapath_id "0xabc"
    }
    
    vhost ("host1") {
      ip "192.168.0.1"
      netmask "255.255.0.0"
      mac "00:00:00:01:00:01"
    }
    
    vhost ("host2") {
      ip "192.168.0.2"
      netmask "255.255.0.0"
      mac "00:00:00:01:00:02"
    }
    
    link "host1", "lsw:1"
    link "host2", "lsw:2"
    
    % cd ..

### To start the C controller

    % ./trema run work/sample -c work/sample.conf
    
If sucessfully run should observe the following:

    Hello 0xabc from work/sample!
    
To stop the controller

    % Press Ctrl-c.


# About OpenFlow 1.3.0

## Notable modifications

+ Multiple tables, groups support (Setting of multiple tables, groups).
+ Extensible match support. (Extensible match support applicable to MPLS and IPv6 match setting).
+ Extensible packet rewrite support. (Extensible packet rewrite support applicable to MPLS and IPv6).

+ Support for added packet-in contents. (Support for additional cookie and match fields).

## Frequently used packets expanded hence processing time increased.

+ The packet-in has been expanded to include the cookie and the match fields.
+ The `flow_mod` that had only match+actions has been expanded to match+instructions+actions.


## Unsupported

+ The cookie mask is to be used in `flow_mod` modify/delete and `flow_stats_request` and
  `aggregate_stats_request`. As currently trema does the cookie translation it is a problem.


## Differences seen by applications

+ `Flow_mod` is necessary after switch connection establishment since the default packet-in is not sent.
+ Since the cookie field is attached to packet-in the application can also attach it to `flow_mod`.
+ It is necessary to search for the `in_port` included in the match of the packet-in.
+ Since the features reply doesn't include port information it is necessary to use a different method to retrieve. (`OFPT_MULTIPART_REQUEST`)


## Ambiguous specification items

- undefined structure
    - p.44: `ofp_instruction_experimenter`
    - p.65,66: `ofp_table_feature_prop_header` and `ofp_table_feature_prop_experimenter`
    - p.66: `ofp_instruction`
- undefined macro
    - p.54: `OFPTC_*`
    - p.69: `OFPQ_ALL`
    - p.70: `OFPG_ANY` and `OFPG_ALL`
- typo
    - p.43: `OFPXMT_OFP_MPLS_BOS` -> `OFPXMT_OFB_MPLS_BOS`
    - p.83: `OFPQCFC_EPERM` -> `OFPSCFC_EPERM`
    - p.38: `OFPQT_MIN` -> `OFPQT_MIN_RATE` and `OFPQT_MAX` -> `OFPQT_MAX_RATE`
    - p.75: `NX_ROLE_` -> `OFPCR_ROLE_`
    - p.72: `/* All OFPMC_* that apply. */` -> `/* All OFPMF_* that apply. */`
- added macro
    - `OFP_DEFAULT_PRIORITY`
    - `OFP_DEFAULT_MISS_SEND_LEN`


License
-------

Trema is released under the GNU General Public License version 2.0:

* http://www.gnu.org/licenses/gpl-2.0.html
