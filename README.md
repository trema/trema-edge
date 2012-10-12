# Trema edge

This is a temporary repository that we create in order to receive some
valuable feedback from our users. In the future we are planning to
merge this repository into the current trema repository.

## Trema for OpenFlow 1.3

We have already developed source that implements the OpenFlow 1.3.0
specification and we also planning to include the newer OpenFlow
version 1.3.1.
The current implementation is C only.
Trema for OpenFlow 1.3 does not support OpenFlow version 1.0.

Status of implementation:

* `trema command`: will not work
* `libtrema`: works
* `switch_manager, switch daemon`: works
* `tremashark`: not yet implemented
* `src/examples/dumper`: works (C only)
* `src/examples/learning_switch`: works (C only)
* `trema apps`: not work

## Tested platforms

* Ubuntu 12.04 (amd64)

It may also run on other GNU/Linux distributions but is not tested.

## Required Packages

To be written later on.

## Build trema

    $ git clone git://github.com/trema/trema-edge.git
    $ cd trema-edge
    $ ./build.rb

## Run learning switch

    $ ./learning_switch.sh start

    Stop learning switch
    $ ./learning_switch.sh stop

## How to build your own controller application

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
    % cd ..

### To start the controller

    % ./trema-run.sh ./work/sample start
    
    Stop controller
    % ./trema-run.sh ./work/sample stop

# About OpenFlow 1.3.0

## Notable modifications

+ Multiple tables,groups support (Setting of multiple tables, groups).
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

+ `Flow_mod` was necessary after switch connection establishment since the default packet-in was not sent.
  It might be better that packet-in is not sent until the startup sequence is completed.
+ Since the cookie field is attached to packet-in the application can also attach it to `flow_mod`.
+ It is necessary to search for the `in_port` included in the match of the packet-in.
+ Since the features reply doesn't include port information it is necessary to use a different method to retrieve. (`OFPT_MULTIPART_REQUEST`)

## Ambiguous specification items

- undefined structure  
-- p.44: `ofp_instruction_experimenter`  
-- p.65,66: `ofp_table_feature_prop_header` and `ofp_table_feature_prop_experimenter`  
-- p.66: `ofp_instruction`  
- undefined macro  
-- p.54: `OFPTC_*`  
-- p.69: `OFPQ_ALL`  
-- p.70: `OFPG_ANY` and `OFPG_ALL`  
- typo  
-- p.43: `OFPXMT_OFP_MPLS_BOS` -> `OFPXMT_OFB_MPLS_BOS`  
-- p.83: `OFPQCFC_EPERM` -> `OFPSCFC_EPERM`  
-- p.38: `OFPQT_MIN` -> `OFPQT_MIN_RATE` and `OFPQT_MAX` -> `OFPQT_MAX_RATE`  
-- p.75: `NX_ROLE_` -> `OFPCR_ROLE_`  
-- p.72: `/* All OFPMC_* that apply. */` -> `/* All OFPMF_* that apply. */`  
- added macro  
-- `OFP_DEFAULT_PRIORITY`  
-- `OFP_DEFAULT_MISS_SEND_LEN`  
- data length of the OXM TLV  
-- `OXM_OF_IPV6_FLABEL` 20bits is 4bytes  
-- `OXM_OF_MPLS_LABEL` 20bits is 4bytes  
-- `OXM_OF_PBB_ISID` 24bits is 4bytes  

License
-------

Trema is released under the GNU General Public License version 2.0:

* http://www.gnu.org/licenses/gpl-2.0.html
