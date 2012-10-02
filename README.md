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

License
-------

Trema is released under the GNU General Public License version 2.0:

* http://www.gnu.org/licenses/gpl-2.0.html
