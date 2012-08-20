/*
 * An OpenFlow application interface library.
 *
 * Author: SUGYO Kazushi
 *
 * Copyright (C) 2012 NEC Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#ifndef OPENFLOW_LOCAL_H
#define OPENFLOW_LOCAL_H

#include <openflow.h>

/* Instruction header that is common to all instructions. The length includes
 * the header and any padding used to make the instruction 64-bit aligned.
 * NB: The length of an instruction *must* always be a multiple of eight. */
struct ofp_instruction {
    uint16_t type;         /* Instruction type */
    uint16_t len;          /* Length of this struct in bytes. */
};
OFP_ASSERT(sizeof(struct ofp_instruction) == 4);

/* Common header for all Table Feature Properties */
struct ofp_table_feature_prop_header {
    uint16_t type;         /* One of OFPTFPT_*. */
    uint16_t length;       /* Length in bytes of this property. */
};
OFP_ASSERT(sizeof(struct ofp_table_feature_prop_header) == 4);

/* Experimenter table feature property */
struct ofp_table_feature_prop_experimenter {
    uint16_t type;         /* One of OFPTFPT_EXPERIMENTER,
                              OFPTFPT_EXPERIMENTER_MISS. */
    uint16_t length;       /* Length in bytes of this property. */
    uint32_t experimenter; /* Experimenter ID which takes the same
                              form as in struct
                              ofp_experimenter_header. */
    uint32_t exp_type;     /* Experimenter defined. */
    /* Followed by:
     * - Exactly (length - 12) bytes containing the experimenter data, then
     * - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     * bytes of all-zero bytes */
    uint32_t experimenter_data[0];
};
OFP_ASSERT(sizeof(struct ofp_table_feature_prop_experimenter) == 12);

/* Instruction structure for experimental instructions */
struct ofp_instruction_experimenter {
    uint16_t type;         /* OFPIT_EXPERIMENTER */
    uint16_t len;          /* Length of this struct in bytes */
    uint32_t experimenter; /* Experimenter ID which takes the same form
                              as in struct ofp_experimenter_header. */
    /* Experimenter-defined arbitrary additional data. */
};
OFP_ASSERT(sizeof(struct ofp_instruction_experimenter) == 8);

/* Group numbering. Groups can use any number up to OFPG_MAX. */
enum ofp_group {
    /* Last usable group number. */
    OFPG_MAX = 0xffffff00,

    /* Fake groups. */
    OFPG_ALL = 0xfffffffc, /* Represents all groups for group delete
                              commands. */
    OFPG_ANY = 0xffffffff  /* Wildcard group used only for flow stats
                              requests. Selects all flows regardless of
                              group (including flows with no group). */
};


#endif // OPENFLOW_LOCAL_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
