/* ccnxtlv_FixedHeader.h
 * Definitions for CCNx packet disassembly structures and routines
 * By Marc Mosko <marc.mosko@parc.com>
 * Copyright 2013,2014 Palo Alto Research Center
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef CCNXTLV_V1_FIXED_HEADER_H
#define CCNXTLV_V1_FIXED_HEADER_H

#include <glib.h>

/**
 * Registers the dissector with Wireshark.  Wireshark will automatically execute
 * this function because the C file is listed in Makefile.common under
 * NONGENERATED_REGISTER_C_FILES.
 */
void proto_register_ccnxtlv_v1_fixedheader(void);

/**
 * Called by the TCP de-segmenter once we have at least the entire fixed header
 * so we can get the entire PDU length.  function signature must comply with Wireshark API.
 */
extern guint ccnxtlvFixedHeaderV1_PacketLength(packet_info *pinfo _U_, tvbuff_t *tvb, int offset);

/**
 * Called by the Optional Header dissector to get the length from the fixed header.
 * This is the length of the OptionalHeaders, it does not include the length of the FixedHeader
 */
gint ccnxtlvFixedHeaderV1_OptionalHeaderLength(packet_info *pinfo _U_, tvbuff_t *tvb, int offset);

/**
 * Returns the payload length, which includes the CCNxMessage, Validation Alg, and Validation Payload.
 */
guint ccnxtlvFixedHeaderV1_PayloadLength(packet_info *pinfo _U_, tvbuff_t *tvb, int offset);

/**
 * Dissect the Fixed Header
 *
 * @param [in] tvb The packet buffer
 * @param [in] pinfo Wireshark metadata about packet
 * @param [in] tree The GUI tree to add elements to
 * @param [in] offset The offset to begin dissection in tvb
 *
 * @return The bytes length of the fixed header, negative is an error
 */
guint
ccnxtlvFixedHeaderV1_Dissect(tvbuff_t *tvb, proto_tree *tree, guint offset);

#endif

