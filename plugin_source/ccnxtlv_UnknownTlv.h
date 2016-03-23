/* ccnxtlv_UnknownTlv.h
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

/**
 * A utility to display an unknown TLV in string format
 */

#ifndef CCNXTLV_UNKNOWN_TLV_H
#define CCNXTLV_UNKNOWN_TLV_H

#include <glib.h>

/**
 * Dissect an unknown TLV.  The buffer tvb at offset "offset" is the TLV Value.
 *
 * @param [in] tvb The packet buffer
 * @param [in] tree The GUI tree to add the "Name" display to
 * @param [in] offset The offset within tvb where the Name value begins
 * @param [in] tlv_type The TLV type of the Name (e.g. T_NAME or T_KEYNAME_NAME)
 * @param [in] tlv_length The TLV length of the Name value.  This is the total length of
 *                        all name segment TLVs.
 *
 * @return number The tlv_length processed
 */
guint ccnxtlvUnknownTlv_Dissect(tvbuff_t *tvb, proto_tree *tree, guint offset, guint16 tlv_type, guint16 tlv_length);

#endif

