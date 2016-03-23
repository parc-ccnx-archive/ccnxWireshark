/* ccnxtlv_Name.h
 * Definitions for CCNx packet disassembly structures and routines
 * By Marc Mosko <marc.mosko@parc.com>
 * Copyright 2013,2014,2015,2016 Palo Alto Research Center
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
 * A utility to display a Name in URI string format
 */

#ifndef CCNXTLV_NAME_H
#define CCNXTLV_NAME_H

#include <glib.h>

/**
 * Dissect a TLV Name.  The buffer tvb at offset "offset" is the TLV Value of the Name.
 *
 * @param [in] tvb The packet buffer
 * @param [in] headerfield The GUI handle for the field display format (from proto_register_field_array)
 * @param [in] tree The GUI tree to add the "Name" display to
 * @param [in] offset The offset within tvb where the Name value begins
 * @param [in] tlv_type The TLV type of the Name (e.g. T_NAME or T_KEYNAME_NAME)
 * @param [in] tlv_length The TLV length of the Name value.  This is the total length of
 *                        all name segment TLVs.
 *
 * @return number The tlv_length processed
 */
guint ccnxtlvName_Dissect(tvbuff_t *tvb, guint headerfield, proto_tree *tree, guint offset, guint16 tlv_type, guint16 tlv_length);

#endif

