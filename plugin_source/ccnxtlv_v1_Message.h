/* ccnxtlv_ContentObject.h
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
 * Dissects a CCNx Message, which may be an Interest, a Content Object, or
 * a Control packet.  The buffer should point to the first byte
 * of the CCNx Message (i.e. the Content Object "type").
 */

#ifndef CCNXTLV_V1_MESSAGE_H
#define CCNXTLV_V1_MESSAGE_H

#include <glib.h>

/**
 * Registers the dissector with Wireshark.  Wireshark will automatically execute
 * this function because the C file is listed in Makefile.common under
 * NONGENERATED_REGISTER_C_FILES.
 */
void proto_register_ccnxtlv_v1_message(void);

/**
 * Dissect a Content Object.
 *
 * @param [in] tvb The packet buffer
 * @param [in] tree The GUI tree to add elements to
 * @param [in] offset The byte offset in tvb where to start dissecting
 * @param [in] tlv_length The byte length beginning at offset of the message
 *
 * @return The bytes processed (should be "length")
 */
guint ccnxtlvMessageV1_Dissect(tvbuff_t *tvb, proto_tree *root, guint offset, guint16 tlv_length);

#endif

