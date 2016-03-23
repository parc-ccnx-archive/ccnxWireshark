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
 * This is not a dissector.  It is common code to print an unknown TLV.  It uses
 * the Header Format (hf_...) from packet-ccnxtlv.c accessed by ccnxtlv_GetUnknownHeaderField().
 *
 * This module is not auto-scanned for a protocol registration.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "moduleinfo.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/prefs.h>
#include <epan/etypes.h>

#include "packet-ccnxtlv.h"
#include "ccnxtlv_UnknownTlv.h"

guint
ccnxtlvUnknownTlv_Dissect(tvbuff_t *tvb, proto_tree *tree, guint offset, guint16 tlv_type, guint16 tlv_length)
{
	if (tree) {
		// Display the unknown TLV using the header field handle from
		// packet-ccnxtlv.c.  It will go in the GUI tree passed to us.
		proto_tree_add_string_format_value(tree, ccnxtlv_GetUnknownHeaderField(), tvb, offset, tlv_length,
				"", "Type: 0x%04x Length: %u",
				tlv_type, tlv_length);
	}
	return tlv_length;
}

