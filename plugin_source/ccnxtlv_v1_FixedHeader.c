/* ccnxtlv_FixedHeader.c
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
#include "ccnxtlv_v1_FixedHeader.h"
#include "ccnxtlv_v1_types.h"

// fixed header protocol handle
static int proto_ccnxtlv_fh = -1;

// header field format handles
static gint	hf_ccnxtlv_fh_version = -1;
static gint	hf_ccnxtlv_fh_packet_type = -1;
static gint	hf_ccnxtlv_fh_packet_length = -1;
static gint	hf_ccnxtlv_fh_hop_limit = -1;
static gint	hf_ccnxtlv_fh_header_length = -1;
static gint	hf_ccnxtlv_fh_return_code = -1;

// subtree handle for the fixed header
static gint ett_ccnxtlv_fh = -1;

// Translate PacketType to a name
static const value_string packetTypeNames[] = {
    { V1_PACKETTYPE_INTEREST, "Interest" },
    { V1_PACKETTYPE_CONTENTOBJECT, "ContentObject" },
    { V1_PACKETTYPE_INTERESTRETURN, "InterestReturn" },
    { V1_PACKETTYPE_CONTROL, "CPI Control" },
    { 0, NULL }
};

/**
 * Return the total packet length based on the fixed header sizes
 *
 * @param [in] pinfo The wireshark metadata about the packet (TODO remove this)
 * @param [in] tvb The packet buffer
 * @param [in] The offset of the fixed header (should be 0)
 *
 * @return The total packet length, including the fixed header
 */
guint
ccnxtlvFixedHeaderV1_PacketLength(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
//	g_print("Entering %s offset = %d\n", __func__, offset);

    /*
     * Get the length of the CCNx 1.0 packet
     */
    guint16 packet_length = tvb_get_ntohs(tvb, offset + 2);

    /*
     * In V1 headers, the HeaderLength includes the FixedHeader
     */
    return packet_length;
}

gint
ccnxtlvFixedHeaderV1_OptionalHeaderLength(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
//	g_print("Entering %s offset = %d\n", __func__, offset);

	/*
     * Get the length of the CCNx 1.0 packet.  Will be negative is invalid value
     */
    guint8 headers_length = tvb_get_guint8(tvb, offset + 7);
	return (gint) headers_length - (gint) FIXED_HEADER_LENGTH;
}

guint
ccnxtlvFixedHeaderV1_PayloadLength(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint packet_length = ccnxtlvFixedHeaderV1_PacketLength(pinfo, tvb, offset);
    guint headers_length = tvb_get_guint8(tvb, offset + 7);

    guint payload_length = packet_length - headers_length;
	return payload_length;
}

guint
ccnxtlvFixedHeaderV1_Dissect(tvbuff_t *tvb, proto_tree *root, guint offset)
{
//	g_print("Entering %s\n", __func__);

	if( root ) {
		proto_tree *ti=NULL;
		proto_tree *fh_tree=NULL;

	    guint8 packetType = tvb_get_guint8(tvb, offset + 1);

		ti = proto_tree_add_item(root, proto_ccnxtlv_fh, tvb, offset, FIXED_HEADER_LENGTH, ENC_BIG_ENDIAN);
		fh_tree = proto_item_add_subtree(ti, ett_ccnxtlv_fh);

		proto_tree_add_item(fh_tree, hf_ccnxtlv_fh_version, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		proto_tree_add_item(fh_tree, hf_ccnxtlv_fh_packet_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		proto_tree_add_item(fh_tree, hf_ccnxtlv_fh_packet_length, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		if (packetType == V1_PACKETTYPE_INTEREST || packetType == V1_PACKETTYPE_INTERESTRETURN) {
			proto_tree_add_item(fh_tree, hf_ccnxtlv_fh_hop_limit, tvb, offset, 1, ENC_BIG_ENDIAN);
		}
		offset += 1;

		if (packetType == V1_PACKETTYPE_INTERESTRETURN) {
			proto_tree_add_item(fh_tree, hf_ccnxtlv_fh_return_code, tvb, offset, 1, ENC_BIG_ENDIAN);
		}
		offset += 1;

		// skip flags
		offset += 1;

		proto_tree_add_item(fh_tree, hf_ccnxtlv_fh_header_length, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
	}
	return FIXED_HEADER_LENGTH;
}

void
proto_register_ccnxtlv_v1_fixedheader(void)
{
//	g_print("Entering %s\n", __func__);

	static gint *ett_fixed_subtree[] = {
		&ett_ccnxtlv_fh,
	};

	static hf_register_info hf[] = {
		{ &hf_ccnxtlv_fh_version,
			{ "Version", "ccnxtlv.fh.ver", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_fh_packet_type,
			{ "Packet Type", "ccnxtlv.fh.pt", FT_UINT8, BASE_DEC, VALS(packetTypeNames), 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_fh_packet_length,
			{ "Packet Length", "ccnxtlv.fh.packet_length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_fh_header_length,
			{ "Headers Length", "ccnxtlv.fh.headers_length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_fh_hop_limit,
			{ "Hop Limit", "ccnxtlv.fh.hop_limit", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_fh_return_code,
			{ "Return Code", "ccnxtlv.fh.return_code", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
	};

	if( proto_ccnxtlv_fh == -1 ) {
		proto_ccnxtlv_fh = proto_register_protocol("Fixed Header V1",
												"Fixed Header V1",
												"fixed_v1");

		prefs_register_protocol(proto_ccnxtlv_fh, NULL);
		proto_register_field_array(proto_ccnxtlv_fh, hf, array_length(hf));
		proto_register_subtree_array(ett_fixed_subtree, array_length(ett_fixed_subtree));
    }
}

