/* packet-ccnxtlv.c
 * Routines for CCNx 1.0 TLV packet 
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

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/prefs.h>
#include "packet-ccnxtlv.h"

#include "ccnxtlv_UnknownTlv.h"
#include "ccnxtlv_v1_types.h"
#include "ccnxtlv_v1_FixedHeader.h"
#include "ccnxtlv_v1_OptionalHeaders.h"
#include "ccnxtlv_v1_Message.h"
#include "ccnxtlv_v1_Validation.h"

#define CCNX_PORT 9695
#define CCNX_ETHERTYPE 0x0801

#define DEBUG_OUTPUT 1

/* desegmentation of CCNx 1.0 in a TCP stream */
static gboolean ccnxtlv_desegment = TRUE;

/*
 * See
 *
 */

static int proto_ccnxtlv = -1;

// ett_ccnxtlv is the main subtree that has the fixed header in it
static gint ett_ccnxtlv = -1;

// for unknown tlvs
static gint hf_ccnxtlv_unknown = -1;
static gint hf_ccnxtlv_name = -1;

static void dissect_ccnxtlv_message(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, gboolean is_msgresp_add);

/**
 * Return the version number, which is always byte 0
 */
guint
ccnxtlvFixedHeader_Version(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
//	g_print("Entering %s offset = %d\n", __func__, offset);

	/*
     * Get the length of the CCNx 1.0 packet
     */
    guint8 version = tvb_get_guint8(tvb, offset + 0);
    return version;
}


/**
 * This is called by the tcp de-segmenter after it has assembled the entire packet.
 * The function signature is defined in the wireshark API.
 *
 * This is called directly for Ethernet frames
 */
static int
dissect_ccnxtlv_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_ccnxtlv_message(tvb, pinfo, tree, FALSE);
    return tvb_length(tvb);
}

// Need to double-dereference a preprocessor variable to print it
#define STRING2(x) #x
#define STRING(x) STRING2(x)

/**
 * This is the function that we register with Wireshark in proto_reg_handoff_ccnxtlv() for tcp
 */
static int
dissect_ccnxtlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    guint8 version = tvb_get_guint8(tvb, 0);

#if VERSION_MAJOR == 1 && VERSION_MINOR == 10
    switch (version) {
    case 1:
        tcp_dissect_pdus(tvb, pinfo, tree, ccnxtlv_desegment, FIXED_HEADER_LENGTH,
        		&ccnxtlvFixedHeaderV1_PacketLength, dissect_ccnxtlv_pdu);
    	break;
    default:
    	break;
    }

#elif VERSION_MAJOR == 1 && VERSION_MINOR > 10
    switch (version) {
    case 1:
        tcp_dissect_pdus(tvb, pinfo, tree, ccnxtlv_desegment, FIXED_HEADER_LENGTH,
        		&ccnxtlvFixedHeaderV1_PacketLength, dissect_ccnxtlv_pdu, data);
    	break;
    default:
    	break;
    }

#else
#pragma message("Unsupported Wireshark version " STRING(PACKAGE_STRING))
#error "Cannot continue"
#endif
    return tvb_length(tvb);
}


static guint
dissect_ccnxtlv_v1_packet_payload(tvbuff_t *tvb, proto_tree *ccnxtlv_tree, guint offset, guint16 tlv_type, guint16 tlv_length)
{
	guint length = 0;

	switch (tlv_type) {
		case V1_MESSAGETYPE_INTEREST: 		// fallthrough
		case V1_MESSAGETYPE_CONTENTOBJECT:	// fallthrough
		case V1_MESSAGETYPE_CONTROL:
			length += ccnxtlvMessageV1_Dissect(tvb, ccnxtlv_tree, offset, tlv_length);
			break;

		case V1_VALIDATION_ALG:
			length += ccnxtlvValidationAlgV1_Dissect(tvb, ccnxtlv_tree, offset, tlv_length);
			break;

		case V1_VALIDATION_PAYLOAD:
			length += ccnxtlvValidationPayloadV1_Dissect(tvb, ccnxtlv_tree, offset, tlv_length);
			break;

		default:
			length += ccnxtlvUnknownTlv_Dissect(tvb, ccnxtlv_tree, offset, tlv_type, tlv_length);
			break;
	}

	if (DEBUG_OUTPUT) {
		g_printf("%s Finished type %u length %u\n", __func__, tlv_type, length);
	}
	return length;
}

static void
dissect_ccnxtlv_v1_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gboolean is_msgresp_add, proto_tree *ccnxtlv_tree)
{
	guint offset = 0;
	offset += ccnxtlvFixedHeaderV1_Dissect(tvb, ccnxtlv_tree, offset);

	gint header_length = ccnxtlvFixedHeaderV1_OptionalHeaderLength(pinfo, tvb, 0);
	if (header_length < 0) {
		proto_tree_add_text(ccnxtlv_tree, tvb, 6, 2,
				"Invalid Optional Header Length, minimum value is 8");
		return;
	}

	offset += ccnxtlvOptionalHeadersV1_Dissect(tvb, ccnxtlv_tree, offset, header_length);

	guint payload_length = ccnxtlvFixedHeaderV1_PayloadLength(pinfo, tvb, 0);

	while (payload_length > 0) {
		guint length = 0;

		guint16 tlv_type = tvb_get_ntohs(tvb, offset + length);
		length += 2;
		guint16 tlv_length = tvb_get_ntohs(tvb, offset + length);
		length += 2;

		g_assert(tlv_length + length <= payload_length);

		if (DEBUG_OUTPUT) {
			g_printf("%s tlv_type %02X tlv_length %u\n", __func__, tlv_type, tlv_length);
		}

		length += dissect_ccnxtlv_v1_packet_payload(tvb, ccnxtlv_tree, offset+length, tlv_type, tlv_length);

		offset += length;
		payload_length -= length;
		if (DEBUG_OUTPUT) {
			g_printf("%s remaining payload %u\n", __func__, payload_length);
		}
	}

}


/**
 * THis should be operating over an entire message, after TCP re-assembly
 */
static void
dissect_ccnxtlv_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        gboolean is_msgresp_add)
{
	if (DEBUG_OUTPUT) {
		g_print("Entering %s\n", __func__);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CCNx 1.0");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {

		proto_tree * ccnxtlv_root = proto_tree_add_item(tree, proto_ccnxtlv, tvb, 0, -1, ENC_NA);

		proto_tree *ccnxtlv_tree = proto_item_add_subtree(ccnxtlv_root, ett_ccnxtlv);

		guint version = ccnxtlvFixedHeader_Version(pinfo, tvb, 0);

		proto_item_append_text(ccnxtlv_tree, ", Version %d", version);

		switch (version) {

		case 1:
			dissect_ccnxtlv_v1_message(tvb, pinfo, tree, is_msgresp_add, ccnxtlv_tree);
			break;

		default:
			proto_tree_add_string_format_value(ccnxtlv_tree, hf_ccnxtlv_unknown, tvb, 0, 0,
					"", "Unknown Fixed Header version");
			break;
		}
	}
}

gint ccnxtlv_GetUnknownHeaderField(void)
{
	return hf_ccnxtlv_unknown;
}

gint ccnxtlv_GetNameHeaderField(void)
{
	return hf_ccnxtlv_name;
}

/**
 * Register the ccnxtlv dissector.  It gets called automatically because it is included
 * in NONGENERATED_REGISTER_C_FILES defined in Makefile.common.
 */
void
proto_register_ccnxtlv(void)
{
	static gint *ett_subtrees[] = {
		&ett_ccnxtlv,
	};

	// These are two common header fields that other modules can use to display
	// fields with the same format everywhere.
	static hf_register_info hf[] = {
		{ &hf_ccnxtlv_unknown,
			{ "Unknown TLV", "ccnxtlv.unknown", FT_STRINGZ, BASE_NONE, NULL, 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_name,
			{ "Name", "ccnxtlv.unknown", FT_STRINGZ, BASE_NONE, NULL, 0x0, "", HFILL }
		},
	};

	if( proto_ccnxtlv == -1 ) {

		proto_ccnxtlv = proto_register_protocol("CCNx 1.0 TLV",
												"CCNx",
												"ccnxtlv");

		module_t * ccnxtlv_module = prefs_register_protocol(proto_ccnxtlv, NULL);

		// Setup the protocol for automatic desegmentation of a TCP stream.
		prefs_register_bool_preference(ccnxtlv_module, "desegment",
			"Desegment all CCNx 1.0 messages spanning multiple TCP segments",
			"Whether the CCNx 1.0 dissector should desegment all messages spanning multiple TCP segments",
			&ccnxtlv_desegment);

		// Initialize the GUI subtrees
		proto_register_subtree_array(ett_subtrees, array_length(ett_subtrees));

		// Initialize the header field handles for displaying protocol fields.
		proto_register_field_array(proto_ccnxtlv, hf, array_length(hf));
	}
}

/**
 * Register the disector for TCP port 9695 and ethertype 0x0801
 *
 * This function is called automatically by the registration process (it gets
 * baked in to the plugin.c auto-generated source module).
 */
void
proto_reg_handoff_ccnxtlv(void)
{
    dissector_handle_t ccnxtlv_tcp_handle;
    ccnxtlv_tcp_handle = new_create_dissector_handle(dissect_ccnxtlv, proto_ccnxtlv);
    dissector_add_uint("tcp.port", CCNX_PORT, ccnxtlv_tcp_handle);

    dissector_handle_t ccnxtlv_ether_handle;
    ccnxtlv_ether_handle = new_create_dissector_handle(dissect_ccnxtlv_pdu, proto_ccnxtlv);
    dissector_add_uint("ethertype", CCNX_ETHERTYPE, ccnxtlv_ether_handle);
}

