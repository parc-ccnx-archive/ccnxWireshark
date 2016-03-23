/* ccnxtlv_v1_Validation.c
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
#include "ccnxtlv_v1_Validation.h"
#include "ccnxtlv_UnknownTlv.h"
#include "ccnxtlv_Name.h"
#include "ccnxtlv_v1_types.h"

// The Wireshark handle to the dissector
static int proto_ccnxtlv_validationalg = -1;
static int proto_ccnxtlv_validationpayload = -1;

// The wireshark handle to the GUI subtree
static gint ett_ccnxtlv_validationalg = -1;
static gint ett_ccnxtlv_validationpayload = -1;

// Wireshark handles for field formants to put in the subtree
static gint hf_ccnxtlv_validation_payload = -1;
static gint hf_ccnxtlv_validation_payload_length = -1;
static gint hf_ccnxtlv_validationalg_type = -1;
static gint hf_ccnxtlv_validationalg_keyid = -1;
static gint hf_ccnxtlv_validationalg_publickey = -1;
static gint hf_ccnxtlv_validationalg_cert = -1;
static gint hf_ccnxtlv_validationalg_keylink = -1;

// Translate the MessageType to a string
static const value_string validationTypeNames[] = {
    { V1_VALIDATIONTYPE_CRC32C, 	"CRC32C" },
    { V1_VALIDATIONTYPE_HMAC_SHA256, "HMAC-SHA256" },
    { V1_VALIDATIONTYPE_VMAC_128, 	"VMAC-128" },
    { V1_VALIDATIONTYPE_RSA_SHA256, "RSA-SHA256" },
    { V1_VALIDATIONTYPE_EC_SECP_256K1, "EC-SECP-256K1" },
    { V1_VALIDATIONTYPE_EC_SECP_384R1, "EC-SECP-384R1" },
    { 0, NULL }
};


/**
 * Dissect the Interest Lifetime Optional Header.
 *
 * @param [in] tvb The packet buffer
 * @param [in] root The GUI tree to add fields to
 * @param [in] offset The byte offset in tvb that points to the HopLimit Value
 * @param [in] tlv_length The byte length of the Hop Limit Value
 *
 * @return The number of bytes processed (should be tlv_length)
 */
static guint
ccnxtlvValidationAlg_DecodeLink(tvbuff_t *tvb, proto_tree *root, guint offset, guint tlv_length)
{
	proto_tree_add_item(root, hf_ccnxtlv_validationalg_keylink, tvb, offset, tlv_length, ENC_BIG_ENDIAN);
	return tlv_length;
}

/**
 * Called for each TLV directly contained in the ValidationAlg
 *
 * @param [in] tvb the packet buffer
 * @param [in] pinfo Wireshark data about the packet
 * @param [in] root The GUI tree to put fields in
 * @param [in] offset The byte offset to start at in tvb
 * @param [in] end The last position in tvb (this is not length)
 */
static guint
ccnxtlvValidationAlg_ProcessTlv(tvbuff_t *tvb, proto_tree *root, guint offset, guint end)
{
	guint16 length = 0;
	guint16 tlv_type = tvb_get_ntohs(tvb, offset + length);
	length += 2;
	guint16 tlv_length = tvb_get_ntohs(tvb, offset + length);
	length += 2;

	// TODO: We should do something more graceful to bail on syntax error
	g_assert(offset + length + tlv_length <= end);

//	g_printf("%s tlv_type %02X tlv_length %u\n", __func__, tlv_type, tlv_length);

	switch(tlv_type) {
		case V1_VALIDATIONTYPE_CRC32C:			// fallthrough
		case V1_VALIDATIONTYPE_HMAC_SHA256:		// fallthrough
		case V1_VALIDATIONTYPE_VMAC_128:		// fallthrough
		case V1_VALIDATIONTYPE_RSA_SHA256:		// fallthrough
		case V1_VALIDATIONTYPE_EC_SECP_256K1:	// fallthrough
		case V1_VALIDATIONTYPE_EC_SECP_384R1:
			proto_tree_add_item(root, hf_ccnxtlv_validationalg_type, tvb, offset, 2, ENC_BIG_ENDIAN);
			// the T and L length are already accounted for in length
			length += 0;
			break;

		case V1_VALIDATIONALG_KEYID:
			proto_tree_add_item(root, hf_ccnxtlv_validationalg_keyid, tvb, offset+length, tlv_length, ENC_BIG_ENDIAN);
			length += tlv_length;
			break;
		case V1_VALIDATIONALG_PUBLICKEY:
			proto_tree_add_item(root, hf_ccnxtlv_validationalg_publickey, tvb, offset+length, tlv_length, ENC_BIG_ENDIAN);
			length += tlv_length;
			break;
		case V1_VALIDATIONALG_CERT:
			proto_tree_add_item(root, hf_ccnxtlv_validationalg_cert, tvb, offset+length, tlv_length, ENC_BIG_ENDIAN);
			length += tlv_length;
			break;
		case V1_VALIDATIONALG_KEYLINK:
			ccnxtlvValidationAlg_DecodeLink(tvb, root, offset, tlv_length);
			length += tlv_length;
			break;
		default:
			ccnxtlvUnknownTlv_Dissect(tvb, root, offset+length, tlv_type, tlv_length);
			length += tlv_length;
			break;
	}
	return length;
}

guint
ccnxtlvValidationAlgV1_Dissect(tvbuff_t *tvb, proto_tree *root, guint offset, guint tlv_length)
{
	// In a summary, we do not necessarily have a tree to add elements to
	if( root ) {
		proto_tree *ti = proto_tree_add_item(root, proto_ccnxtlv_validationalg, tvb, offset, tlv_length, ENC_NA);
		proto_tree *opt_tree = proto_item_add_subtree(ti, ett_ccnxtlv_validationalg);

		proto_item_append_text(opt_tree, ", Length %d", tlv_length);

		guint end = tlv_length + offset;
		while( offset < end ) {
			offset += ccnxtlvValidationAlg_ProcessTlv(tvb, opt_tree, offset, end);
//			g_print("%s: offset %u end %u\n", __func__, offset, end);
		}
	}
	return tlv_length;
}

guint
ccnxtlvValidationPayloadV1_Dissect(tvbuff_t *tvb, proto_tree *root, guint offset, guint tlv_length)
{
	if( root ) {
		proto_tree *ti = proto_tree_add_item(root, proto_ccnxtlv_validationpayload, tvb, offset, tlv_length, ENC_NA);
		proto_tree *opt_tree = proto_item_add_subtree(ti, ett_ccnxtlv_validationpayload);

		// -2 to highlight the TLV length field just before the "value"
		proto_tree_add_item(opt_tree, hf_ccnxtlv_validation_payload_length, tvb, offset-2, 2, ENC_BIG_ENDIAN);

		proto_tree_add_item(opt_tree, hf_ccnxtlv_validation_payload, tvb, offset, tlv_length, ENC_NA);
	}

	return tlv_length;
}

static void
register_validationalg(void)
{
	static gint *ett_message_tree[] = {
		&ett_ccnxtlv_validationalg,
	};

	// Define the display fields we might use directly.
	static hf_register_info hf[] = {
		{ &hf_ccnxtlv_validationalg_type,
			{ "ValidationType", "ccnxtlv.validaiton.type", FT_UINT16, BASE_DEC, VALS(validationTypeNames), 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_validationalg_keyid,
			{ "KeyId", "ccnxtlv.validation.keyid", FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_validationalg_publickey,
			{ "PublicKey", "ccnxtlv.validation.pubkey", FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_validationalg_cert,
			{ "Certificate", "ccnxtlv.validation.cert", FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_validationalg_keylink,
			{ "KeyName", "ccnxtlv.validation.keylink", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
		},

	};

	// Only do work if we are currently uninitialized
	if( proto_ccnxtlv_validationalg == -1 ) {
	    module_t *ccnxtlv_module;
	    proto_ccnxtlv_validationalg = proto_register_protocol("CCNx ValidationAlg",
												"CCNxValidationAlg",
												"ccnxvalidationalg");

		ccnxtlv_module = prefs_register_protocol(proto_ccnxtlv_validationalg, NULL);
		proto_register_field_array(proto_ccnxtlv_validationalg, hf, array_length(hf));
		proto_register_subtree_array(ett_message_tree, array_length(ett_message_tree));
	}
}

static void
register_validationpayload(void)
{
	static gint *ett_message_tree[] = {
		&ett_ccnxtlv_validationpayload,
	};

	// Define the display fields we might use directly.
	static hf_register_info hf[] = {
		{ &hf_ccnxtlv_validation_payload_length,
			{ "ValidaitonPayload Length", "ccnxtlv.validation.payload_len", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_validation_payload,
			{ "ValidationPayload", "ccnxtlv.validation.payload", FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
		},
	};

	// Only do work if we are currently uninitialized
	if( proto_ccnxtlv_validationpayload == -1 ) {
	    module_t *ccnxtlv_module;
	    proto_ccnxtlv_validationpayload = proto_register_protocol("CCNx ValidationPayload",
												"CCNxValidationPayload",
												"ccnxvalidationpayload");

		ccnxtlv_module = prefs_register_protocol(proto_ccnxtlv_validationpayload, NULL);
		proto_register_field_array(proto_ccnxtlv_validationpayload, hf, array_length(hf));
		proto_register_subtree_array(ett_message_tree, array_length(ett_message_tree));
	}
}


// Register the GUI fields
void
proto_register_ccnxtlv_v1_validation(void)
{
	register_validationalg();
	register_validationpayload();
}

