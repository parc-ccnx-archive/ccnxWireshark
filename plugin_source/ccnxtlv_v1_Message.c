/* ccnxtlv_ContentObject.c
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
#include "ccnxtlv_v1_Message.h"
#include "ccnxtlv_UnknownTlv.h"
#include "ccnxtlv_Name.h"
#include "ccnxtlv_v1_types.h"

// The Wireshark handle to the dissector
static int proto_ccnxtlv_message = -1;

// The wireshark handle to the GUI subtree
static gint ett_ccnxtlv_message = -1;

// Wireshark handles for field formants to put in the subtree
static gint hf_ccnxtlv_message_payload = -1;
static gint hf_ccnxtlv_message_type = -1;
static gint hf_ccnxtlv_message_payload_length = -1;

// The GUI field handle for displaying header fields
static gint hf_ccnxtlv_metadata_end_chunk = -1;

// Field display handles
static gint hf_ccnxtlv_metadata_payload_type = -1;
static gint hf_ccnxtlv_metadata_expiry_time = -1;

static gint hf_ccnxtlv_metadata_keyidrest = -1;
static gint hf_ccnxtlv_metadata_cohrest = -1;

// Translate the ContentType to a string
static const value_string payloadTypeNames[] = {
    { CCNx_PAYLOAD_DATA, "Data" },
    { CCNx_PAYLOAD_KEY, "Key" },
    { CCNx_PAYLOAD_LINK, "Link" },
    { CCNx_PAYLOAD_MANIFEST, "Manifest" },
    { 0, NULL }
};

// Translate the MessageType to a string
static const value_string messageTypeNames[] = {
    { V1_MESSAGETYPE_INTEREST, "Interest" },
    { V1_MESSAGETYPE_CONTENTOBJECT, "ContentObject" },
    { V1_MESSAGETYPE_CONTROL, "Control" },
    { 0, NULL }
};

/**
 * Convert a milliseconds-since-epoch value to a text string
 *
 * Output will be something like "2014-04-01 12:01:02.123 UTC"
 *
 * @param [in] tvb the packet buffer
 * @param [in] root The GUI tree
 * @param [in] offset The byte offset within tvb (used to highlight GUI)
 * @param [in] tlv_length The length of the value (used to highlight GUI)
 * @param [in] msec_since_epoch The time to display, expected to be in UTC
 * @param [in] hf_handle The GUI field handle to display in
 *
 */
static void
ccnxtlvMetadata_DisplayTime(tvbuff_t *tvb, proto_tree *root, guint offset, guint tlv_length,
		guint64 msec_since_epoch, guint hf_handle)
{
	time_t sec   = (time_t) (msec_since_epoch / 1000);
	guint32 msec = (guint32) (msec_since_epoch - sec * 1000);

	struct tm *tmtime = gmtime(&sec);
	char buffer[1024];
	strftime(buffer, 1024, "%F %T", tmtime);
	proto_tree_add_string_format_value(root, hf_handle, tvb, offset, tlv_length, "", "%s.%03u UTC", buffer, msec);
}

/**
 * Called for each TLV directly contained in the CCNxMessage
 *
 * @param [in] tvb the packet buffer
 * @param [in] pinfo Wireshark data about the packet
 * @param [in] root The GUI tree to put fields in
 * @param [in] offset The byte offset to start at in tvb
 * @param [in] end The last position in tvb (this is not length)
 */
static guint
ccnxtlvMessage_ProcessTlv(tvbuff_t *tvb, proto_tree *root, guint offset, guint end)
{
	guint16 length = 0;
	guint16 tlv_type = tvb_get_ntohs(tvb, offset + length);
	length += 2;
	guint16 tlv_length = tvb_get_ntohs(tvb, offset + length);
	length += 2;

//	g_print("%s: offset %u type %04X tlv_length %u end %u\n", __func__, offset+length, tlv_type, tlv_length, end);

	// TODO: We should do something more graceful to bail on syntax error
	g_assert(offset + length + tlv_length <= end);

	switch(tlv_type) {
		case V1_MESSAGE_NAME:
			ccnxtlvName_Dissect(tvb, ccnxtlv_GetNameHeaderField(), root, offset+length, tlv_type, tlv_length);
			break;

		case V1_METADATA_KEYIDREST:
			proto_tree_add_item(root, hf_ccnxtlv_metadata_keyidrest, tvb, offset+length, tlv_length, ENC_NA);
			break;
		case V1_METADATA_COHREST:
			proto_tree_add_item(root, hf_ccnxtlv_metadata_cohrest, tvb, offset+length, tlv_length, ENC_NA);
			break;
		case V1_METADATA_ENDCHUNK:
			proto_tree_add_item(root, hf_ccnxtlv_metadata_end_chunk, tvb, offset+length, tlv_length, ENC_BIG_ENDIAN);
			break;
		case V1_METADATA_PAYLOADTYPE:
			proto_tree_add_item(root, hf_ccnxtlv_metadata_payload_type, tvb, offset+length, tlv_length, ENC_BIG_ENDIAN);
			break;
		case V1_METADATA_EXPIRYTIME: {
			guint64 msec_since_epoch = tvb_get_ntoh64(tvb, offset+length);
			ccnxtlvMetadata_DisplayTime(tvb, root, offset, tlv_length, msec_since_epoch, hf_ccnxtlv_metadata_expiry_time);
			break;
		}

		case V1_METADATA_IPIDM:
			break;

		case V1_MESSAGE_PAYLOAD:
			// Contents just adds a line with the length of the contents, we don't parse it
			proto_tree_add_item(root, hf_ccnxtlv_message_payload_length, tvb, offset+length-2, 2, ENC_NA);
			proto_tree_add_item(root, hf_ccnxtlv_message_payload, tvb, offset+length, tlv_length, ENC_NA);
			break;
		default:
			ccnxtlvUnknownTlv_Dissect(tvb, root, offset+length, tlv_type, tlv_length);
			break;
	}
	length += tlv_length;
	return length;
}

guint
ccnxtlvMessageV1_Dissect(tvbuff_t *tvb, proto_tree *root, guint offset, guint16 tlv_length)
{
	// In a summary, we do not necessarily have a tree to add elements to
	if( root ) {
		proto_tree *ti = proto_tree_add_item(root, proto_ccnxtlv_message, tvb, offset, tlv_length, ENC_NA);
		proto_tree *opt_tree = proto_item_add_subtree(ti, ett_ccnxtlv_message);

		proto_item_append_text(opt_tree, ", Length %d", tlv_length);

		// need to backup 4 bytes to get the TLV "type"
		proto_tree_add_item(opt_tree, hf_ccnxtlv_message_type, tvb, offset-4, 2, ENC_BIG_ENDIAN);

		guint end = tlv_length + offset;
		while( offset < end ) {
			offset += ccnxtlvMessage_ProcessTlv(tvb, opt_tree, offset, end);
//			g_print("%s: offset %u end %u\n", __func__, offset, end);
		}
	}
//	g_print("%s: Finished\n", __func__);
	return tlv_length;
}

void
proto_register_ccnxtlv_v1_message(void)
{
	static gint *ett_message_tree[] = {
		&ett_ccnxtlv_message,
	};

	// Define the display fields we might use directly.
	static hf_register_info hf[] = {
		{ &hf_ccnxtlv_message_type,
			{ "MessageType", "ccnxtlv.message.type", FT_UINT16, BASE_DEC, VALS(messageTypeNames), 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_message_payload_length,
			{ "Payload Length", "ccnxtlv.message.payload_len", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_message_payload,
			{ "Payload", "ccnxtlv.message.payload", FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_metadata_payload_type,
			{ "PayloadType", "ccnxtlv.message.payloadtype", FT_UINT8, BASE_DEC, VALS(payloadTypeNames), 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_metadata_expiry_time,
			{ "ExpiryTime", "ccnxtlv.message.expirytime", FT_STRINGZ, BASE_NONE, NULL, 0x0, "", HFILL }
		},

		{ &hf_ccnxtlv_metadata_keyidrest,
			{ "KeyId", "ccnxtlv.message.keyidrest", FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_metadata_cohrest,
			{ "ContentObjectHash", "ccnxtlv.metadata.cohrest", FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_metadata_end_chunk,
			{ "EndChunk", "ccnxtlv.obj.pi.endchunk", FT_UINT64, BASE_DEC, NULL, 0x0, "", HFILL }
		},
	};

	// Only do work if we are currently uninitialized
	if( proto_ccnxtlv_message == -1 ) {
	    module_t *ccnxtlv_module;
		proto_ccnxtlv_message = proto_register_protocol("CCNx Message",
												"CCNxMessage",
												"ccnxmessage");

		ccnxtlv_module = prefs_register_protocol(proto_ccnxtlv_message, NULL);
		proto_register_field_array(proto_ccnxtlv_message, hf, array_length(hf));
		proto_register_subtree_array(ett_message_tree, array_length(ett_message_tree));
	}
}

