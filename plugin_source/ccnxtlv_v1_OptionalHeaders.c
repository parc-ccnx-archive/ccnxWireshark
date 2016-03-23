
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
#include "ccnxtlv_v1_OptionalHeaders.h"
#include "ccnxtlv_UnknownTlv.h"
#include "ccnxtlv_v1_types.h"

static int proto_ccnxtlv_optional = -1;
static gint ett_ccnxtlv_optional = -1;

static gint	hf_ccnxtlv_oh_lifetime = -1;
static gint	hf_ccnxtlv_oh_unknown = -1;
static gint	hf_ccnxtlv_oh_cachelifetime = -1;

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
ccnxtlvOptionalHeaders_DecodeLifetime(tvbuff_t *tvb, proto_tree *root, guint offset, guint tlv_length)
{
	proto_tree_add_item(root, hf_ccnxtlv_oh_lifetime, tvb, offset, tlv_length, ENC_BIG_ENDIAN);
	return tlv_length;
}

/**
 * Dissect the Recommended Cache Lifetime, which is a uint64 time
 *
 * @param [in] tvb The packet buffer
 * @param [in] root The GUI tree to add fields to
 * @param [in] offset The byte offset in tvb that points to the HopLimit Value
 * @param [in] tlv_length The byte length of the Hop Limit Value
 *
 * @return The number of bytes processed (should be tlv_length)
 */
static guint
ccnxtlvOptionalHeaders_DecodeCacheLifetime(tvbuff_t *tvb, proto_tree *root, guint offset, guint tlv_length)
{
	proto_tree_add_item(root, hf_ccnxtlv_oh_cachelifetime, tvb, offset, tlv_length, ENC_BIG_ENDIAN);
	return tlv_length;
}

/**
 * Dissect a TLV found within NameAuth
 *
 * @param [in] tvb the packet buffer
 * @param [in] root The GUI tree
 * @param [in] offset The byte offset within tvb, points to "Type"
 * @param [in] end The end of the NameAuth container
 *
 * @return The bytes processed (offset+bytes <= end)
 */
static guint
ccnxtlvOptionalHeaders_ProcessTlv(tvbuff_t *tvb, proto_tree *root, guint offset, guint end)
{
	guint16 length = 0;
	guint16 tlv_type = tvb_get_ntohs(tvb, offset + length);
	length += 2;
	guint16 tlv_length = tvb_get_ntohs(tvb, offset + length);
	length += 2;

//	g_print("offset = %u length = %u tlv_length = %u end = %u\n", offset, length, tlv_length, end);
	g_assert(offset + length + tlv_length <= end);

	switch(tlv_type) {
		case V1_HEADERS_LIFETIME:
			ccnxtlvOptionalHeaders_DecodeLifetime(tvb, root, offset+length, tlv_length);
			break;

		case V1_HEADERS_CACHETIME:
			ccnxtlvOptionalHeaders_DecodeCacheLifetime(tvb, root, offset+length, tlv_length);
			break;

		default:
			ccnxtlvUnknownTlv_Dissect(tvb, root, offset+length, tlv_type, tlv_length);
			break;
	}
	length += tlv_length;
	return length;
}

guint
ccnxtlvOptionalHeadersV1_Dissect(tvbuff_t *tvb, proto_tree *root, guint offset, guint header_length)
{
//	g_print("Entering %s\n", __func__);

	if( root ) {

		proto_tree *ti = proto_tree_add_item(root, proto_ccnxtlv_optional, tvb, offset, header_length, ENC_NA);
		proto_tree *opt_tree = proto_item_add_subtree(ti, ett_ccnxtlv_optional);

		proto_item_append_text(opt_tree, ", Length %d", header_length);

		guint end = header_length + offset;
		while( offset < end ) {
			guint bytes = ccnxtlvOptionalHeaders_ProcessTlv(tvb, opt_tree, offset, end);
			offset += bytes;
//			g_print("%s: offset %u length %u\n", __func__, offset, header_length);
		}
	}
	return header_length;
}


void
proto_register_ccnxtlv_v1_optionalheaders(void)
{
//	g_print("Entering %s\n", __func__);

    module_t *ccnxtlv_module;

	static gint *ett_optional_tree[] = {
		&ett_ccnxtlv_optional,
	};

	static hf_register_info hf[] = {
		{ &hf_ccnxtlv_oh_lifetime,
			{ "Interest Lifetime", "ccnxtlv.oh.lifetime", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_oh_unknown,
			{ "Unknown TLV", "ccnxtlv.oh.unknown", FT_STRINGZ, BASE_NONE, NULL, 0x0, "", HFILL }
		},
		{ &hf_ccnxtlv_oh_cachelifetime,
			{ "Recommended Cache Lifetime", "ccnxtlv.oh.rct", FT_UINT64, BASE_DEC, NULL, 0x0, "", HFILL }
		},
	};


	if( proto_ccnxtlv_optional == -1 ) {
		proto_ccnxtlv_optional = proto_register_protocol("Optional Headers V1",
												"Optional Headers V1",
												"optional_v1");

		ccnxtlv_module = prefs_register_protocol(proto_ccnxtlv_optional, NULL);
		proto_register_field_array(proto_ccnxtlv_optional, hf, array_length(hf));

		proto_register_subtree_array(ett_optional_tree, array_length(ett_optional_tree));
	}
}

