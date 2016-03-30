/* ccnxtlv_UnknownTlv.h
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
 * This is not a dissector.  It is common code to print an Name TLV.  The user
 * must pass an initialized Header Field id to use for the formatting.
 *
 * This module is not auto-scanned for a protocol registration.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "moduleinfo.h"

#include <glib.h>
#include <ctype.h>

#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/prefs.h>
#include <epan/etypes.h>

#include "packet-ccnxtlv.h"
#include "ccnxtlv_Name.h"
#include "ccnxtlv_v1_types.h"

/**
 * The name component pointed to at (tvb_offset + inputOffset) should be printed as a
 * human-readable name component.  It will be printed in ASCII with URI escapes.
 *
 * The name component will be appended to the char buffer "output" beginning at location
 * "outputOffset".
 *
 * Returns the new outputOffset
 */
static guint
ccnxtlvName_PrintName(tvbuff_t *tvb, unsigned tvb_offset, guint inputOffset, guint end, char *output, guint outputOffset, guint outputLength)
{
	while (inputOffset < end) {
		guint8 c = tvb_get_guint8(tvb, tvb_offset + inputOffset);

		if( isprint(c) ) {
//			g_printf("%s: char %02x print\n", __func__, c);
			outputOffset += g_snprintf(output + outputOffset, outputLength - outputOffset, "%c", c);
		} else {
//			g_printf("%s: char %02x escape\n", __func__, c);
			outputOffset += g_snprintf(output + outputOffset, outputLength - outputOffset, "%%%02x", c);
		}
		inputOffset++;
	}
	return outputOffset;
}

/**
 * The name component pointed to at (tvb_offset + inputOffset) should be printed as a
 * binary name component.  It will be displayed as a HEX string.
 *
 * The name component will be appended to the char buffer "output" beginning at location
 * "outputOffset".
 *
 * Returns the new outputOffset
 */
static guint
ccnxtlvName_PrintHex(tvbuff_t *tvb, unsigned tvb_offset, guint inputOffset, guint end, char *output, guint outputOffset, guint outputLength)
{
	while (inputOffset < end) {
		guint8 c = tvb_get_guint8(tvb, tvb_offset + inputOffset);

//		g_printf("%s: char %02x escape\n", __func__, c);
		outputOffset += g_snprintf(output + outputOffset, outputLength - outputOffset, "%02x", c);
		inputOffset++;
	}
	return outputOffset;
}

/**
 * The buffer pointed to by tvb at offset tvb_offset is a CCNx Name TLV value.
 * It is a series of TLVs that each encapsulate a Name Segment.  The entire
 * value length is inputLength.
 *
 * This function will allocate an output buffer with malloc() and print the
 * URI representation of the Name.
 */
static char *
ccnxtlvName_TlvToLci(tvbuff_t *tvb, guint tvb_offset, guint inputLength)
{
	// this should be more than enough without needing to realloc
	guint outputLength = inputLength * 10;
	guint outputOffset = 0;
	guint inputOffset = 0;
	char * output = g_malloc(outputLength);
	memset(output, 0, outputLength);

	outputOffset += g_snprintf(output + outputOffset, outputLength - outputOffset, "ccnx:");
	while( inputOffset < inputLength ) {
		guint16 tlv_type = tvb_get_ntohs(tvb, tvb_offset + inputOffset);
		guint16 tlv_length = tvb_get_ntohs(tvb, tvb_offset + inputOffset + 2);
		inputOffset += 4;

//		g_printf("%s: tlv_type = %04x tlv_length = %u\n", __func__, tlv_type, tlv_length);

		g_assert(inputOffset + tlv_length <= inputLength);

		outputOffset += g_snprintf(output + outputOffset, outputLength - outputOffset, "/0x%x=", tlv_type);
		guint end = inputOffset + tlv_length;

		switch(tlv_type) {
			case V1_NAME_NAME:
				outputOffset = ccnxtlvName_PrintName(tvb, tvb_offset, inputOffset, end, output, outputOffset, outputLength);
				break;
			default:
				outputOffset = ccnxtlvName_PrintHex(tvb, tvb_offset, inputOffset, end, output, outputOffset, outputLength);
				break;
		}

		inputOffset += tlv_length;
	}
	return output;
}


guint
ccnxtlvName_Dissect(tvbuff_t *tvb, guint headerfield, proto_tree *tree, guint offset, guint16 tlv_type, guint16 tlv_length)
{
	if (tree) {
		char * nameString = ccnxtlvName_TlvToLci(tvb, offset, tlv_length);
//		proto_tree_add_string_format_value(tree, ccnxtlv_GetNameHeaderField(), tvb, offset, tlv_length,
//				"", "Type 0x%04x Length %u Value %s",
//				tlv_type, tlv_length, nameString);
		proto_tree_add_string_format_value(tree, headerfield, tvb, offset, tlv_length,
				"", "%s", nameString);
		g_free(nameString);
	}
	return tlv_length;
}

