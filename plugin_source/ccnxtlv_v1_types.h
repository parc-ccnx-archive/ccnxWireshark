/* ccnxtlv_types.h
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
 * Defines the TLV type constants for CCNx 1.0
 */
#ifndef CCNXTLV_V1_TYPES_H_
#define CCNXTLV_V1_TYPES_H_

// Name segment of type NAME
#define V1_NAME_NAME 0x0001
#define V1_NAME_IPID 0x0002

// The experimental TLV range
#define V1_EXP_START	0x1000
#define V1_EXP_END		0x1FFF

// Fixed header packet types
#define V1_PACKETTYPE_INTEREST       0x00
#define V1_PACKETTYPE_CONTENTOBJECT  0x01
#define V1_PACKETTYPE_INTERESTRETURN 0x02
#define V1_PACKETTYPE_CONTROL        0xA4

// Top-level containers in the packet payload
#define V1_MESSAGETYPE_INTEREST      0x0001
#define V1_MESSAGETYPE_CONTENTOBJECT 0x0002
#define V1_MESSAGETYPE_CONTROL       0xBEEF
#define V1_VALIDATION_ALG			  0x0003
#define V1_VALIDATION_PAYLOAD         0x0004

// Optional Headers
#define V1_HEADERS_LIFETIME           0x0001
#define V1_HEADERS_CACHETIME		  0x0002

// CCNxMessage fields
#define V1_MESSAGE_NAME               0x0000
#define V1_MESSAGE_PAYLOAD            0x0001

// Metadata fields
#define V1_METADATA_KEYIDREST         0x0002
#define V1_METADATA_COHREST           0x0003
#define V1_METADATA_IPIDM             0x0004

#define V1_METADATA_PAYLOADTYPE       0x0005
#define V1_METADATA_EXPIRYTIME        0x0006
#define V1_METADATA_ENDCHUNK          0x0007

// ValidationType constants
#define V1_VALIDATIONTYPE_CRC32C		0x0002
#define V1_VALIDATIONTYPE_HMAC_SHA256	0x0004
#define V1_VALIDATIONTYPE_VMAC_128	 	0x0005
#define V1_VALIDATIONTYPE_RSA_SHA256	0x0006
#define V1_VALIDATIONTYPE_EC_SECP_256K1	0x0007
#define V1_VALIDATIONTYPE_EC_SECP_384R1	0x0008

#define V1_VALIDATIONALG_KEYID			0x0009
#define V1_VALIDATIONALG_PUBLICKEY		0x000B
#define V1_VALIDATIONALG_CERT			0x000C
#define V1_VALIDATIONALG_KEYLINK 		0x000E
#define V1_VALIDATIONALG_SIGTIME        0x000F

// LINK
#define V1_LINK_NAME					0x0000
#define V1_LINK_KEYIDREST               0x0001
#define V1_LINK_COHREST                 0x0002

// PayloadType constants
#define CCNx_PAYLOAD_DATA 				0
#define CCNx_PAYLOAD_KEY  				1
#define CCNx_PAYLOAD_LINK 				2
#define CCNx_PAYLOAD_MANIFEST 			3

#endif /* CCNXTLV_TYPES_H_ */
