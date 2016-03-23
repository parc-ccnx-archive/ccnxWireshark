/* ccnxtlv_OptionalHeaders.h
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

#ifndef CCNXTLV_V1_OPTIONAL_HEADERS_H
#define CCNXTLV_V1_OPTIONAL_HEADERS_H

#include <glib.h>

/**
 * Registers the dissector with Wireshark.  Wireshark will automatically execute
 * this function because the C file is listed in Makefile.common under
 * NONGENERATED_REGISTER_C_FILES.
 */
void proto_register_ccnxtlv_v1_optionalheaders(void);

/**
 * Dissect the Object Info container
 *
 * @param [in] tvb The packet buffer
 * @param [in] tree The GUI tree to add to
 * @param [in] offset The byte offset within tvb where the OptionalHeaders start
 * @param [in] length The length of the OptionalHeaders
 *
 * @return The bytes processed (should be "length")
 */
guint ccnxtlvOptionalHeadersV1_Dissect(tvbuff_t *tvb, proto_tree *tree, guint offset, guint length);

#endif

