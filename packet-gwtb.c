/* packet-gwtb.c
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/crypt/crypt-rc4.c>

#define PROTO_TAG_GWTB									"GWTB"
#define TCP_PORT_GWTB									9924
#define FRAME_HEADER_LEN								2
#define FRAME_REQUEST_LEN								48
#define FRAME_RESPONSE_LEN								32

typedef struct gwtb_info_t {
	guint32				length;
	guchar				auth;
	guchar				*data;
	rc4_state_struct	*rc4;
} gwtb_info_t;

typedef struct gwtb_key_t {
	unsigned char		chars[16];
} gwtb_key_t;

typedef struct gwtb_entry_t {
	gwtb_key_t			*greeting;
	gwtb_key_t			*request_key[2];
	gwtb_key_t			*response_key[2];
	rc4_state_struct	*request_rc4;
	rc4_state_struct	*response_rc4;
} gwtb_entry_t;

/* Wireshark ID of the GWTB protocol */
static int proto_gwtb = -1;

/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_gwtb()
*/

/** Kts attempt at defining the protocol */
static gint hf_gwtb = -1;
static gint hf_greeting = -1;
static gint hf_authkey = -1;
static gint hf_length = -1;
static gint hf_string = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_gwtb = -1;
static gint ett_greeting = -1;
static gint ett_authkey = -1;
static gint ett_length = -1;
static gint ett_string = -1;


static gwtb_entry_t* dissect_gwtb_get_data(packet_info* pinfo)
{
	conversation_t *conversation;
	gwtb_entry_t *data_ptr;

	/*
	 * Do we have a conversation for this connection?
	 */
	conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	if (conversation == NULL) {
		/* We don't yet have a conversation, so create one. */
		conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,	pinfo->srcport, pinfo->destport, 0);
	}

	/*
	 * Do we already have a state structure for this conv
	 */
	data_ptr = (gwtb_entry_t*)conversation_get_proto_data(conversation, proto_gwtb);
	if (!data_ptr) {
		/*
         * No.  Attach that information to the conversation, and add
		 * it to the list of information structures.
		 */
		data_ptr = (gwtb_entry_t*)se_alloc(sizeof(gwtb_entry_t));
		data_ptr->greeting = NULL;
		data_ptr->request_key[0] = NULL;
		data_ptr->request_key[1] = NULL;
		data_ptr->response_key[0] = NULL;
		data_ptr->response_key[1] = NULL;
		data_ptr->request_rc4 = NULL;
		data_ptr->response_rc4 = NULL;

		conversation_add_proto_data(conversation, proto_gwtb, data_ptr);
	}

	return data_ptr;
}

static guint get_gwtb_request_len(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
	return FRAME_REQUEST_LEN;
}
static guint get_gwtb_response_len(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
	return FRAME_RESPONSE_LEN;
}

static guint get_gwtb_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
	gwtb_info_t *info_ptr = (gwtb_info_t*)p_get_proto_data(pinfo->fd, proto_gwtb);
	rc4_state_struct rc4 = *info_ptr->rc4;
	guint32 length = tvb_length(tvb);
	guchar *data;
	guint len;

	if (!info_ptr->length) {
		data = (guchar*)ep_alloc(length);
		if (data) {
			tvb_memcpy(tvb, data, offset, length);
			crypt_rc4(&rc4, data, length);
			while (info_ptr->length < length) {
				len = ((guint)pntohs((guint16*)(data+offset)))+FRAME_HEADER_LEN;
				offset += len;
				info_ptr->length += len;
			}
		}
	}

	return info_ptr->length;
}


static void dissect_gwtb_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gwtb_entry_t *data_ptr = dissect_gwtb_get_data(pinfo);
	gwtb_info_t *info_ptr = (gwtb_info_t*)p_get_proto_data(pinfo->fd, proto_gwtb);
	proto_item *gwtb_item = NULL;
	proto_tree *gwtb_tree = NULL;	
	guint32 offset = 0;
	guint32 i;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_GWTB);

	if (tvb_get_guint8(tvb, 0) == 1 && tvb_get_guint8(tvb, 2) == 1 && tvb_get_guint8(tvb, 15) == 105) {
		if (check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO, "Authentication Request");

		if (tree) { /* we are being asked for details */
			gwtb_item = proto_tree_add_item(tree, proto_gwtb, tvb, 0, -1, FALSE);
			gwtb_tree = proto_item_add_subtree(gwtb_item, ett_gwtb);

			proto_tree_add_item(gwtb_tree, hf_greeting, tvb, offset, 16, FALSE);
			proto_tree_add_item(gwtb_tree, hf_authkey, tvb, offset+16, 16, FALSE);
			proto_tree_add_item(gwtb_tree, hf_authkey, tvb, offset+32, 16, FALSE);
		}

		if (data_ptr && data_ptr->request_rc4 == NULL) {
			data_ptr->greeting = (gwtb_key_t *)tvb_get_ptr(tvb, offset, sizeof(gwtb_key_t));
			offset += sizeof(gwtb_key_t);

			data_ptr->request_key[0] = (gwtb_key_t *)tvb_get_ptr(tvb, offset, sizeof(gwtb_key_t));
			offset += sizeof(gwtb_key_t);

			data_ptr->request_key[1] = (gwtb_key_t *)tvb_get_ptr(tvb, offset, sizeof(gwtb_key_t));
			offset += sizeof(gwtb_key_t);

			for (i = 0; i < sizeof(gwtb_key_t); i++) {
				data_ptr->request_key[1]->chars[i] ^= data_ptr->request_key[0]->chars[i];
			}

			info_ptr->auth = TRUE;
			data_ptr->request_rc4 = (rc4_state_struct*)se_alloc(sizeof(rc4_state_struct));
			crypt_rc4_init(data_ptr->request_rc4, data_ptr->request_key[1]->chars, sizeof(gwtb_key_t));
		}
	} else {
		if (check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO, "Unknown Data Transmission");

		if (tree) { /* we are being asked for details */
			gwtb_item = proto_tree_add_item(tree, proto_gwtb, tvb, 0, -1, FALSE);
			gwtb_tree = proto_item_add_subtree(gwtb_item, ett_gwtb);
		}
	}
}

static void dissect_gwtb_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gwtb_entry_t *data_ptr = dissect_gwtb_get_data(pinfo);
	gwtb_info_t *info_ptr = (gwtb_info_t*)p_get_proto_data(pinfo->fd, proto_gwtb);
	proto_item *gwtb_item = NULL;
	proto_tree *gwtb_tree = NULL;	
	guint32 offset = 0;
	guint32 i;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_GWTB);

	if (data_ptr->greeting != NULL) {
		if (check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO, "Authentication Response");

		if (tree) { /* we are being asked for details */
			gwtb_item = proto_tree_add_item(tree, proto_gwtb, tvb, 0, -1, FALSE);
			gwtb_tree = proto_item_add_subtree(gwtb_item, ett_gwtb);

			proto_tree_add_item(gwtb_tree, hf_authkey, tvb, offset, 16, FALSE);
			proto_tree_add_item(gwtb_tree, hf_authkey, tvb, offset+16, 16, FALSE);
		}

		if (data_ptr && data_ptr->response_rc4 == NULL) {
			data_ptr->response_key[0] = (gwtb_key_t *)tvb_get_ptr(tvb, offset, sizeof(gwtb_key_t));
			offset += sizeof(gwtb_key_t);

			data_ptr->response_key[1] = (gwtb_key_t *)tvb_get_ptr(tvb, offset, sizeof(gwtb_key_t));
			offset += sizeof(gwtb_key_t);

			for (i = 0; i < sizeof(gwtb_key_t); i++) {
				data_ptr->response_key[1]->chars[i] ^= data_ptr->response_key[0]->chars[i];
			}

			info_ptr->auth = TRUE;
			data_ptr->response_rc4 = (rc4_state_struct*)se_alloc(sizeof(rc4_state_struct));
			crypt_rc4_init(data_ptr->response_rc4, data_ptr->response_key[1]->chars, sizeof(gwtb_key_t));
		}
	} else {
		if (check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO, "Unknown Data Transmission");

		if (tree) { /* we are being asked for details */
			gwtb_item = proto_tree_add_item(tree, proto_gwtb, tvb, 0, -1, FALSE);
			gwtb_tree = proto_item_add_subtree(gwtb_item, ett_gwtb);
		}
	}
}

static void dissect_gwtb_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gwtb_info_t *info_ptr = (gwtb_info_t*)p_get_proto_data(pinfo->fd, proto_gwtb);
	tvbuff_t *next_tvb;
	proto_item *gwtb_item = NULL;
	proto_tree *gwtb_tree = NULL;
	guint32 offset = 0;
	guint32 length = tvb_length(tvb);
	guint16 size;

	if (!info_ptr->data) {
		info_ptr->auth = FALSE;
		info_ptr->data = (guchar*)se_alloc(length);
		tvb_memcpy(tvb, info_ptr->data, offset, length);
		crypt_rc4(info_ptr->rc4, info_ptr->data, length);
	}

	next_tvb = tvb_new_real_data(info_ptr->data, length, length);
	tvb_set_child_real_data_tvbuff(tvb, next_tvb);
	add_new_data_source(pinfo, next_tvb, "Data");
	length = tvb_length(next_tvb);

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_GWTB);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d - %s", 
			pinfo->srcport, 
			pinfo->destport, 
				(pinfo->match_port == pinfo->destport || TCP_PORT_GWTB == pinfo->destport) ? "Request" : "Response"
		);
	}

	if (tree) { /* we are being asked for details */
		while(offset < length) {
			gwtb_item = proto_tree_add_item(tree, proto_gwtb, next_tvb, offset, length-offset, FALSE);
			gwtb_tree = proto_item_add_subtree(gwtb_item, ett_gwtb);

			size = tvb_get_ntohs(next_tvb, offset);

			proto_tree_add_item(gwtb_tree, hf_length, next_tvb, offset, FRAME_HEADER_LEN, FALSE);
			offset += FRAME_HEADER_LEN;

			proto_tree_add_item(gwtb_tree, hf_string, next_tvb, offset, size, FALSE);
			offset += size;
		}
	}
}

static void dissect_gwtb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gwtb_entry_t *data_ptr = dissect_gwtb_get_data(pinfo);
	gwtb_info_t *info_ptr = (gwtb_info_t*) p_get_proto_data(pinfo->fd, proto_gwtb);

	if (!info_ptr) {
		info_ptr = (gwtb_info_t*)se_alloc(sizeof(gwtb_info_t));
		info_ptr->length = 0;
		info_ptr->auth = FALSE;
		info_ptr->data = NULL;
		p_add_proto_data(pinfo->fd, proto_gwtb, info_ptr);
	}

	if (pinfo->match_port == pinfo->destport || TCP_PORT_GWTB == pinfo->destport) {
		if ((!data_ptr->request_rc4 || info_ptr->auth) && (!info_ptr->data)) {
			tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_REQUEST_LEN, get_gwtb_request_len, dissect_gwtb_request);
		} else if (!info_ptr->auth) {
			info_ptr->rc4 = data_ptr->request_rc4;
			tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN, get_gwtb_message_len, dissect_gwtb_message);
		}
	} else {
		if ((!data_ptr->response_rc4 || info_ptr->auth) && (!info_ptr->data)) {
			tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_RESPONSE_LEN, get_gwtb_response_len, dissect_gwtb_response);
		} else if (!info_ptr->auth) {
			info_ptr->rc4 = data_ptr->response_rc4;
			tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN, get_gwtb_message_len, dissect_gwtb_message);
		}
	}
}

void proto_register_gwtb(void)
{
	/* A header field is something you can search/filter on.
	* 
	* We create a structure to register our fields. It consists of an
	* array of hf_register_info structures, each of which are of the format
	* {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	*/
	static hf_register_info hf[] = {
		{ &hf_gwtb,
			{ "Data", "gwtb.data", FT_NONE, BASE_NONE, NULL, 0x0, "GWTB Data", HFILL }
		},
		{ &hf_greeting,
			{ "Greeting", "gwtb.greeting", FT_BYTES, BASE_NONE, NULL, 0x0, "Greeting", HFILL}
		},
		{ &hf_authkey,
			{ "Auth Key", "gwtb.authkey", FT_BYTES, BASE_NONE, NULL, 0x0, "Auth Key", HFILL}
		},
		{ &hf_length,
			{ "Length", "gwtb.length", FT_UINT16, BASE_DEC, NULL, 0x0, "Length", HFILL}
		},
		{ &hf_string,
			{ "String", "gwtb.string", FT_STRING, BASE_NONE, NULL, 0x0, "String", HFILL}
		}
	};
	static gint *ett[] = {
		&ett_gwtb,
		&ett_greeting,
		&ett_authkey,
		&ett_length,
		&ett_string
	};

	proto_gwtb = proto_register_protocol("GWTB Protocol", PROTO_TAG_GWTB, "gwtb");
	proto_register_field_array(proto_gwtb, hf, array_length (hf));
	proto_register_subtree_array(ett, array_length (ett));

	register_dissector("gwtb", dissect_gwtb, proto_gwtb);
}

void proto_reg_handoff_gwtb(void)
{
	static int gwtb_initialized = FALSE;
	static dissector_handle_t gwtb_handle;

	if (!gwtb_initialized)
	{
		gwtb_handle = create_dissector_handle(dissect_gwtb, proto_gwtb);
		gwtb_initialized = TRUE;
	}
	else
	{
		dissector_delete("tcp.port", TCP_PORT_GWTB, gwtb_handle);
	}

	dissector_add("tcp.port", TCP_PORT_GWTB, gwtb_handle);
}
