/*
 * Copyright (C) 2007,2008,2009 Colin DIDIER
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "module.h"
#include "signals.h"
#include "settings.h"

#include "xmpp-servers.h"
#include "rosters-tools.h"
#include "tools.h"
#include "xep/disco.h"

char *pgp_passwd = NULL;

static void
sig_set_presence(XMPP_SERVER_REC *server, const int show, const char *status,
    const int priority)
{
	LmMessage *lmsg;
	char *str;
	const char *pgp_keyid;

	g_return_if_fail(IS_XMPP_SERVER(server));
	if (!xmpp_presence_changed(show, server->show, status,
	    server->away_reason, priority, server->priority)) {
		signal_stop();
		return;
	}

	lmsg = lm_message_new(NULL, LM_MESSAGE_TYPE_PRESENCE);
	server->show = show;

	if (!xmpp_priority_out_of_bound(priority))
		server->priority = priority;

	if (show != XMPP_PRESENCE_AVAILABLE)
		lm_message_node_add_child(lmsg->node, "show",
		    xmpp_presence_show[server->show]);

	if(server->away_reason) g_free(server->away_reason);
	server->away_reason = NULL;

	if(!status) status = "";
	server->away_reason = g_strdup(status);
	str = xmpp_recode_out(server->away_reason);
	lm_message_node_add_child(lmsg->node, "status", str);
	if(!str) str = g_strdup("");

	if((pgp_keyid = settings_get_str("xmpp_pgp"))) {
		LmMessageNode *x;
		char *signature = call_gpg("-ab", str, NULL, 0, 1);
		disco_add_feature("jabber:x:signed");
		disco_add_feature("jabber:x:encrypted");

		if(signature) {
			x = lm_message_node_add_child(lmsg->node, "x", signature);
			lm_message_node_set_attribute(x, "xmlns", "jabber:x:signed");

			free(signature);
		}
	}

	g_free(str);

	str = g_strdup_printf("%d", server->priority);
	lm_message_node_add_child(lmsg->node, "priority", str);
	g_free(str);

	signal_emit("xmpp send presence", 2, server, lmsg);
	lm_message_unref(lmsg);
	if (show != XMPP_PRESENCE_AVAILABLE) /* away */
		signal_emit("event 306", 2, server, server->jid);
	else if (server->usermode_away) /* unaway */
		signal_emit("event 305", 2, server, server->jid);
}

static void
sig_recv_message(XMPP_SERVER_REC *server, LmMessage *lmsg, const int type,
    const char *id, const char *from, const char *to)
{
	LmMessageNode *node, *encrypted;
	char *str, *subject;
	
	if ((type != LM_MESSAGE_SUB_TYPE_NOT_SET
	    && type != LM_MESSAGE_SUB_TYPE_HEADLINE
	    && type != LM_MESSAGE_SUB_TYPE_NORMAL
	    && type != LM_MESSAGE_SUB_TYPE_CHAT)
	    || server->ischannel(SERVER(server), from))
		return;
	node = lm_message_node_get_child(lmsg->node, "subject");
	if (node != NULL && node->value != NULL && *node->value != '\0') {
		str = xmpp_recode_in(node->value);
		subject = g_strconcat("Subject: ", str, (void *)NULL);
		g_free(str);
		signal_emit("message private", 4, server, subject, from, from);
		g_free(subject);
	}

	str = NULL;
	encrypted = lm_find_node(lmsg->node, "x", "xmlns", "jabber:x:encrypted");
	if(encrypted && encrypted->value) {
		/* TODO: indicate the message was encrypted */
		/* TODO: verify signatures */
		char *send_to_gpg = malloc(sizeof( \
			"-----BEGIN PGP MESSAGE-----\n\n" \
			"-----END PGP MESSAGE-----\n")+ \
			strlen(encrypted->value)+1 \
		);
		char *from_gpg;

		send_to_gpg[0] = '\0';
		strcat(send_to_gpg, "-----BEGIN PGP MESSAGE-----\n\n");
		strcat(send_to_gpg, encrypted->value);
		strcat(send_to_gpg, "-----END PGP MESSAGE-----\n");

		from_gpg = call_gpg("-d", send_to_gpg, NULL, 0, 0);
		if(from_gpg) {
			str = xmpp_recode_in(from_gpg);
			free(from_gpg);
		}

		free(send_to_gpg);
	} else {
		node = lm_message_node_get_child(lmsg->node, "body");
		if (node != NULL && node->value != NULL && *node->value != '\0') {
			str = xmpp_recode_in(node->value);
		}
	}
	if(str) {
		if (g_ascii_strncasecmp(str, "/me ", 4) == 0)
			signal_emit("message xmpp action", 5,
			    server, str+4, from, from,
			    GINT_TO_POINTER(SEND_TARGET_NICK));
		else
			signal_emit("message private", 4, server,
			    str, from, from);
		g_free(str);
	}
}

void
protocol_init(void)
{
	signal_add_first("xmpp set presence", sig_set_presence);
	signal_add("xmpp recv message", sig_recv_message);
}

void
protocol_deinit(void)
{
	signal_remove("xmpp set presence", sig_set_presence);
	signal_remove("xmpp recv message", sig_recv_message);
}
