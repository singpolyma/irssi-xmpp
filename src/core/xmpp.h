#ifndef __XMPP_H
#define __XMPP_H

typedef struct _XMPP_SERVER_CONNECT_REC XMPP_SERVER_CONNECT_REC;
typedef struct _XMPP_SERVER_REC XMPP_SERVER_REC;
typedef struct _XMPP_QUERY_REC XMPP_QUERY_REC;
typedef struct _XMPP_NICK_REC XMPP_NICK_REC;
typedef struct _MUC_REC MUC_REC;

#define XMPP_PROTOCOL_NAME "XMPP"
#define XMPP_PROTOCOL (chat_protocol_lookup(XMPP_PROTOCOL_NAME))

#define IRSSI_XMPP_PACKAGE "irssi-xmpp"
#define IRSSI_XMPP_VERSION "0.53"

extern char *pgp_passwd;

#endif
