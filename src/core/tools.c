/*
 * Copyright (C) 2007 Colin DIDIER
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

#define _POSIX_SOURCE 1
#define _BSD_SOURCE 1
#define _SVID_SOURCE 1
#include <stdio.h>

#include <string.h>

#include "module.h"
#include "recode.h"
#include "settings.h"
#include "signals.h"
#include "xmpp-servers.h"

#define XMPP_PRIORITY_MIN -128
#define XMPP_PRIORITY_MAX 127

static const char *utf8_charset = "UTF-8";

char *call_gpg(char *switches, char *input, char *input2, \
               int get_stderr, int snip_data) {
	int pipefd[2], tmp_fd, tmp2_fd = 0, in_data = !snip_data;
	FILE *cstream;
	char *cmd, *tmp_path, *tmp2_path = NULL, *output = NULL;
	size_t output_size = 0;
	char buf[100], buf2[100] = "";
	const char *keyid = settings_get_str("xmpp_pgp");

	if(keyid) { /* If no keyID, then we don't need a password */
		if(pipe(pipefd)) goto pgp_error;
		if(!pgp_passwd) pgp_passwd = get_password("OpenPGP Password:");

		if(write(pipefd[1], pgp_passwd, strlen(pgp_passwd)) < 1) goto pgp_error;
		if(close(pipefd[1])) goto pgp_error;
	}

	if(!(tmp_path = tempnam(NULL, "irssi-xmpp-gpg"))) goto pgp_error;
	if((tmp_fd = open(tmp_path, O_WRONLY|O_CREAT|O_EXCL, \
		 S_IRUSR|S_IWUSR)) < 0)
		goto pgp_error;

	if(write(tmp_fd, input, strlen(input)) < 0) goto pgp_error;

	if(input2) {
		if(!(tmp2_path = tempnam(NULL, "irssi-xmpp-gpg"))) goto pgp_error;
		if((tmp2_fd = open(tmp2_path, O_WRONLY|O_CREAT|O_EXCL, \
			 S_IRUSR|S_IWUSR)) < 0)
			goto pgp_error;

		if(write(tmp2_fd, input2, strlen(input2)) < 0) goto pgp_error;
	}

	cmd = malloc(sizeof("gpg -u '' --passphrase-fd '' -qo - --batch " \
	              "--no-tty '' '' 2>/dev/null") \
	              +strlen(switches)+8+strlen(tmp_path)+ \
	              (tmp2_path ? strlen(tmp2_path) : 0));
	if(keyid) {
		sprintf(cmd, "gpg -u '%s' --passphrase-fd '%d' ", keyid, pipefd[0]);
	} else {
		strcpy(cmd, "gpg ");
	}
	strcat(cmd, switches);
	strcat(cmd, " -qo - --batch --no-tty '");
	strcat(cmd, tmp_path);
	strcat(cmd, "' ");

	if(tmp2_path) {
		strcat(cmd, "'");
		strcat(cmd, tmp2_path);
		strcat(cmd, "'");
	}

	if(get_stderr) {
		strcat(cmd, " 2>&1");
	} else {
		strcat(cmd, " 2>/dev/null");
	}

	fflush(NULL);
	cstream = popen(cmd, "r");

	while(fgets(buf, sizeof(buf)-1, cstream)) {
		if(strlen(buf2) > 0) {
			output = realloc(output, output_size+strlen(buf2)+1);
			if(!output) goto pgp_error;
			if(output_size < 1) output[0] = '\0';
			output_size += strlen(buf2);
			strcat(output, buf2);
		}

		if(!in_data && buf[0] == '\n') {
			in_data = 1;
			continue;
		} else if(in_data) {
			strcpy(buf2, buf);
		}
	}

	/* Get last line if not snipping */
	if(!snip_data && strlen(buf2) > 0) {
		output = realloc(output, output_size+strlen(buf2)+1);
		if(!output) goto pgp_error;
		if(output_size < 1) output[0] = '\0';
		output_size += strlen(buf2);
		strcat(output, buf2);
	}

	pclose(cstream); /* TODO: check exit code */

	close(tmp_fd);
	free(tmp_path);
	if(tmp2_fd)   close(tmp2_fd);
	if(tmp2_path) free(tmp2_path);
	if(keyid)     close(pipefd[0]);
	free(cmd);

	return output;
pgp_error:
	return NULL;
}



static gboolean
xmpp_get_local_charset(G_CONST_RETURN char **charset)
{
	*charset = settings_get_str("term_charset");
	if (is_valid_charset(*charset))
		return (g_ascii_strcasecmp(*charset, utf8_charset) == 0);
	return g_get_charset(charset);
}

char *
xmpp_recode_out(const char *str)
{
	G_CONST_RETURN char *charset;
	char *recoded, *stripped;

	if (str == NULL || *str == '\0')
		return NULL;
	recoded = stripped = NULL;
	signal_emit("xmpp formats strip codes", 2, str, &stripped);
	if (stripped != NULL) 
		str = stripped;
	if (!xmpp_get_local_charset(&charset) && charset != NULL)
		recoded = g_convert_with_fallback(str, -1, utf8_charset,
		    charset, NULL, NULL, NULL, NULL);
	recoded = recoded != NULL ? recoded : g_strdup(str);
	g_free(stripped);
	return recoded;
}

char *
xmpp_recode_in(const char *str)
{
	G_CONST_RETURN char *charset;
	char *recoded, *to = NULL;

	if (str == NULL || *str == '\0')
		return NULL;
	if (xmpp_get_local_charset(&charset) || charset == NULL)
		return g_strdup(str);
	if (settings_get_bool("recode_transliterate") &&
	    g_ascii_strcasecmp(charset, "//TRANSLIT") != 0)
		charset = to = g_strconcat(charset ,"//TRANSLIT", (void *)NULL);
	recoded = g_convert_with_fallback(str, -1, charset, utf8_charset, NULL,
	    NULL, NULL, NULL);
	g_free(to);
	return (recoded != NULL) ? recoded : g_strdup(str);
}

char *
xmpp_find_resource_sep(const char *jid)
{
	return jid == NULL ? NULL : g_utf8_strchr(jid, -1, '/');
}

char *
xmpp_extract_resource(const char *jid)
{
        char *pos;

        g_return_val_if_fail(jid != NULL, NULL);
        pos = xmpp_find_resource_sep(jid);
	return (pos != NULL) ? g_strdup(pos + 1) : NULL;
}

char *
xmpp_strip_resource(const char *jid)
{
        char *pos;

        g_return_val_if_fail(jid != NULL, NULL);
        pos = xmpp_find_resource_sep(jid);
	return (pos != NULL) ? g_strndup(jid, pos - jid) : g_strdup(jid);
}

char *
xmpp_extract_user(const char *jid)
{
        char *pos;

        g_return_val_if_fail(jid != NULL, NULL);
        pos = g_utf8_strchr(jid, -1, '@');
	return (pos != NULL) ? g_strndup(jid, pos - jid) :
	    xmpp_strip_resource(jid);
}

char *
xmpp_extract_domain(const char *jid)
{
	char *pos1, *pos2;

	pos1 = g_utf8_strchr(jid, -1, '@');
	pos2 = xmpp_find_resource_sep(jid);
	if (pos1 == NULL)
		return NULL;
	if (pos2 != NULL && pos2 < pos1)
		return g_strdup(pos1 + 1);
	return (pos2 != NULL) ? 
		g_strndup(pos1 + 1, pos2 - pos1 - 1) : g_strdup(pos1 + 1);
}

gboolean
xmpp_have_domain(const char *jid)
{
	char *pos;

        g_return_val_if_fail(jid != NULL, FALSE);
	pos = g_utf8_strchr(jid, -1, '@');
	return (pos != NULL && *(pos+1) != '\0');
}

gboolean
xmpp_have_resource(const char *jid)
{
	char *pos;

        g_return_val_if_fail(jid != NULL, FALSE);
	pos = xmpp_find_resource_sep(jid);
        return (pos != NULL && *(pos+1) != '\0');
}

gboolean
xmpp_priority_out_of_bound(const int priority)
{
        return (XMPP_PRIORITY_MIN <= priority
            && priority <= XMPP_PRIORITY_MAX) ? FALSE : TRUE;
}

gboolean
xmpp_presence_changed(const int show, const int old_show, const char *status,
    const char *old_status, const int priority, const int old_priority)
{
	return (show != old_show)
	    || (status == NULL && old_status != NULL)
	    || (status != NULL && old_status == NULL)
	    || (status != NULL && old_status != NULL
	    && strcmp(status, old_status) != 0)
	    || (priority != old_priority);
}
