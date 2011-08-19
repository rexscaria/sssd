/*
   SSSD

   SUDO Responder

   Copyright (C)  Arun Scaria <arunscaria91@gmail.com> (2011)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _SUDOSRV_PRIVATE_H_
#define _SUDOSRV_PRIVATE_H_


#define CONFDB_SUDO_CONF_ENTRY "config/sudo"

#ifndef SSS_SUDO_SERVICE_PIPE
#define SSS_SUDO_SERVICE_PIPE "unix:path=" PIPE_PATH "/sudo"
#endif

#ifndef SUDO_SERVER_INTERFACE
#define SUDO_SERVER_INTERFACE "org.freedesktop.sssd.sudo"
#endif

#ifndef SUDO_SERVER_PATH
#define SUDO_SERVER_PATH "/org/freedesktop/sssd/sudo"
#endif

#ifndef SUDO_METHOD_QUERY
#define SUDO_METHOD_QUERY "queryService"
#endif
#define SUDO_DP_INTERFACE "org.freedesktop.sssd.sudo.dataprovider"
#define SUDO_DP_PATH      "/org/freedesktop/sssd/sudo/dataprovider"
#define SUDO_DP_METHOD_QUERY "queryDPService"


#define SSS_SUDO_RESPONDER_HEADER 0x43256

#define SSS_SUDO_SBUS_SERVICE_VERSION 0x0001
#define SSS_SUDO_SBUS_SERVICE_NAME "sudo"

#define CONFDB_SERVICE_RECON_RETRIES "reconnection_retries"
#define CONFDB_SUDO_ENTRY_NEG_TIMEOUT "entry_negative_timeout"
#define CONFDB_SUDO_ID_TIMEOUT "sudo_id_timeout"

static int sudo_query_validation(DBusMessage *message, struct sbus_connection *conn);
struct sbus_method sudo_methods[] = {

                                     { SUDO_METHOD_QUERY, sudo_query_validation },
                                     { NULL, NULL }
};

struct sbus_interface sudo_monitor_interface = {
                                                SUDO_SERVER_INTERFACE,
                                                SUDO_SERVER_PATH,
                                                SBUS_DEFAULT_VTABLE,
                                                sudo_methods,
                                                NULL
};

struct sbus_interface sudo_dp_interface = {
                                           SUDO_DP_INTERFACE,
                                           SUDO_DP_PATH,
                                           SBUS_DEFAULT_VTABLE,
                                           NULL/*sudo_dp_methods*/,
                                           NULL
};

struct sudo_ctx {
    struct resp_ctx *rctx;
    struct sss_nc_ctx *ncache;

    int neg_timeout;
    time_t id_timeout;
};

struct sudo_cmd_ctx {
    int negated;
    char * fqcomnd;
    char * arg;
};
struct sudo_client {
    struct sudo_ctx *sudoctx;
    struct sbus_connection *conn;
    struct tevent_timer *timeout;
    bool initialized;
};

/*the Dlinked list structure for sudo rules */

struct sss_sudorule_list
{
    struct ldb_message *data;

    struct sss_sudorule_list *next;
    struct sss_sudorule_list *prev;
} ;

struct sss_valid_sudorules
{
    struct ldb_message *default_rule;
    struct sss_sudorule_list *non_defaults;
};

enum error_types_sudo_responder{

    SSS_SUDO_RESPONDER_SUCCESS = 0x01,
    SSS_SUDO_RESPONDER_FAILED,
    SSS_SUDO_RESPONDER_BUF_ERR,
    SSS_SUDO_RESPONDER_CONNECTION_ERR,
    SSS_SUDO_RESPONDER_SYSTEM_ERR,
    SSS_SUDO_RESPONDER_LOG_ERR,
    SSS_SUDO_RESPONDER_MESSAGE_ERR,
    SSS_SUDO_RESPONDER_REPLY_ERR,
    SSS_SUDO_RESPONDER_DHASH_ERR,
    SSS_SUDO_RESPONDER_MEMORY_ERR,
    SSS_SUDO_RESPONDER_PARSE_ERR

};
#endif
