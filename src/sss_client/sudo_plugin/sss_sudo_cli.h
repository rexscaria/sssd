/*
    SSSD

    Authors:
        Arun Scaria <arunscaria91@gmail.com>

    Copyright (C) 2011 Arun Scaria <arunscaria91@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
 */


#ifndef _SSS_SUDO_CLI_H_
#define _SSS_SUDO_CLI_H_


#ifndef SSS_SUDO_SERVICE_PIPE
#define SSS_SUDO_SERVICE_PIPE "unix:path=" PIPE_PATH "/sudo"
#endif

#undef SSS_SUDO_TIMEOUT
#define SSS_SUDO_TIMEOUT 60

#ifndef SUDO_SERVER_INTERFACE
#define SUDO_SERVER_INTERFACE "org.freedesktop.sssd.sudo"
#endif

#ifndef SUDO_SERVER_PATH
#define SUDO_SERVER_PATH "/org/freedesktop/sssd/sudo"
#endif

#ifndef SUDO_METHOD_QUERY
#define SUDO_METHOD_QUERY "queryService"
#endif

#ifndef CHECK_AND_RETURN_PI_STRING
#define CHECK_AND_RETURN_PI_STRING(s) ((s != NULL && *s != '\0')? s : "(not available)")
#endif

#define INIT_SETTINGS_TABLE_SIZE 15

#define INIT_ENV_TABLE_SIZE 10

#define SUDO_CLIENT_TIMEOUT 60000

#define SSS_SUDO_REPLY_HEADER 0x43256

#ifndef _SSSCLI_H

/* If sss_cli.h is not included */
struct sss_cli_req_data {
    size_t len;
    const void *data;
};


#endif



enum sudo_error_types {

    SSS_SUDO_SUCCESS = 0x01,
    SSS_SUDO_FAILED,
    SSS_SUDO_BUF_ERR,
    SSS_SUDO_CONNECTION_ERR,
    SSS_SUDO_SYSTEM_ERR,
    SSS_SUDO_LOG_ERR,
    SSS_SUDO_LOG_NOTICE,
    SSS_SUDO_MESSAGE_ERR,
    SSS_SUDO_MESSAGE_OK,
    SSS_SUDO_REPLY_ERR,
    SSS_SUDO_REPLY_OK,
    SSS_SUDO_SEND_AND_RECIEVE_OK

};

enum sss_sudo_validation_status {
    SSS_SUDO_VALIDATION_SUCCESS = 0x00,
    SSS_SUDO_VALIDATION_ERR
};


struct sss_sudo_msg_contents
{

    /* from user_info */
    uid_t userid;
    char *cwd;
    char *tty;

    /* from settings */
    char * runas_user;
    char * runas_group;
    char * prompt;
    char * network_addrs;
    int use_sudoedit;
    int use_set_home;
    int use_preserve_environment;
    int use_implied_shell;
    int use_login_shell;
    int use_run_shell;
    int use_preserve_groups;
    int use_ignore_ticket;
    int use_noninteractive;
    int debug_level;

    /*from user_env*/
    char * const * user_env;

    /* command with arguments */
    char * fq_command;
    char ** command;
    int command_count;

    /* Clients pid */
    pid_t cli_pid;

    hash_table_t *settings_table;
    hash_table_t *env_table;
};

struct sudo_result_contents{
    dbus_uint32_t header;
    char * result_str;
    char ** command_array;
    dbus_uint32_t command_array_out_size;
    hash_table_t *env_table_out;
    char ** env_array;
};

#define  SSS_SUDO_ITEM_RUSER                "runas_user"
#define  SSS_SUDO_ITEM_RGROUP               "runas_group"
#define  SSS_SUDO_ITEM_PROMPT               "prompt"
#define  SSS_SUDO_ITEM_NETADDR              "net_addr"
#define  SSS_SUDO_ITEM_USE_SUDOEDIT         "use_sudoedit"
#define  SSS_SUDO_ITEM_USE_SETHOME          "use_sethome"
#define  SSS_SUDO_ITEM_USE_PRESERV_ENV      "use_preserve_env"
#define  SSS_SUDO_ITEM_USE_IMPLIED_SHELL    "use_implied_shell"
#define  SSS_SUDO_ITEM_USE_LOGIN_SHELL      "use_login_shell"
#define  SSS_SUDO_ITEM_USE_RUN_SHELL        "use_run_shell"
#define  SSS_SUDO_ITEM_USE_PRE_GROUPS       "use_preserve_groups"
#define  SSS_SUDO_ITEM_USE_IGNORE_TICKET    "use_ignore_ticket"
#define  SSS_SUDO_ITEM_USE_NON_INTERACTIVE  "use_non_interactive"
#define  SSS_SUDO_ITEM_DEBUG_LEVEL          "use_debug_level"
#define  SSS_SUDO_ITEM_CLI_PID              "client_pid"


#define SUDO_ALLOW_ACCESS_STR  "ALLOW"
#define SUDO_DENY_ACCESS_STR   "DENY"

#define SUDO_ALLOW_CMD_EXECUTION  1
#define SUDO_DENY_CMD_EXECUTION   0
#define SUDO_ERR_CMD_EXECUTION    -1


#endif  /* _SSS_SUDO_CLI_H_ */
