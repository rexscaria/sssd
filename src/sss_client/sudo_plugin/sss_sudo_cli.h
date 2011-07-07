/*
    SSSD

    sss_sudo_cli.h

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


#undef SSS_END_OF_SUDO_REQUEST
#define SSS_END_OF_SUDO_REQUEST 0x405645

#undef SSS_START_OF_SUDO_REQUEST
#define SSS_START_OF_SUDO_REQUEST 0x436789

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

#ifndef _SSSCLI_H

   /* If sss_cli.h is not included */
struct sss_cli_req_data {
    size_t len;
    const void *data;
};

enum sss_status {
    SSS_STATUS_TRYAGAIN,
    SSS_STATUS_UNAVAIL,
    SSS_STATUS_SUCCESS
};

#endif 

enum error_types_sudo{

  SSS_SUDO_SUCCESS = 0x01,
  SSS_SUDO_BUF_ERR,
  SSS_SUDO_SYSTEM_ERR,
  SSS_SUDO_LOG_ERR,
  SSS_SUDO_LOG_NOTICE,
  SSS_SUDO_MESSAGE_ERR

};

enum sss_sudo_validation_status {
    SSS_SUDO_VALIDATION_SUCCESS = 0x00,
    SSS_SUDO_VALIDATION_ERR
};



enum sudo_nullable_item_type{

  SSS_SUDO_ITEM_CWD = 0x0001,
  SSS_SUDO_ITEM_TTY = 0x0002,
  SSS_SUDO_ITEM_RUSER = 0x0004,
  SSS_SUDO_ITEM_RGROUP = 0x0008,
  SSS_SUDO_ITEM_PROMPT = 0x0010,
  SSS_SUDO_ITEM_NETADDR = 0x0020,
  SSS_SUDO_ITEM_COMMAND = 0x0040,
  SSS_SUDO_ITEM_USER_ENV = 0x0080,

};

static struct sss_sudo_msg_contents
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
  char * * user_env;
 
  /* command with arguments */
  char ** command;
  int command_count;

  /* Clients pid */
  int cli_pid;
};

#endif  /* _SSS_SUDO_CLI_H_ */
