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


#ifndef _SSSCLI_H

   /* If sss_cli.h is not imported */
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

};



enum sudo_item_type{

  SSS_SUDO_ITEM_UID = 0x0000,
  SSS_SUDO_ITEM_CWD,
  SSS_SUDO_ITEM_TTY,
  SSS_SUDO_ITEM_RUSER,
  SSS_SUDO_ITEM_RGROUP,
  SSS_SUDO_ITEM_PROMPT,
  SSS_SUDO_ITEM_NETADDR,
  SSS_SUDO_ITEM_USE_SUDOEDIT,
  SSS_SUDO_ITEM_USE_SETHOME,
  SSS_SUDO_ITEM_USE_PRESERV_ENV,
  SSS_SUDO_ITEM_USE_IMPLIED_SHELL,
  SSS_SUDO_ITEM_USE_LOGIN_SHELL,
  SSS_SUDO_ITEM_USE_RUN_SHELL,
  SSS_SUDO_ITEM_USE_PRE_GROUPS,
  SSS_SUDO_ITEM_USE_IGNORE_TICKET,
  SSS_SUDO_ITEM_USE_NON_INTERACTIVE,
  SSS_SUDO_ITEM_DEBUG_LEVEL,
  SSS_SUDO_ITEM_COMMAND,
  SSS_SUDO_ITEM_USER_ENV,
  SSS_SUDO_ITEM_CLI_PID

};

#endif  /* _SSS_SUDO_CLI_H_ */
