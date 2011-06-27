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

#define SUDO_INTERFACE "org.freedesktop.sssd.sudo"
#define SUDO_PATH "/org/freedesktop/sssd/sudo"
#define SUDO_METHOD_QUERY "queryService"

static int sudo_query_validation(DBusMessage *message, struct sbus_connection *conn);
struct sbus_method sudo_methods[] = {
  
    { SUDO_METHOD_QUERY, sudo_query_validation },
    { NULL, NULL }
};

struct sbus_interface sudo_interface = {
    SUDO_INTERFACE,
    SUDO_PATH,
    SBUS_DEFAULT_VTABLE,
    sudo_methods,
    NULL
};

struct sudo_ctx {
    struct tevent_context *ev;
    struct confdb_ctx *cdb;
    
    struct sbus_connection *mon_conn;
    struct sbus_connection *sbus_srv;

    size_t check_online_ref_count;
};

struct sudo_client {
    struct sudo_ctx *sudoctx;
    struct sbus_connection *conn;
    struct tevent_timer *timeout;
    bool initialized;
};

#endif