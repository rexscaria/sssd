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


#ifndef SSSD_DBUS_MESSAGES_HELPERS_H_
#define SSSD_DBUS_MESSAGES_HELPERS_H_

#define INIT_TABLE_SIZE 14

enum dhash_msgiter_conversion_status {
    SSS_SBUS_CONV_SUCCESS = 0x00,
    SSS_SBUS_DHASH_INVALID,
    SSS_SBUS_DHASH_NULL,
    SSS_SBUS_ITER_MESSAGE_ERR,
    SSS_SBUS_ITER_INVALID_ERR
};

void callback_delete(hash_entry_t *entry,
                     hash_destroy_enum type,
                     void *pvt);

int dbus_dhash_to_msg_iter(hash_table_t **stable_in,
                           DBusMessageIter *msg_iter_start);

int dbus_msg_iter_to_dhash(DBusMessageIter *iter,
                           hash_table_t **table_out);

#endif /* SSSD_DBUS_MESSAGES_HELPERS_H_ */
