/*
 * sssd_dbus_messages_helpers.h
 *
 *  Created on: Jul 9, 2011
 *      Author: r00tkit
 */

#ifndef SSSD_DBUS_MESSAGES_HELPERS_H_
#define SSSD_DBUS_MESSAGES_HELPERS_H_

enum dhash_msgiter_conversion_status {
    SSS_SBUS_CONV_SUCCESS = 0x00,
    SSS_SBUS_DHASH_INVALID,
    SSS_SBUS_DHASH_NULL,
    SSS_SBUS_ITER_MESSAGE_ERR,
    SSS_SBUS_ITER_INVALID_ERR

};

#define INIT_TABLE_SIZE 14

void callback_delete(hash_entry_t *entry, hash_destroy_enum type, void *pvt);

int dbus_dhash_to_msg_iter(hash_table_t **table_in, DBusMessageIter *msg_iter_start);

int dbus_msg_iter_to_dhash(DBusMessageIter *iter, hash_table_t **table_out);

#endif /* SSSD_DBUS_MESSAGES_HELPERS_H_ */
