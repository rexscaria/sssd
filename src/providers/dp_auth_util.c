/*
   SSSD

   Data Provider, auth utils

   Copyright (C) Sumit Bose <sbose@redhat.com>	2009

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

#include "data_provider.h"

void pam_print_data(int l, struct pam_data *pd)
{
    DEBUG(l, ("command: %d\n", pd->cmd));
    DEBUG(l, ("domain: %s\n", pd->domain));
    DEBUG(l, ("user: %s\n", pd->user));
    DEBUG(l, ("service: %s\n", pd->service));
    DEBUG(l, ("tty: %s\n", pd->tty));
    DEBUG(l, ("ruser: %s\n", pd->ruser));
    DEBUG(l, ("rhost: %s\n", pd->rhost));
    DEBUG(l, ("authtok type: %d\n", pd->authtok_type));
    DEBUG(l, ("authtok size: %d\n", pd->authtok_size));
    DEBUG(l, ("newauthtok type: %d\n", pd->newauthtok_type));
    DEBUG(l, ("newauthtok size: %d\n", pd->newauthtok_size));
    DEBUG(l, ("priv: %d\n", pd->priv));
    DEBUG(l, ("cli_pid: %d\n", pd->cli_pid));
}

int pam_add_response(struct pam_data *pd, enum response_type type,
                     int len, const uint8_t *data)
{
    struct response_data *new;

    new = talloc(pd, struct response_data);
    if (new == NULL) return ENOMEM;

    new->type = type;
    new->len = len;
    new->data = talloc_memdup(pd, data, len);
    if (new->data == NULL) return ENOMEM;
    new->next = pd->resp_list;
    pd->resp_list = new;

    return EOK;
}

bool dp_pack_pam_request(DBusMessage *msg, struct pam_data *pd)
{
    int ret;

    if (pd->user == NULL) return false;
    if (pd->service == NULL) pd->service = talloc_strdup(pd, "");
    if (pd->tty == NULL) pd->tty = talloc_strdup(pd, "");
    if (pd->ruser == NULL) pd->ruser = talloc_strdup(pd, "");
    if (pd->rhost == NULL) pd->rhost = talloc_strdup(pd, "");


    ret = dbus_message_append_args(msg,
                                   DBUS_TYPE_INT32,  &(pd->cmd),
                                   DBUS_TYPE_STRING, &(pd->user),
                                   DBUS_TYPE_STRING, &(pd->service),
                                   DBUS_TYPE_STRING, &(pd->tty),
                                   DBUS_TYPE_STRING, &(pd->ruser),
                                   DBUS_TYPE_STRING, &(pd->rhost),
                                   DBUS_TYPE_UINT32, &(pd->authtok_type),
                                   DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
                                       &(pd->authtok),
                                       (pd->authtok_size),
                                   DBUS_TYPE_UINT32, &(pd->newauthtok_type),
                                   DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
                                       &(pd->newauthtok),
                                       pd->newauthtok_size,
                                   DBUS_TYPE_INT32, &(pd->priv),
                                   DBUS_TYPE_UINT32, &(pd->cli_pid),
                                   DBUS_TYPE_INVALID);

    return ret;
}

bool dp_unpack_pam_request(DBusMessage *msg, struct pam_data *pd, DBusError *dbus_error)
{
    int ret;

    ret = dbus_message_get_args(msg, dbus_error,
                                DBUS_TYPE_INT32,  &(pd->cmd),
                                DBUS_TYPE_STRING, &(pd->user),
                                DBUS_TYPE_STRING, &(pd->service),
                                DBUS_TYPE_STRING, &(pd->tty),
                                DBUS_TYPE_STRING, &(pd->ruser),
                                DBUS_TYPE_STRING, &(pd->rhost),
                                DBUS_TYPE_UINT32, &(pd->authtok_type),
                                DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
                                    &(pd->authtok),
                                    &(pd->authtok_size),
                                DBUS_TYPE_UINT32, &(pd->newauthtok_type),
                                DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
                                    &(pd->newauthtok),
                                    &(pd->newauthtok_size),
                                DBUS_TYPE_INT32, &(pd->priv),
                                DBUS_TYPE_UINT32, &(pd->cli_pid),
                                DBUS_TYPE_INVALID);

    return ret;
}

bool dp_pack_pam_response(DBusMessage *msg, struct pam_data *pd)
{
    dbus_bool_t dbret;
    struct response_data *resp;
    DBusMessageIter iter;
    DBusMessageIter array_iter;
    DBusMessageIter struct_iter;
    DBusMessageIter data_iter;

    dbus_message_iter_init_append(msg, &iter);

    /* Append the PAM status */
    dbret = dbus_message_iter_append_basic(&iter,
                                   DBUS_TYPE_UINT32, &(pd->pam_status));
    if (!dbret) {
        return false;
    }

    /* Create an array of response structures */
    dbret = dbus_message_iter_open_container(&iter,
                                             DBUS_TYPE_ARRAY, "(uay)",
                                             &array_iter);
    if (!dbret) {
        return false;
    }

    resp = pd->resp_list;
    while (resp != NULL) {
        /* Create a DBUS struct */
        dbret = dbus_message_iter_open_container(&array_iter,
                                                 DBUS_TYPE_STRUCT, NULL,
                                                 &struct_iter);
        if (!dbret) {
            return false;
        }

        /* Add the response type */
        dbret = dbus_message_iter_append_basic(&struct_iter,
                                               DBUS_TYPE_UINT32,
                                               &(resp->type));
        if (!dbret) {
            return false;
        }

        /* Add the response message */
        dbret = dbus_message_iter_open_container(&struct_iter,
                                                 DBUS_TYPE_ARRAY, "y",
                                                 &data_iter);
        if (!dbret) {
            return false;
        }
        dbret = dbus_message_iter_append_fixed_array(&data_iter,
                       DBUS_TYPE_BYTE, &(resp->data), resp->len);
        if (!dbret) {
            return false;
        }
        dbret = dbus_message_iter_close_container(&struct_iter, &data_iter);
        if (!dbret) {
            return false;
        }

        resp = resp->next;
        dbret = dbus_message_iter_close_container(&array_iter, &struct_iter);
        if (!dbret) {
            return false;
        }
    }

    /* Close the struct array */
    dbret = dbus_message_iter_close_container(&iter, &array_iter);
    if (!dbret) {
        return false;
    }

    return true;
}

bool dp_unpack_pam_response(DBusMessage *msg, struct pam_data *pd, DBusError *dbus_error)
{
    DBusMessageIter iter;
    DBusMessageIter array_iter;
    DBusMessageIter struct_iter;
    DBusMessageIter sub_iter;
    int type;
    int len;
    const uint8_t *data;

    if (!dbus_message_iter_init(msg, &iter)) {
        DEBUG(1, ("pam response has no arguments.\n"));
        return false;
    }

    if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32) {
        DEBUG(1, ("pam response format error.\n"));
        return false;
    }
    dbus_message_iter_get_basic(&iter, &(pd->pam_status));

    if (!dbus_message_iter_next(&iter)) {
        DEBUG(1, ("pam response has too few arguments.\n"));
        return false;
    }

    /* After this point will be an array of pam data */
    if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
        DEBUG(1, ("pam response format error.\n"));
        DEBUG(1, ("Type was %c\n", (char)dbus_message_iter_get_arg_type(&iter)));
        return false;
    }

    if (dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT) {
        DEBUG(1, ("pam response format error.\n"));
        return false;
    }

    dbus_message_iter_recurse(&iter, &array_iter);
    while (dbus_message_iter_get_arg_type(&array_iter) != DBUS_TYPE_INVALID) {
        /* Read in a pam data struct */
        if (dbus_message_iter_get_arg_type(&array_iter) != DBUS_TYPE_STRUCT) {
            DEBUG(1, ("pam response format error.\n"));
            return false;
        }

        dbus_message_iter_recurse(&array_iter,  &struct_iter);

        /* PAM data struct contains a type and a byte-array of data */

        /* Get the pam data type */
        if (dbus_message_iter_get_arg_type(&struct_iter) != DBUS_TYPE_UINT32) {
            DEBUG(1, ("pam response format error.\n"));
            return false;
        }
        dbus_message_iter_get_basic(&struct_iter, &type);

        if (!dbus_message_iter_next(&struct_iter)) {
            DEBUG(1, ("pam response format error.\n"));
            return false;
        }

        /* Get the byte array */
        if (dbus_message_iter_get_arg_type(&struct_iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&struct_iter) != DBUS_TYPE_BYTE) {
            DEBUG(1, ("pam response format error.\n"));
            return false;
        }

        dbus_message_iter_recurse(&struct_iter, &sub_iter);
        dbus_message_iter_get_fixed_array(&sub_iter, &data, &len);

        pam_add_response(pd, type, len, data);
        dbus_message_iter_next(&array_iter);
    }

    return true;
}

static void id_callback(DBusPendingCall *pending, void *ptr)
{
    DBusMessage *reply;
    DBusError dbus_error;
    dbus_bool_t ret;
    dbus_uint16_t dp_ver;
    int type;

    dbus_error_init(&dbus_error);

    reply = dbus_pending_call_steal_reply(pending);
    if (!reply) {
        /* reply should never be null. This function shouldn't be called
         * until reply is valid or timeout has occurred. If reply is NULL
         * here, something is seriously wrong and we should bail out.
         */
        DEBUG(0, ("Severe error. A reply callback was called but no"
                  " reply was received and no timeout occurred\n"));

        /* FIXME: Destroy this connection ? */
        goto done;
    }

    type = dbus_message_get_type(reply);
    switch (type) {
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        ret = dbus_message_get_args(reply, &dbus_error,
                                    DBUS_TYPE_UINT16, &dp_ver,
                                    DBUS_TYPE_INVALID);
        if (!ret) {
            DEBUG(1, ("Failed to parse message\n"));
            if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
            /* FIXME: Destroy this connection ? */
            goto done;
        }

        DEBUG(4, ("Got id ack and version (%d) from DP\n", dp_ver));

        break;

    case DBUS_MESSAGE_TYPE_ERROR:
        DEBUG(0,("The Monitor returned an error [%s]\n",
                 dbus_message_get_error_name(reply)));
        /* Falling through to default intentionally*/
    default:
        /*
         * Timeout or other error occurred or something
         * unexpected happened.
         * It doesn't matter which, because either way we
         * know that this connection isn't trustworthy.
         * We'll destroy it now.
         */

        /* FIXME: Destroy this connection ? */
        break;
    }

done:
    dbus_pending_call_unref(pending);
    dbus_message_unref(reply);
}

int dp_common_send_id(struct sbus_connection *conn, uint16_t version,
                      const char *name)
{
    DBusPendingCall *pending_reply;
    DBusConnection *dbus_conn;
    DBusMessage *msg;
    dbus_bool_t ret;

    dbus_conn = sbus_get_connection(conn);

    /* create the message */
    msg = dbus_message_new_method_call(NULL,
                                       DP_PATH,
                                       DP_INTERFACE,
                                       DP_METHOD_REGISTER);
    if (msg == NULL) {
        DEBUG(0, ("Out of memory?!\n"));
        return ENOMEM;
    }

    DEBUG(4, ("Sending ID to DP: (%d,%s)\n",
              version, name));

    ret = dbus_message_append_args(msg,
                                   DBUS_TYPE_UINT16, &version,
                                   DBUS_TYPE_STRING, &name,
                                   DBUS_TYPE_INVALID);
    if (!ret) {
        DEBUG(1, ("Failed to build message\n"));
        return EIO;
    }

    ret = dbus_connection_send_with_reply(dbus_conn, msg, &pending_reply,
                                          30000 /* TODO: set timeout */);
    if (!ret || !pending_reply) {
        /*
         * Critical Failure
         * We can't communicate on this connection
         * We'll drop it using the default destructor.
         */
        DEBUG(0, ("D-BUS send failed.\n"));
        dbus_message_unref(msg);
        return EIO;
    }

    /* Set up the reply handler */
    dbus_pending_call_set_notify(pending_reply, id_callback, NULL, NULL);
    dbus_message_unref(msg);

    return EOK;
}
