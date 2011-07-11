/*
 * sssd_dbus_messages_helpers.c
 *
 *  Created on: Jul 9, 2011
 *      Author: r00tkit
 */

#include <sys/time.h>
#include <errno.h>
#include "util/util.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_private.h"
#include <dhash.h>
#include "sbus/sssd_dbus_messages_helpers.h"


void callback_delete(hash_entry_t *entry, hash_destroy_enum type, void *pvt)
{
    if (entry->value.type == HASH_VALUE_PTR)
        free(entry->value.ptr);
}

int dbus_dhash_to_msg_iter(hash_table_t **table_in,
                           DBusMessageIter *msg_iter_start)
{

    hash_table_t *  local_table = NULL;
    hash_entry_t *entry;
    struct hash_iter_context_t *iter;

    char * str_value,*str_key;

    DBusMessageIter *msg_iter;
    DBusMessageIter sub_iter;
    DBusMessageIter dict_iter;

    msg_iter = msg_iter_start;

    if( !table_in && !*table_in) {
        fprintf(stderr,"Table is not valid.");
        return SSS_SBUS_DHASH_NULL;
    }
    local_table =  *table_in;

    if(!dbus_message_iter_open_container(msg_iter,
                                        DBUS_TYPE_ARRAY,
                                        "{ss}",
                                        &sub_iter)) {
           fprintf(stderr, "Out Of Memory!\n");
           return SSS_SBUS_ITER_MESSAGE_ERR;
       }
    printf("Iterate using iterator\n");
       iter = new_hash_iter_context(local_table);
       while ((entry = iter->next(iter)) != NULL) {

           if(entry->key.type != HASH_KEY_STRING && entry->value.type != HASH_VALUE_PTR) {
               fprintf(stderr,"fatal: Unexpected hashtable");
               return SSS_SBUS_DHASH_INVALID;
           }

           str_key   = strdup((char *) entry->key.str);
           str_value = strdup((char *) entry->value.ptr);

           if(!dbus_message_iter_open_container(&sub_iter,
                                                DBUS_TYPE_DICT_ENTRY,
                                                NULL,
                                                &dict_iter)) {
               fprintf(stderr, "Out Of Memory!\n");
               return SSS_SBUS_ITER_MESSAGE_ERR;
           }

                 if (!dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &str_key)) {
                     fprintf(stderr, "Out Of Memory!\n");
                     return SSS_SBUS_ITER_MESSAGE_ERR;
                 }
                 if (!dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &str_value)) {
                     fprintf(stderr, "Out Of Memory!\n");
                     return SSS_SBUS_ITER_MESSAGE_ERR;
                 }

                 free(str_key);
                 free(str_value);
           if (!dbus_message_iter_close_container(&sub_iter,&dict_iter)) {
               fprintf(stderr, "Out Of Memory!\n");
               return SSS_SBUS_ITER_MESSAGE_ERR;
           }



       }
       free(iter);
       if (!dbus_message_iter_close_container(msg_iter,&sub_iter)) {
              fprintf(stderr, "Out Of Memory!\n");
              return SSS_SBUS_ITER_MESSAGE_ERR;
       }

    return SSS_SBUS_CONV_SUCCESS;

}

int dbus_msg_iter_to_dhash(DBusMessageIter *iter, hash_table_t **table_out)
{
    DBusMessageIter msg_iter;
    DBusMessageIter sub_iter;
    DBusMessageIter dict_iter;
    hash_table_t *local_table = NULL;
    hash_key_t   key;
    hash_value_t value;
    int err_h;
    char * tmp;

    msg_iter = *iter;

    err_h =  hash_create((unsigned long)INIT_TABLE_SIZE,
                                        &local_table,
                                        callback_delete,
                                        NULL);
        if (err_h != HASH_SUCCESS) {
                fprintf(stderr, "couldn't create hash table (%s)\n", hash_error_string(err_h));
                return err_h;
        }

        if(DBUS_TYPE_ARRAY != dbus_message_iter_get_arg_type(&msg_iter)) {
            fprintf(stderr,"dictionary is invalid");
            return SSS_SBUS_ITER_INVALID_ERR;

        }
        else {
            fprintf(stdout,"Signature of dict : %s \n",dbus_message_iter_get_signature(&msg_iter));
                dbus_message_iter_recurse(&msg_iter, &sub_iter);
            }

            while(1){

                if(DBUS_TYPE_DICT_ENTRY != dbus_message_iter_get_arg_type(&sub_iter)) {
                    fprintf(stderr,"dict content failed");
                }
                else {
                    dbus_message_iter_recurse(&sub_iter, &dict_iter);
                }

                    if(DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&dict_iter)) {
                        printf("string array content failed");
                        return SSS_SBUS_ITER_MESSAGE_ERR;
                    }
                    else {
                        key.type = HASH_KEY_STRING;
                        value.type = HASH_VALUE_PTR;
                        dbus_message_iter_get_basic(&dict_iter, &tmp);
                        key.str = tmp;
                        fprintf(stderr," %s ",key.str);
                        dbus_message_iter_next (&dict_iter);
                        if(DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&dict_iter)) {
                            printf("string array content failed");
                            return SSS_SBUS_ITER_MESSAGE_ERR;
                        }
                        dbus_message_iter_get_basic(&dict_iter, &tmp);
                        value.ptr = tmp;
                        fprintf(stderr,": %s \n",(char *)value.ptr);

                        if ((err_h = hash_enter(local_table, &key, &value)) != HASH_SUCCESS) {
                            fprintf(stderr, "couldn't add to table \"%s\" (%s)\n", key.str, hash_error_string(err_h));
                            return err_h;
                        }
                        if(!dbus_message_iter_next (&sub_iter)) {
                                 fprintf(stderr,"struct ended.");
                                 break;
                             }
                    }

            }

            *table_out = local_table;
            return SSS_SBUS_CONV_SUCCESS;
}
