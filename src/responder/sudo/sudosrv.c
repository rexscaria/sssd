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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>

#include <popt.h>
#include "dhash.h"
#include "util/util.h"
#include "sbus/sbus_client.h"
#include "sbus/sssd_dbus_messages_helpers.h"

#include "sudosrv.h"
#include "sss_client/sudo_plugin/sss_sudo_cli.h"



static int sudo_client_destructor(void *ctx)
{
    struct sudo_client *sudocli = talloc_get_type(ctx, struct sudo_client);
    if (sudocli) {
            talloc_zfree(sudocli); 
            DEBUG(4, ("Removed Sudo client\n"));       
    }
    return 0;
}

struct test {
  uid_t userid;
  char * cwd;
  char * tty;
};
struct sss_sudo_msg_contents * msg;


static int sudo_query_validation(DBusMessage *message, struct sbus_connection *conn)
{
  
    dbus_uint16_t version = 45674;
    struct sudo_client *sudocli;
    DBusMessage *reply;
    DBusError dbus_error;
    DBusMessageIter msg_iter;
    DBusMessageIter subItem;
    char *tmp;
    dbus_bool_t dbret;
    void *data;
    hash_table_t *settings_table;
    hash_table_t *env_table;

    data = sbus_conn_get_private_data(conn);
    sudocli = talloc_get_type(data, struct sudo_client);
    if (!sudocli) {
        DEBUG(0, ("Connection holds no valid init data\n"));
        return SSS_SUDO_RESPONDER_CONNECTION_ERR;
    }

    msg = talloc((TALLOC_CTX *)sudocli,struct sss_sudo_msg_contents);
    
    /* First thing, cancel the timeout */
    DEBUG(4, ("Cancel SUDO client timeout [%p]\n", sudocli->timeout));
    talloc_zfree(sudocli->timeout);

    dbus_error_init(&dbus_error);
    
    if (!dbus_message_iter_init(message, &msg_iter)) {
      fprintf(stderr, "Message received as empty!\n");
      return SSS_SUDO_RESPONDER_MESSAGE_ERR;
   }

        if(DBUS_TYPE_STRUCT != dbus_message_iter_get_arg_type(&msg_iter)) {
            fprintf(stderr, "Argument is not struct!\n");
            return SSS_SUDO_RESPONDER_MESSAGE_ERR;
        }
        else{
            dbus_message_iter_recurse(&msg_iter,&subItem);
        }

            if(DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&subItem)) {
                fprintf(stderr,"UID failed");
                return SSS_SUDO_RESPONDER_MESSAGE_ERR;
            }
            else {
                dbus_message_iter_get_basic(&subItem, &msg->userid);
                dbus_message_iter_next (&subItem);
            }

            if(DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&subItem)) {
                fprintf(stderr,"CWD failed");
                return SSS_SUDO_RESPONDER_MESSAGE_ERR;
            }
            else {
                dbus_message_iter_get_basic(&subItem, &msg->cwd);
                dbus_message_iter_next (&subItem);
            }
     
            if(DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&subItem)) {
                fprintf(stderr,"TTY failed");
                return SSS_SUDO_RESPONDER_MESSAGE_ERR;
            }
            else {
                dbus_message_iter_get_basic(&subItem, &msg->tty);
            }

            fprintf(stderr," The message is:  UID: %d\nCWD: %s\nTTY: %s\n",msg->userid,msg->cwd,msg->tty);

        dbus_message_iter_next (&msg_iter);

        if( DBUS_TYPE_ARRAY != dbus_message_iter_get_arg_type(&msg_iter)) {
            fprintf(stderr, "Command array failed!\n");
            return SSS_SUDO_RESPONDER_MESSAGE_ERR;
        }
        else{
            dbus_message_iter_recurse(&msg_iter,&subItem);
        }
   
        while(1)
        {
            if(DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&subItem)) {
                printf("string array content failed");
                return SSS_SUDO_RESPONDER_MESSAGE_ERR;

            }
            else {
                dbus_message_iter_get_basic(&subItem, &tmp);
                fprintf(stderr," ARRAY: %s \n",tmp);
                    if(!dbus_message_iter_next (&subItem)) {
                        /*"Array ended. */
                        break;
                    }
	
            }
          
        }
    
        dbus_message_iter_next(&msg_iter);
    
        if( dbus_msg_iter_to_dhash(&msg_iter, &settings_table)!= SSS_SBUS_CONV_SUCCESS){
            fprintf(stderr, "settings table corrupted!\n");
            return SSS_SUDO_RESPONDER_MESSAGE_ERR;
        }

        dbus_message_iter_next(&msg_iter);

        if( dbus_msg_iter_to_dhash(&msg_iter, &env_table)!= SSS_SBUS_CONV_SUCCESS){
            fprintf(stderr, "environment table corrupted!\n");
            return SSS_SUDO_RESPONDER_MESSAGE_ERR;

        }
    
    
    /*if (!dbret) {
        DEBUG(1, ("Failed to parse message, killing connection\n"));
        if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
        sbus_disconnect(conn);

    }*/


  
        talloc_set_destructor((TALLOC_CTX *)sudocli, sudo_client_destructor);

        DEBUG(4, ("Got string [%s]\n", msg->cwd));

            /* reply that all is ok */
        reply = dbus_message_new_method_return(message);
        if (!reply) {
            DEBUG(0, ("Dbus Out of memory!\n"));
            return ENOMEM;
        }

        dbret = dbus_message_append_args(reply,
                                         DBUS_TYPE_UINT16, &version,
                                         DBUS_TYPE_INVALID);
        if (!dbret) {
            DEBUG(0, ("Failed to build sudo dbus reply\n"));
            dbus_message_unref(reply);
            sbus_disconnect(conn);
            return EIO;
        }

            /* send reply back */
        sbus_conn_send_reply(conn, reply);
        dbus_message_unref(reply);

        sudocli->initialized = true;
        return EOK;
}

static void init_timeout(struct tevent_context *ev,
                         struct tevent_timer *te,
                         struct timeval t, void *ptr)
{
    struct sudo_client *sudocli;

    DEBUG(2, ("Client timed out  [%p]!\n", te));

    sudocli = talloc_get_type(ptr, struct sudo_client);

    sbus_disconnect(sudocli->conn);
    talloc_zfree(sudocli);
}

static int sudo_client_init(struct sbus_connection *conn, void *data)
{
    struct sudo_ctx *sudoctx;
    struct sudo_client *sudocli;
    struct timeval tv;
    
    sudoctx = talloc_get_type(data, struct sudo_ctx);

    /* hang off this memory to the connection so that when the connection
     * is freed we can potentially call a destructor */

    sudocli = talloc(conn, struct sudo_client);
    if (!sudocli) {
        DEBUG(0,("Out of memory?!\n"));
        talloc_zfree(conn);
        return ENOMEM;
    }
    sudocli->sudoctx = sudoctx;
    sudocli->conn = conn;
    sudocli->initialized = false;

    /* 5 seconds should be plenty */
    tv = tevent_timeval_current_ofs(5, 0);

    sudocli->timeout = tevent_add_timer(sudoctx->ev, sudocli, tv, init_timeout, sudocli);
    if (!sudocli->timeout) {
        DEBUG(0,("Out of memory?!\n"));
        talloc_zfree(conn);
        return ENOMEM;
    }
    DEBUG(4, ("Set-up Sudo client timeout [%p]\n", sudocli->timeout));

    /* Attach the client context to the connection context, so that it is
     * always available when we need to manage the connection. */
    sbus_conn_set_private_data(conn, sudocli);

    return EOK;
}


int sudo_server_init(TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct sudo_ctx *_ctx)
{
  
    int ret;
    struct sbus_connection *serv;
    
  
    DEBUG(1, ("Setting up the sudo server.\n"));
    
     
        
    ret = sbus_new_server(mem_ctx,ev, SSS_SUDO_SERVICE_PIPE,
                          &sudo_interface, &serv,
                          sudo_client_init, _ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not set up sudo sbus server.\n"));
        return ret;
    }

    return EOK;
  
}

int sudo_process_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct confdb_ctx *cdb)
{
  struct sudo_ctx *ctx;
  int ret;
  
  ctx = talloc_zero(mem_ctx, struct sudo_ctx);
  ctx->ev = ev;
  ctx->cdb = cdb;
  
  
  ret = sudo_server_init(mem_ctx, ev, ctx);
  DEBUG(0, ("sudo server returned %d.\n",ret));
  
    return EOK;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    struct main_context *main_ctx;
    int ret;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        POPT_TABLEEND
    };

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                  poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }

    poptFreeContext(pc);

   /* set up things like debug, signals, daemonization, etc... */
    debug_log_file = "sssd_sudo";

    ret = server_setup("sssd[sudo]", 0, CONFDB_SUDO_CONF_ENTRY, &main_ctx);
    if (ret != EOK) return 2;

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(2, ("Could not set up to exit when parent process does\n"));
    }

    ret = sudo_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}

