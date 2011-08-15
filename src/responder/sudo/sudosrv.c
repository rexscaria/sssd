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
#include <fnmatch.h>

#include <popt.h>
#include "dhash.h"
#include "util/util.h"
#include "db/sysdb.h"
#include "db/sysdb_private.h"
#include "sbus/sbus_client.h"
#include "sbus/sssd_dbus_messages_helpers.h"
#include "responder/common/responder.h"
#include "responder/common/negcache.h"
#include "responder/common/responder_packet.h"

#include "responder/sudo/sudosrv.h"
#include "sss_client/sudo_plugin/sss_sudo_cli.h"
#include "sbus/sbus_client.h"
#include "responder/common/responder_packet.h"
#include "providers/data_provider.h"
#include "monitor/monitor_interfaces.h"
#include "list_sss/list_sss.h"




static int sudo_client_destructor(void *ctx)
{
    struct sudo_client *sudocli = talloc_get_type(ctx, struct sudo_client);
    if (sudocli) {
        talloc_zfree(sudocli);
        DEBUG(4, ("Removed Sudo client\n"));
    }
    return 0;
}

int prepare_filter(char * filter,uid_t user_id,char * host, struct ldb_result *res){

    int i,ret=EOK;
    filter = talloc_asprintf_append(filter,"("SYSDB_SUDO_USER_ATTR"=#%d)",user_id);
    if (!filter) {
        DEBUG(0, ("Failed to build filter - %s\n",filter));
        ret = ENOMEM;
        goto done;
    }
    filter = talloc_asprintf_append(filter,"("SYSDB_SUDO_USER_ATTR"=+*)");
    if (!filter) {
        DEBUG(0, ("Failed to build filter - %s\n",filter));
        ret = ENOMEM;
        goto done;
    }


    for(i=0;i< res->count;i++){
        filter = talloc_asprintf_append(filter,"("SYSDB_SUDO_USER_ATTR"=%s)",ldb_msg_find_attr_as_string(res->msgs[i], SYSDB_NAME, NULL));
        if (!filter) {
            DEBUG(0, ("Failed to build filter - %s\n",filter));
            ret = ENOMEM;
            goto done;
        }
    }
    filter = talloc_asprintf_append(filter,")("SYSDB_SUDO_HOST_ATTR"=+*)");
    if (!filter) {
        DEBUG(0, ("Failed to build filter - %s\n",filter));
        ret = ENOMEM;
        goto done;
    }
    filter = talloc_asprintf_append(filter,"("SYSDB_SUDO_HOST_ATTR"=ALL)");
    if (!filter) {
        DEBUG(0, ("Failed to build filter - %s\n",filter));
        ret = ENOMEM;
        goto done;
    }
    filter = talloc_asprintf_append(filter,"("SYSDB_SUDO_HOST_ATTR"=%s)",host);
    if (!filter) {
        DEBUG(0, ("Failed to build filter - %s\n",filter));
        ret = ENOMEM;
        goto done;
    }
    done:
    if(ret!=ENOMEM) return EOK;
    else return ret;

}


int compare_sudo_order(const struct ldb_message **msg1, const struct ldb_message **msg2)
{
    double order_msg1 = ldb_msg_find_attr_as_double(*msg1, SYSDB_SUDO_ORDER_ATTR, 0.0);
    double order_msg2 = ldb_msg_find_attr_as_double(*msg2, SYSDB_SUDO_ORDER_ATTR, 0.0);
    if(order_msg1>order_msg2) return 1;
    else if (order_msg1==order_msg1) return 0;
    else return -1;
}


int search_sudo_rules(struct sudo_client *sudocli,
                      struct sysdb_ctx *sysdb,
                      struct sss_domain_info * domain,
                      char * user_name,
                      uid_t user_id,
                      struct sss_sudo_msg_contents *sudo_msg) {
    TALLOC_CTX *tmpctx;
    const char *attrs[] = { SYSDB_SUDO_CONTAINER_ATTR,
                            SYSDB_SUDO_USER_ATTR,
                            SYSDB_SUDO_HOST_ATTR,
                            SYSDB_SUDO_OPTION_ATTR,
                            SYSDB_SUDO_COMMAND_ATTR,
                            SYSDB_SUDO_RUNAS_USER_ATTR,
                            SYSDB_SUDO_RUNAS_GROUP_ATTR,
                            SYSDB_SUDO_NOT_BEFORE_ATTR,
                            SYSDB_SUDO_NOT_AFTER_ATTR,
                            SYSDB_SUDO_ORDER_ATTR,
                            NULL };
    char *filter = NULL, *tmpcmd,*space;
    struct ldb_message **sudo_rules_msgs;
    struct ldb_message_element *el;
    struct ldb_result *res;
    int ret;
    size_t count;
    int i,j,flag=0;
    double order;
    TALLOC_CTX *listctx;
    list_sss *list, *current, *tmp;
    struct sudo_cmd_ctx * sudo_cmnd;
    char * host = "arun.scaria.com";


    fprintf(stdout,"in Sudo rule\n");
    tmpctx = talloc_new(sudocli);
    if (!tmpctx) {
        return ENOMEM;
    }

    ret  = sysdb_get_groups_by_user(tmpctx,
                                    sysdb,
                                    domain,
                                    user_name,
                                    &res);
    if (ret) {
        if (ret == ENOENT) {
            ret = EOK;
        }
        goto done;
    }
    filter = talloc_asprintf(tmpctx,"|(|("SYSDB_SUDO_USER_ATTR"=%s)",user_name);
    if (!filter) {
        DEBUG(0, ("Failed to build filter - %s\n",filter));
        ret = ENOMEM;
        goto done;
    }
    ret = prepare_filter(filter,user_id,host, res);
    if (ret==ENOMEM) {
        DEBUG(0, ("Failed to build filter - %s\n",filter));
        goto done;
    }


    DEBUG(0,(stdout,"Filter - %s\n",filter));
    ret = sysdb_search_sudo_rules(tmpctx,
                                  sysdb,
                                  domain,
                                  filter,
                                  attrs,
                                  &count,
                                  &sudo_rules_msgs);

    if (ret) {
        if (ret == ENOENT) {
            ret = EOK;
        }
        goto done;
    }

    DEBUG(0, ("Found %d sudo rule entries!\n\n", count));

    if (count == 0) {
        ret = EOK;
        goto done;
    }

    qsort(sudo_rules_msgs,count,sizeof(struct ldb_message *), (__compar_fn_t)compare_sudo_order);

    listctx = talloc_new(NULL);
    if (!listctx) {
        return ENOMEM;
    }
    initList(&list);

    for(i=0; i< count ; i++) {
        appendNode(listctx, &list, sudo_rules_msgs[i]);
    }
    current = list;
    sudo_cmnd = talloc(listctx,struct sudo_cmd_ctx);

    while(current!=NULL) {



        DEBUG(0, ("--sudoOrder: %f\n",
                ldb_msg_find_attr_as_double((struct ldb_message *)current->data,
                                            SYSDB_SUDO_ORDER_ATTR,
                                            0.0)));
        DEBUG(0, ("--dn: %s----\n",
                ldb_dn_get_linearized(((struct ldb_message *)current->data)->dn)));

        el = ldb_msg_find_element((struct ldb_message *)current->data,
                                  SYSDB_SUDO_COMMAND_ATTR);
        if (!el) {
            DEBUG(0, ("Failed to get sudo commands for sudorule [%s]\n",
                    ldb_dn_get_linearized(((struct ldb_message *)current->data)->dn)));
            tmp = current->next;
            delNode(&list,current);
            current = tmp;
            continue;
        }
        flag = 0;
        /* see if this is a user */
        for (j = 0; j < el->num_values; j++) {
            DEBUG(0, ("sudoCommand: %s\n" ,(const char *) (el->values[j].data)));
            /* Do command elimination here */
            tmpcmd = talloc_asprintf(listctx,
                                     "%s",
                                     (const char *) (el->values[j].data));
            space = strchr(tmpcmd,' ');
            if(space != NULL) {
                *space = '\0';
                sudo_cmnd->arg= (space +1);
            }
            else
                sudo_cmnd->arg= NULL;

            if(tmpcmd[0]=='!') {
                sudo_cmnd->fqcomnd=tmpcmd+1;
            }
            else {
                sudo_cmnd->fqcomnd=tmpcmd;
            }

            if(fnmatch(sudo_cmnd->fqcomnd,sudo_msg->fq_command,FNM_PATHNAME) == 0){
                current=current->next;
                flag=1;
                break;
            }
        }

        if(flag==1) {
            continue;
        }

        tmp = current->next;
        delNode(&list,current);
        current = tmp;

    }


    talloc_free(listctx);

    done:
    talloc_zfree(tmpctx);
    return ret;
}


static int sudo_query_validation(DBusMessage *message, struct sbus_connection *conn)
{

    dbus_uint32_t header = SSS_SUDO_RESPONDER_HEADER,command_size;
    struct sudo_client *sudocli;
    DBusMessage *reply;
    DBusError dbus_error;
    DBusMessageIter msg_iter;
    DBusMessageIter subItem;
    char **ui;
    char **command_array;
    int ret = -1;
    dbus_bool_t dbret;
    void *data;
    int count = 0, i = 0;
    hash_table_t *settings_table;
    hash_table_t *env_table;
    char * result;
    struct sss_sudo_msg_contents * msg;
    struct sysdb_ctx **sysdblist;
    TALLOC_CTX * tmpctx;
    struct ldb_message *ldb_msg;
    size_t no_ldbs = 0;
    const char *attrs[] = { SYSDB_NAME, SYSDB_UIDNUM, NULL};
    const char * user_name;
    uid_t user_id;

    result = strdup("PASS");

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
        dbus_message_iter_next (&subItem);
    }
    if(DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&subItem)) {
        fprintf(stderr,"FQ Command failed");
        return SSS_SUDO_RESPONDER_MESSAGE_ERR;
    }
    else {
        dbus_message_iter_get_basic(&subItem, &msg->fq_command);
    }

    fprintf(stdout,"-----------Message---------\n"
            "uid : %d\ncwd : %s\ntty : %s\nFQ Command: %s\n",msg->userid,msg->cwd,msg->tty,msg->fq_command);

    dbus_message_iter_next (&msg_iter);

    if(DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&msg_iter)) {
        fprintf(stderr,"array size failed");
        return SSS_SUDO_RESPONDER_MESSAGE_ERR;
    }
    else {
        dbus_message_iter_get_basic(&msg_iter, &msg->command_count);
        fprintf(stdout,"Command array size: %d\n",msg->command_count);
    }
    dbus_message_iter_next (&msg_iter);

    command_array = (char**)malloc(msg->command_count*sizeof(char *));
    fprintf(stdout,"command : ");

    if( DBUS_TYPE_ARRAY != dbus_message_iter_get_arg_type(&msg_iter)) {
        fprintf(stderr, "Command array failed!\n");
        return SSS_SUDO_RESPONDER_MESSAGE_ERR;
    }
    else{
        dbus_message_iter_recurse(&msg_iter,&subItem);
    }

    for(ui = command_array,count = msg->command_count; count--; ui++)
    {
        if(DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&subItem)) {
            printf("string array content failed");
            return SSS_SUDO_RESPONDER_MESSAGE_ERR;

        }
        else {
            dbus_message_iter_get_basic(&subItem, ui);
            fprintf(stdout,"%s ",*ui);
            if(!dbus_message_iter_next (&subItem)) {
                /*"Array ended. */
                break;
            }
        }
    }
    fprintf(stdout,"\n");

    msg->command = command_array;
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

    DEBUG(0, ("-----------Message END---------\n"));
    //////////////////

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }
    i=0;
    sysdblist = sudocli->sudoctx->rctx->db_list->dbs;
    no_ldbs = sudocli->sudoctx->rctx->db_list->num_dbs;
    i=0;
    while(i < no_ldbs) {

        ret = sysdb_search_user_by_uid(tmpctx,
                                       sysdblist[i],
                                       sysdblist[i]->domain,
                                       msg->userid,
                                       attrs,
                                       &ldb_msg);
        if (ret != EOK) {
            i++;
            DEBUG(0, ("No User matched\n"));
            if (ret == ENOENT) {

                continue;
            }
            DEBUG(0, ("sysdb_search_user_by_uid Returned something other that ENOENT\n"));
            continue;
        }
        break;

    }
    if(ldb_msg == NULL) {
        DEBUG(0, ("NoUserEntryFound Error. Exit with error message.\n"));
        goto free_ctx;
    }

    user_name = ldb_msg_find_attr_as_string(ldb_msg, SYSDB_NAME, NULL);
    user_id = ldb_msg_find_attr_as_string(ldb_msg, SYSDB_UIDNUM, NULL);
    ret =  search_sudo_rules(sudocli, sysdblist[i],sysdblist[i]->domain, "tom",user_id,msg);
    if(ret != EOK){
        DEBUG(0, ("Error in rule"));
    }

    free_ctx:
    talloc_zfree(tmpctx);
    /////////////////////


    talloc_set_destructor((TALLOC_CTX *)sudocli, sudo_client_destructor);

    DEBUG(4, ("Got string [%s]\n", msg->cwd));

    /* reply that all is ok */
    reply = dbus_message_new_method_return(message);
    if (!reply) {
        DEBUG(0, ("Dbus Out of memory!\n"));
        return SSS_SUDO_RESPONDER_REPLY_ERR;
    }

    command_size = msg->command_count;
    dbret = dbus_message_append_args(reply,
                                     DBUS_TYPE_UINT32, &header,
                                     DBUS_TYPE_STRING,&result,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(0, ("Failed to build sudo dbus reply\n"));
        dbus_message_unref(reply);
        sbus_disconnect(conn);
        return SSS_SUDO_RESPONDER_REPLY_ERR;
    }

    dbus_message_iter_init_append(reply, &msg_iter);

    if(!dbus_message_iter_open_container(&msg_iter,
                                         DBUS_TYPE_ARRAY,
                                         "s",
                                         &subItem)) {
        fprintf(stderr, "Out Of Memory!\n");
        return SSS_SUDO_RESPONDER_REPLY_ERR;
    }

    for(command_array = msg->command ; command_size-- ; command_array++) {

        if (!dbus_message_iter_append_basic(&subItem,
                                            DBUS_TYPE_STRING,
                                            command_array)) {
            fprintf(stderr, "Out Of Memory!\n");
            return SSS_SUDO_RESPONDER_REPLY_ERR;
        }
    }

    if (!dbus_message_iter_close_container(&msg_iter,&subItem)) {
        fprintf(stderr, "Out Of Memory!\n");
        return SSS_SUDO_RESPONDER_REPLY_ERR;
    }

    if(dbus_dhash_to_msg_iter(&env_table,&msg_iter) != SSS_SBUS_CONV_SUCCESS){
        fprintf(stderr,"fatal: env message framing failed.");
        return SSS_SUDO_RESPONDER_DHASH_ERR;
    }

    /* send reply back */
    sbus_conn_send_reply(conn, reply);
    dbus_message_unref(reply);

    sudocli->initialized = true;
    free(result);
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

    sudocli->timeout = tevent_add_timer(sudoctx->rctx->ev, sudocli, tv, init_timeout, sudocli);
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
static void sudo_dp_reconnect_init(struct sbus_connection *conn, int status, void *pvt)
{
    struct be_conn *be_conn = talloc_get_type(pvt, struct be_conn);
    int ret;

    /* Did we reconnect successfully? */
    if (status == SBUS_RECONNECT_SUCCESS) {
        DEBUG(1, ("Reconnected to the Data Provider.\n"));

        /* Identify ourselves to the data provider */
        ret = dp_common_send_id(be_conn->conn,
                                DATA_PROVIDER_VERSION,
                                "PAM");
        /* all fine */
        if (ret == EOK) return;
    }

    /* Handle failure */
    DEBUG(0, ("Could not reconnect to %s provider.\n",
            be_conn->domain->name));


}

int sudo_server_init(TALLOC_CTX *mem_ctx,
                     struct sudo_ctx *_ctx)
{

    int ret;
    struct sbus_connection *serv;


    DEBUG(1, ("Setting up the sudo server.\n"));



    ret = sbus_new_server(mem_ctx,
                          _ctx->rctx->ev,
                          SSS_SUDO_SERVICE_PIPE,
                          &sudo_monitor_interface,
                          &serv,
                          sudo_client_init,
                          _ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not set up sudo sbus server.\n"));
        return ret;
    }

    return EOK;

}

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version sudo_cli_protocol_version[] = {
                                                                      {0, NULL, NULL}
    };

    return sudo_cli_protocol_version;
}

struct sss_cmd_table *get_sudo_cmds(void)
{
    static struct sss_cmd_table sss_cmds[] = {
                                              {SSS_SUDO_AUTHENTICATE, NULL},
                                              {SSS_SUDO_INVALIDATE, NULL},
                                              {SSS_SUDO_VALIDATE, NULL},
                                              {SSS_SUDO_LIST, NULL},
                                              {SSS_CLI_NULL, NULL}
    };

    return sss_cmds;
}

int sudo_process_init(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct confdb_ctx *cdb)
{
    struct sss_cmd_table *sudo_cmds;
    struct be_conn *iter;
    struct sudo_ctx *ctx;
    int ret, max_retries;
    int id_timeout;


    ctx = talloc_zero(mem_ctx, struct sudo_ctx);
    if (!ctx) {
        DEBUG(0, ("fatal error initializing sudo_ctx\n"));
        return ENOMEM;
    }
    sudo_cmds = get_sudo_cmds();
    ret = sss_process_init(ctx,
                           ev,
                           cdb,
                           sudo_cmds,
                           SSS_SUDO_SOCKET_NAME,
                           SSS_SUDO_PRIV_SOCKET_NAME,
                           CONFDB_SUDO_CONF_ENTRY,
                           SSS_SUDO_SBUS_SERVICE_NAME,
                           SSS_SUDO_SBUS_SERVICE_VERSION,
                           &sudo_monitor_interface,
                           "SUDO", &sudo_dp_interface,
                           &ctx->rctx);
    if (ret != EOK) {
        goto done;
    }


    ctx->rctx->pvt_ctx = ctx;



    ret = confdb_get_int(ctx->rctx->cdb, ctx->rctx, CONFDB_SUDO_CONF_ENTRY,
                         CONFDB_SERVICE_RECON_RETRIES, 3, &max_retries);
    if (ret != EOK) {
        DEBUG(0, ("Failed to set up automatic reconnection\n"));
        goto done;
    }

    for (iter = ctx->rctx->be_conns; iter; iter = iter->next) {
        sbus_reconnect_init(iter->conn, max_retries,
                            sudo_dp_reconnect_init, iter);
    }

    /* Set up the negative cache */
    ret = confdb_get_int(cdb, ctx, CONFDB_SUDO_CONF_ENTRY,
                         CONFDB_SUDO_ENTRY_NEG_TIMEOUT, 15,
                         &ctx->neg_timeout);
    if (ret != EOK) goto done;

    /* Set up the PAM identity timeout */
    ret = confdb_get_int(cdb, ctx, CONFDB_SUDO_CONF_ENTRY,
                         CONFDB_SUDO_ID_TIMEOUT, 5,
                         &id_timeout);
    if (ret != EOK) goto done;

    ctx->id_timeout = (size_t)id_timeout;

    ret = sss_ncache_init(ctx, &ctx->ncache);
    if (ret != EOK) {
        DEBUG(0, ("fatal error initializing negative cache\n"));
        goto done;
    }

    ret = sss_ncache_prepopulate(ctx->ncache, cdb, ctx->rctx->names,
                                 ctx->rctx->domains);
    if (ret != EOK) {
        goto done;
    }

    ret = sudo_server_init(mem_ctx, ctx);
    DEBUG(0, ("sudo server returned %d.\n",ret));

    return EOK;
    done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
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

