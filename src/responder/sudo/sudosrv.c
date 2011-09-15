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
#include <netdb.h>


#include <popt.h>
#include "dhash.h"
#include "util/util.h"
#include "util/dlinklist.h"
#include "db/sysdb.h"
#include "db/sysdb_private.h"
#include "sbus/sbus_client.h"
#include "sbus/sssd_dbus_messages_helpers.h"
#include "responder/common/responder.h"
#include "responder/common/negcache.h"
#include "responder/common/responder_packet.h"

#include "responder/sudo/sudosrv.h"
#include "match_sudo.h"
#include "sss_client/sudo_plugin/sss_sudo_cli.h"
#include "sbus/sbus_client.h"
#include "responder/common/responder_packet.h"
#include "providers/data_provider.h"
#include "monitor/monitor_interfaces.h"


static int sudo_client_destructor(void *ctx)
{
    struct sudo_client *sudocli = talloc_get_type(ctx, struct sudo_client);
    if (sudocli) {
        talloc_zfree(sudocli);
        DEBUG(4, ("Removed Sudo client\n"));
    }
    return 0;
}

char * get_host_name(TALLOC_CTX* mem_ctx){

    struct addrinfo hints, *info;
    int gai_result;

    char *hostname = talloc_size(mem_ctx,1024);
    hostname[1024]='\0';
    gethostname(hostname, 1023);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; /*either IPV4 or IPV6*/
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;

    if ((gai_result = getaddrinfo(hostname, "http", &hints, &info)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai_result));
        exit(1);
    }


    return talloc_strdup(mem_ctx, info->ai_canonname);

}

errno_t prepare_filter( TALLOC_CTX * mem_ctx,
                        const char * username,
                        uid_t user_id,
                        const char * runas_user,
                        uid_t runas_uid,
                        const char * runas_group,
                        gid_t runas_gid,
                        char * host,
                        struct ldb_result *groups_res,
                        struct ldb_result *groups_res_runas,
                        char ** filter_out)   {

    int i,ret=EOK;
    char *filter;
    const char * group_name;

    filter = talloc_asprintf(mem_ctx,"&(|("SYSDB_SUDO_USER_ATTR"=%s)",username);
    if (!filter) {
        DEBUG(0, ("Failed to build filter \n"));
        ret = ENOMEM;
        goto done;
    }

    FILTER_APPEND_CHECK(filter,filter,"("SYSDB_SUDO_USER_ATTR"=#%u)",user_id);

    FILTER_APPEND_CHECK(filter,filter,"("SYSDB_SUDO_USER_ATTR"=%s)","+*");

    for(i=0;i< groups_res->count;i++){
        group_name = ldb_msg_find_attr_as_string(groups_res->msgs[i], SYSDB_NAME, NULL);
        if( !group_name){
            DEBUG(0,("Failed to get group name from group search result"));
            /* Not fatal */
        }
        FILTER_APPEND_CHECK(filter,filter,"("SYSDB_SUDO_USER_ATTR"=%%%s)",group_name);
    }
    FILTER_APPEND_CHECK(filter,filter,")(|("SYSDB_SUDO_HOST_ATTR"=%s)","+*");

    FILTER_APPEND_CHECK(filter,filter,"("SYSDB_SUDO_HOST_ATTR"=%s)","ALL");

    FILTER_APPEND_CHECK(filter,filter,"("SYSDB_SUDO_HOST_ATTR"=%s))",host);

    FILTER_APPEND_CHECK(filter,filter,"(|(|("SYSDB_SUDO_RUNAS_USER_ATTR"=%s)",runas_user);

    FILTER_APPEND_CHECK(filter,filter,"("SYSDB_SUDO_RUNAS_USER_ATTR"=#%u)",runas_uid);

    for(i=0;i< groups_res_runas->count;i++){
        group_name = ldb_msg_find_attr_as_string(groups_res_runas->msgs[i], SYSDB_NAME, NULL);
        if( !group_name){
            DEBUG(0,("Failed to get group name from runas group search result"));
            /* Not fatal */
        }
        FILTER_APPEND_CHECK(filter,filter,"("SYSDB_SUDO_RUNAS_USER_ATTR"=%%%s)",group_name);
    }

    FILTER_APPEND_CHECK(filter,filter,"("SYSDB_SUDO_RUNAS_USER_ATTR"=%s)","+*");

    FILTER_APPEND_CHECK(filter,filter,"("SYSDB_SUDO_RUNAS_USER_ATTR"=%s))","ALL");

    FILTER_APPEND_CHECK(filter,filter,"(|("SYSDB_SUDO_RUNAS_GROUP_ATTR"=%s)",runas_group);

    FILTER_APPEND_CHECK(filter,filter,"("SYSDB_SUDO_RUNAS_GROUP_ATTR"=#%u)",runas_gid);

    FILTER_APPEND_CHECK(filter,filter,"("SYSDB_SUDO_RUNAS_GROUP_ATTR"=%s)))","ALL");

    done:
    *filter_out = filter;
    return ret;

}


int compare_sudo_order(const struct ldb_message **msg1, const struct ldb_message **msg2)
{
    int ret;
    double order_msg1 = ldb_msg_find_attr_as_double(*msg1, SYSDB_SUDO_ORDER_ATTR, 0.0);
    double order_msg2 = ldb_msg_find_attr_as_double(*msg2, SYSDB_SUDO_ORDER_ATTR, 0.0);
    /*
     * No need to consider errors since zero is assumed by default
     *
     **/
    ret = (order_msg1 < order_msg2)?  1: ((order_msg1 == order_msg1) ?  0 :  -1);
    return ret;
}

errno_t eliminate_sudorules_by_sudocmd(TALLOC_CTX * mem_ctx,
                                       struct sss_sudorule_list ** head,
                                       const char * fq_command) {


    struct sss_sudorule_list * list_head = *head , *current_node, *tmp_node;
    struct ldb_message_element *el;
    int flag =0;
    int i=0;
    char * tmpcmd, *space;
    struct sudo_cmd_ctx * sudo_cmnd;

    DEBUG(0,("\n\n\nIn rule elimination based on commands\n"));
    sudo_cmnd = talloc_zero(mem_ctx,struct sudo_cmd_ctx);
    if(!sudo_cmnd){
        DEBUG(0,("Failed to allocate command structure.\n"));
        return ENOMEM;
    }
    current_node = list_head;
    while(current_node != NULL) {

        DEBUG(0, ("\n--sudoOrder: %f\n",
                ldb_msg_find_attr_as_double(current_node->data,
                                            SYSDB_SUDO_ORDER_ATTR,
                                            0.0)));
        DEBUG(0, ("--dn: %s----\n",
                ldb_dn_get_linearized(current_node->data->dn)));

        el = ldb_msg_find_element(current_node->data,
                                  SYSDB_SUDO_COMMAND_ATTR);
        if (!el) {
            DEBUG(0, ("Failed to get sudo commands for sudorule [%s]\n",
                    ldb_dn_get_linearized(current_node->data->dn)));
            tmp_node = current_node->next;
            DLIST_REMOVE(list_head,current_node);
            current_node =  tmp_node;
            continue;
        }
        flag = 0;
        /* check each command with wild cards */
        for (i = 0; i < el->num_values; i++) {
            DEBUG(0, ("sudoCommand: %s\n" ,(const char *) (el->values[i].data)));
            /* Do command elimination here */
            tmpcmd = talloc_asprintf(mem_ctx,
                                     "%s",
                                     (const char *) (el->values[i].data));
            if (!tmpcmd) {
                DEBUG(0, ("Failed to build commands string - dn: %s\n",
                        ldb_dn_get_linearized(current_node->data->dn)));
                return ENOMEM;
            }

            if(strcmp(tmpcmd,"ALL") == 0){
                current_node=current_node->next;
                flag=1;
                break;
            }
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

            if(fnmatch(sudo_cmnd->fqcomnd,fq_command,FNM_PATHNAME) == 0){
                current_node=current_node->next;
                flag=1;
                break;
            }
        }

        if(flag==1) {
            continue;
        }
        tmp_node = current_node->next;
        DLIST_REMOVE(list_head,current_node);
        current_node =  tmp_node;
    }
    *head = list_head;
    DEBUG(0,("Rule elimination based on commands is over\n"));
    return EOK;
}


errno_t eliminate_sudorules_by_sudohosts(TALLOC_CTX * mem_ctx,
                                         struct sss_sudorule_list ** head,
                                         const char * host_name,
                                         const char * domain_name) {


    struct sss_sudorule_list * list_head = *head , *current_node, *tmp_node;
    struct ldb_message_element *el;
    int flag =0;
    int i=0;
    char * tmphost;
    DEBUG(0,("\n\n\nIn rule elimination based on hosts\n"));

    current_node = list_head;
    while(current_node != NULL) {

        DEBUG(0, ("\n--sudoOrder: %f\n",
                ldb_msg_find_attr_as_double((struct ldb_message *)current_node->data,
                                            SYSDB_SUDO_ORDER_ATTR,
                                            0.0)));
        DEBUG(0, ("--dn: %s----\n",
                ldb_dn_get_linearized(((struct ldb_message *)current_node->data)->dn)));

        el = ldb_msg_find_element((struct ldb_message *)current_node->data,
                                  SYSDB_SUDO_HOST_ATTR);

        if (!el) {
            DEBUG(0, ("Failed to get sudo hosts for sudorule [%s]\n",
                    ldb_dn_get_linearized(((struct ldb_message *)current_node->data)->dn)));
            current_node = current_node->next;
            continue;
        }
        flag = 0;

        for (i = 0; i < el->num_values; i++) {

            DEBUG(0, ("sudoHost: %s\n" ,(const char *) (el->values[i].data)));
            tmphost = ( char *) (el->values[i].data);
            if(strcmp(tmphost,"ALL")==0){
                current_node=current_node->next;
                flag=1;
                break;
            }
            else if(tmphost[0] == '+'){
                ++tmphost;
                if(innetgr(tmphost,host_name,NULL,domain_name) == 1){
                    current_node=current_node->next;
                    flag=1;
                    break;

                }
            }
            else {
                if(strcmp(tmphost,host_name)==0){
                    current_node=current_node->next;
                    flag=1;
                    break;
                }
            }

        }
        if(flag==1) {
            continue;
        }
        tmp_node = current_node->next;
        DLIST_REMOVE(list_head,current_node);
        current_node =  tmp_node;
    }
    *head = list_head;
    DEBUG(0,("Rule elimination based on hosts over\n"));
    return EOK;
}

errno_t eliminate_sudorules_by_sudouser_netgroups(TALLOC_CTX * mem_ctx,
                                                  struct sss_sudorule_list ** head,
                                                  const char * user_name,
                                                  const char * domain_name) {


    struct sss_sudorule_list * list_head = *head , *current_node, *tmp_node;
    struct ldb_message_element *el;
    int flag =0;
    int i=0, valid_user_count = 0;
    char * tmpuser;

    DEBUG(0,("\n\n\nIn rule elimination based on user net groups\n"));
    current_node = list_head;
    while(current_node != NULL) {
        DEBUG(0, ("\n--sudoOrder: %f\n",
                ldb_msg_find_attr_as_double((struct ldb_message *)current_node->data,
                                            SYSDB_SUDO_ORDER_ATTR,
                                            0.0)));
        DEBUG(0, ("--dn: %s----\n",
                ldb_dn_get_linearized(((struct ldb_message *)current_node->data)->dn)));
        el = ldb_msg_find_element((struct ldb_message *)current_node->data,
                                  SYSDB_SUDO_USER_ATTR);

        if (!el) {
            DEBUG(0, ("Failed to get sudo hosts for sudorule [%s]\n",
                    ldb_dn_get_linearized(((struct ldb_message *)current_node->data)->dn)));
            DLIST_REMOVE(list_head,current_node);
            continue;
        }
        flag = 0;
        /*
         * TODO: The elimination of sudo rules based on hosts an user net groups depends
         *  on the innetgr(). This makes the code less efficient since we are calling the
         *  sssd in loop. Find a good solution to resolve the membserNisnetgroup attribute.
         *
         *  CAUTION: Most of the contents of the netgroup is stored on LDAP. But they leave
         *  a generic memberNisNetgroup entry in the LDAP entry, so that if the local machine
         *  chooses, they can add an "override" locally. So there's no guarantee that
         *  memberNisNetgroup maps to something else on the LDAP server.
         *
         */

        for (i = 0; i < el->num_values; i++) {

            DEBUG(0, ("sudoUser: %s\n" ,(const char *) (el->values[i].data)));
            tmpuser = ( char *) (el->values[i].data);
            if(tmpuser[0] == '+'){
                tmpuser++;
                if(innetgr(tmpuser,NULL,user_name,domain_name) == 1){
                    flag = 1;
                }
            }
            else{
                valid_user_count++;
                break;
            }
        }

        if(flag == 1 || valid_user_count > 0){
            current_node = current_node -> next;
            continue;
        }
        tmp_node = current_node->next;
        DLIST_REMOVE(list_head,current_node);
        current_node =  tmp_node;
    }
    *head = list_head;
    DEBUG(0,("Rule elimination based on user net groups is over\n"));
    return EOK;
}


errno_t eliminate_sudorules_by_sudo_runasuser_netgroups(TALLOC_CTX * mem_ctx,
                                                        struct sss_sudorule_list ** head,
                                                        const char * user_name,
                                                        const char * domain_name) {


    struct sss_sudorule_list * list_head = *head , *current_node, *tmp_node;
    struct ldb_message_element *el;
    int flag =0;
    int i=0, valid_user_count = 0;
    char * tmpuser;

    DEBUG(0,("\n\n\nIn rule elimination based on runas user net groups\n"));
    current_node = list_head;
    while(current_node != NULL) {
        DEBUG(0, ("\n--sudoOrder: %f\n",
                ldb_msg_find_attr_as_double((struct ldb_message *)current_node->data,
                                            SYSDB_SUDO_ORDER_ATTR,
                                            0.0)));
        DEBUG(0, ("--dn: %s----\n",
                ldb_dn_get_linearized(((struct ldb_message *)current_node->data)->dn)));
        el = ldb_msg_find_element((struct ldb_message *)current_node->data,
                                  SYSDB_SUDO_USER_ATTR);

        if (!el) {
            DEBUG(0, ("Failed to get sudo hosts for sudorule [%s]\n",
                    ldb_dn_get_linearized(((struct ldb_message *)current_node->data)->dn)));
            DLIST_REMOVE(list_head,current_node);
            continue;
        }
        flag = 0;
        /*
         * TODO: The elimination of sudo rules based on hosts an user net groups depends
         *  on the innetgr(). This makes the code less efficient since we are calling the
         *  sssd in loop. Find a good solution to resolve the membserNisnetgroup attribute.
         *
         *  CAUTION: Most of the contents of the netgroup is stored on LDAP. But they leave
         *  a generic memberNisNetgroup entry in the LDAP entry, so that if the local machine
         *  chooses, they can add an "override" locally. So there's no guarantee that
         *  memberNisNetgroup maps to something else on the LDAP server.
         *
         */

        for (i = 0; i < el->num_values; i++) {

            DEBUG(0, ("sudoUser: %s\n" ,(const char *) (el->values[i].data)));
            tmpuser = ( char *) (el->values[i].data);
            if(tmpuser[0] == '+'){
                tmpuser++;
                if(innetgr(tmpuser,NULL,user_name,domain_name) == 1){
                    flag = 1;
                }
            }
            else{
                valid_user_count++;
                break;
            }
        }

        if(flag == 1 || valid_user_count > 0){
            current_node = current_node -> next;
            continue;
        }
        tmp_node = current_node->next;
        DLIST_REMOVE(list_head,current_node);
        current_node =  tmp_node;
    }
    *head = list_head;
    DEBUG(0,("Rule elimination based on runas user net groups is over\n"));
    return EOK;
}

errno_t search_sudo_rules(struct sudo_client *sudocli,
                          struct sysdb_ctx *sysdb,
                          struct sss_domain_info * domain,
                          const char * user_name,
                          uid_t user_id,
                          const char * runas_user,
                          uid_t runas_uid,
                          const char * runas_group,
                          gid_t runas_gid,
                          struct sss_sudo_msg_contents *sudo_msg,
                          struct sss_valid_sudorules **valid_sudorules_out) {
    TALLOC_CTX *tmp_mem_ctx;
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
    const char *attrs_default[] = { SYSDB_SUDO_CONTAINER_ATTR,
                                    SYSDB_SUDO_OPTION_ATTR,
                                    NULL };
    char *filter = NULL, *host = NULL;
    char * filter_default = NULL;
    struct ldb_message **sudo_rules_msgs;
    struct ldb_message **default_rule;
    struct ldb_result *res, *res_runas;
    int ret;
    size_t count = 0, count_default = 0;
    int i = 0;
    TALLOC_CTX *listctx;
    struct sss_sudorule_list *list_head =NULL, *tmp_node;
    struct sss_valid_sudorules * valid_rules;

    DEBUG(0,("in Sudo rule elimination\n"));
    tmp_mem_ctx = talloc_new(NULL);
    if (!tmp_mem_ctx) {
        return ENOMEM;
    }

    valid_rules = talloc_zero(tmp_mem_ctx,struct sss_valid_sudorules);
    ret  = sysdb_get_groups_by_user(tmp_mem_ctx,
                                    sysdb,
                                    user_name,
                                    &res);
    if (ret) {
        DEBUG(0, ("Failed to get groups of the requested sudoUser \n"));
        if(ret != ENOENT)
            goto done;
    }

    ret  = sysdb_get_groups_by_user(tmp_mem_ctx,
                                    sysdb,
                                    runas_user,
                                    &res_runas);
    if (ret) {
        DEBUG(0, ("Failed to get groups of the runas sudoUser \n"));
        if(ret != ENOENT)
            goto done;
    }

    host = get_host_name(tmp_mem_ctx);
    if (!host) {
        DEBUG(0, ("Failed to build hostname \n"));
        return ENOMEM;
    }
    DEBUG(0, ("Host - %s\n",host));

    filter_default = talloc_asprintf(tmp_mem_ctx,"%s=%s",SYSDB_SUDO_CONTAINER_ATTR,SYSDB_SUDO_DEFAULT_RULE);
    if (!filter_default) {
        DEBUG(0, ("Failed to build filter for default rule \n"));
        ret = ENOMEM;
        goto done;
    }

    ret = prepare_filter(tmp_mem_ctx,user_name,user_id, runas_user, runas_uid, runas_group, runas_gid, host, res, res_runas, &filter);
    if (ret!=EOK) {
        DEBUG(0, ("Failed to build filter(Non default) - %s\n",filter));
        goto done;
    }
    DEBUG(0,("Filter(Non Default) - %s\n",filter));
    DEBUG(0,("Filter(Default) - %s\n",filter_default));

    ret = sysdb_search_sudo_rules(tmp_mem_ctx,
                                  sysdb,
                                  filter,
                                  attrs,
                                  &count,
                                  &sudo_rules_msgs);
    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(0, ("Failed to get the rules - Deny the command execution\n"));
        }
        goto done;
    }

    if (count == 0) {
        ret = EOK;
        goto done;
    }

    ret = sysdb_search_sudo_rules(tmp_mem_ctx,
                                  sysdb,
                                  filter_default,
                                  attrs_default,
                                  &count_default,
                                  &default_rule);
    if (ret) {
        DEBUG(0, ("Failed to get the default rule - Not fatal\n", count));
        valid_rules->default_rule = NULL;
    }
    else {
        valid_rules->default_rule = *default_rule;
    }
    if(count_default > 1){
        DEBUG(0, ("More than one default rule found - Unexpected behavior( fatal )\n", count));
        ret = EIO;
        goto done;
    }
    DEBUG(0, ("Found %d sudo rules and %d default rules entries!\n\n", count, count_default));

    qsort(sudo_rules_msgs,count,sizeof(struct ldb_message *), (__compar_fn_t)compare_sudo_order);

    listctx = talloc_new(tmp_mem_ctx);
    if (!listctx) {
        return ENOMEM;
    }

    for(i=0; i < count ; i++) {
        tmp_node =  talloc_zero(listctx,struct sss_sudorule_list);
        tmp_node->data = sudo_rules_msgs[i];
        tmp_node->next = NULL;
        tmp_node->prev = NULL;
        DLIST_ADD_END( list_head, tmp_node, struct sss_sudorule_list *);

    }


    ret = eliminate_sudorules_by_sudocmd(tmp_mem_ctx,
                                         &list_head,
                                         sudo_msg->fq_command);
    if (ret != EOK) {
        DEBUG(0, ("Failed to eliminate sudo rules based on sudo commands\n"));
        ret = EIO;
        goto done;
    }
    if(list_head == NULL){
        /* No more rules left. Return err */
        DEBUG(0, ("All rules are eliminated based on sudo commands\n"));
        ret = EOK;
        valid_rules->non_defaults = NULL;
        *valid_sudorules_out = valid_rules;
        goto done;
    }

    ret = unsetenv("_SSS_LOOPS");
    if (ret != EOK) {
        DEBUG(0, ("Failed to unset _SSS_LOOPS, "
                "sudo rule elimination might not work as expected.\n"));
    }

    ret = eliminate_sudorules_by_sudohosts(tmp_mem_ctx,
                                           &list_head,
                                           host,
                                           sysdb->domain->name);
    if (ret != EOK) {
        DEBUG(0, ("Failed to eliminate sudo rules based on sudo Hosts\n"));
        ret = EIO;
        goto done;
    }
    if(list_head == NULL){
        /* No more rules left. Return err */
        DEBUG(0, ("All rules are eliminated based on sudo Hosts\n"));
        ret = EOK;
        valid_rules->non_defaults = NULL;
        *valid_sudorules_out = valid_rules;
        goto done;
    }

    ret = eliminate_sudorules_by_sudouser_netgroups(tmp_mem_ctx,
                                                    &list_head,
                                                    user_name,
                                                    sysdb->domain->name);
    if (ret != EOK) {
        DEBUG(0, ("Failed to eliminate sudo rules based on sudo user net groups\n"));
        ret = EIO;
        goto done;
    }
    if(list_head == NULL){
        /* No more rules left. Return err */
        DEBUG(0, ("All rules are eliminated based on sudo users\n"));
        ret = EOK;
        valid_rules->non_defaults = NULL;
        *valid_sudorules_out = valid_rules;
        goto done;
    }

    setenv("_SSS_LOOPS", "NO", 0);
    talloc_steal(sudocli,listctx);

    valid_rules->non_defaults = list_head;
    *valid_sudorules_out = valid_rules;

    done:

    talloc_zfree(tmp_mem_ctx);
    return ret;
}

errno_t find_sudorules_for_user_in_db_list(TALLOC_CTX * ctx,
                                           struct sudo_client *sudocli,
                                           struct sss_sudo_msg_contents * sudo_msg,
                                           struct sss_valid_sudorules ** valid_sudorules) {
    struct sysdb_ctx **sysdblist;
    struct ldb_message *ldb_msg = NULL , * ldb_msg_runas_ctx = NULL;
    size_t no_ldbs = 0;
    const char *attrs[] = { SYSDB_NAME, SYSDB_UIDNUM, NULL};
    const char *attrs_group[] = { SYSDB_NAME, SYSDB_GIDNUM, NULL};
    uid_t user_id;
    int i = 0,ret;
    const char * user_name;
    struct sss_valid_sudorules * res_sudorules_valid;
    const char * runas_user , * runas_group;
    uid_t runas_uid = 0;
    gid_t runas_gid = 0;


    sysdblist = sudocli->sudoctx->rctx->db_list->dbs;
    no_ldbs = sudocli->sudoctx->rctx->db_list->num_dbs;


    while(i < no_ldbs) {

        ret = sysdb_search_user_by_uid(ctx,
                                       sysdblist[i],
                                       sudo_msg->userid,
                                       attrs,
                                       &ldb_msg);
        if (ret != EOK) {
            i++;
            DEBUG(0, ("No User matched\n"));
            if (ret == ENOENT) {
                continue;
            }
            DEBUG(0, ("sysdb_search_user_by_uid Returned something other that ENOENT\n"));
            return ENOMEM;
        }
        break;

    }
    if(ret !=EOK || ldb_msg == NULL) {
        DEBUG(0, ("NoUserEntryFound Error. Exit with error message.\n"));
        return ENOENT;
    }

    user_name = ldb_msg_find_attr_as_string(ldb_msg, SYSDB_NAME, NULL);
    user_id = sudo_msg->userid;
    if ( user_name == NULL){
        DEBUG(0, ("Error in getting user_name. fatal error"));
        return ENOENT;
    }
    if(sudo_msg->runas_user != NULL){
        if(sudo_msg->runas_user[0] == '#'){
            runas_uid = atoi(sudo_msg->runas_user+1);
            ret = sysdb_search_user_by_uid(ctx,
                                           sysdblist[i],
                                           runas_uid,
                                           attrs,
                                           &ldb_msg_runas_ctx);
            if(ret != EOK || ldb_msg_runas_ctx == NULL){
                DEBUG(0,("The runas user with uid(%d) is not found - Fatal\n",runas_uid));
                return ENOENT;
            }
            runas_user = ldb_msg_find_attr_as_string(ldb_msg_runas_ctx,SYSDB_NAME, NULL);
        }
        else {
            runas_user = sudo_msg->runas_user;
            ret = sysdb_search_user_by_name(ctx,
                                            sysdblist[i],
                                            runas_user,
                                            attrs,
                                            &ldb_msg_runas_ctx);
            if(ret != EOK || ldb_msg_runas_ctx == NULL){
                DEBUG(0,("The runas user with uid(%d) is not found - Fatal\n",runas_uid));
                return ENOENT;
            }
            runas_uid = ldb_msg_find_attr_as_uint64(ldb_msg_runas_ctx, SYSDB_UIDNUM, -1 );
        }

        if(runas_user == NULL || runas_uid == -1 ){
            DEBUG(0, ("User requested to run as some user, but granted to be super user - Fatal \n"));
            return ENOENT;
        }
    }
    else {
        runas_user = SYSDB_SUDO_DEFAULT_RUNAS_USER_NAME;
        runas_uid = SYSDB_SUDO_DEFAULT_RUNAS_USER_ID;
    }

    if(sudo_msg->runas_group != NULL){
        if(sudo_msg->runas_group[0] == '#'){
            runas_gid = atoi(sudo_msg->runas_group+1);
            ret = sysdb_search_group_by_gid(ctx,
                                            sysdblist[i],
                                            runas_gid,
                                            attrs_group,
                                            &ldb_msg_runas_ctx);
            if(ret != EOK || ldb_msg_runas_ctx == NULL){
                DEBUG(0,("The runas group with gid(%d) is not found - Fatal\n",runas_gid));
                return ENOENT;
            }
            runas_group = ldb_msg_find_attr_as_string(ldb_msg_runas_ctx, SYSDB_NAME, NULL);
        }
        else {
            runas_group = sudo_msg->runas_group;
            ret = sysdb_search_user_by_name(ctx,
                                            sysdblist[i],
                                            runas_group,
                                            attrs_group,
                                            &ldb_msg_runas_ctx);
            if(ret != EOK || ldb_msg_runas_ctx == NULL){
                DEBUG(0,("The runas group with gid(%d) is not found - Fatal\n",runas_gid));
                return ENOENT;
            }
            runas_gid = ldb_msg_find_attr_as_uint64(ldb_msg_runas_ctx, SYSDB_UIDNUM, -1);
        }

        if( runas_group == NULL || runas_gid == -1) {
            DEBUG(0, ("User requested to run as some group, but granted to be super user group - Fatal \n"));
            return ENOENT;
        }
    }
    else {
        runas_group = SYSDB_SUDO_DEFAULT_RUNAS_GROUP_NAME;
        runas_gid = SYSDB_SUDO_DEFAULT_RUNAS_GROUP_ID;
    }

    ret =  search_sudo_rules(sudocli,
                             sysdblist[i],
                             sysdblist[i]->domain,
                             "tom"/*user_name*/,
                             user_id,
                             runas_user,
                             runas_uid,
                             runas_group,
                             runas_gid,
                             sudo_msg,
                             &res_sudorules_valid);
    if(ret != EOK){
        DEBUG(0, ("Error in rule search"));
        return ret;
    }
    if(res_sudorules_valid == NULL || res_sudorules_valid->non_defaults == NULL){
        /* All the rules are eliminated and nothing left for evaluation */
        DEBUG(0, ("No rule left for evaluation\n"));
        return ENOENT;
    }
    *valid_sudorules = res_sudorules_valid;
    /* Do the evaluation now */
    return ret;

}

errno_t load_settings( hash_table_t *settings_table,struct sss_sudo_msg_contents *contents){


    hash_table_t *  local_table = NULL;
    hash_entry_t *entry;
    struct hash_iter_context_t *iter;

    if( !settings_table ) {
        DEBUG(0,("Table is not valid."));
        return SSS_SBUS_DHASH_NULL;
    }
    local_table =  settings_table;

    iter = new_hash_iter_context(local_table);
    while ((entry = iter->next(iter)) != NULL) {

        if(entry->key.type != HASH_KEY_STRING && entry->value.type != HASH_VALUE_PTR) {
            DEBUG(0,("fatal: Unexpected hashtable"));
            return SSS_SBUS_DHASH_INVALID;
        }

        CHECK_KEY_AND_SET_MESSAGE_STR(entry->key.str,
                                      SSS_SUDO_ITEM_RUSER,
                                      contents->runas_user,
                                      ((char *) entry->value.ptr));
        CHECK_KEY_AND_SET_MESSAGE_STR(entry->key.str,
                                      SSS_SUDO_ITEM_RGROUP,
                                      contents->runas_group,
                                      ((char *) entry->value.ptr));
        CHECK_KEY_AND_SET_MESSAGE_STR(entry->key.str,
                                      SSS_SUDO_ITEM_PROMPT,
                                      contents->prompt,
                                      ((char *) entry->value.ptr));
        CHECK_KEY_AND_SET_MESSAGE_STR(entry->key.str,
                                      SSS_SUDO_ITEM_NETADDR,
                                      contents->network_addrs,
                                      ((char *) entry->value.ptr));
        CHECK_KEY_AND_SET_MESSAGE_INT(entry->key.str,
                                      SSS_SUDO_ITEM_USE_SUDOEDIT,
                                      contents->use_sudoedit,
                                      ((char *) entry->value.ptr));
        CHECK_KEY_AND_SET_MESSAGE_INT(entry->key.str,
                                      SSS_SUDO_ITEM_USE_SETHOME,
                                      contents->use_set_home,
                                      ((char *) entry->value.ptr));
        CHECK_KEY_AND_SET_MESSAGE_INT(entry->key.str,
                                      SSS_SUDO_ITEM_USE_PRESERV_ENV ,
                                      contents->use_preserve_environment,
                                      ((char *) entry->value.ptr));
        CHECK_KEY_AND_SET_MESSAGE_INT(entry->key.str,
                                      SSS_SUDO_ITEM_USE_IMPLIED_SHELL,
                                      contents->use_implied_shell,
                                      ((char *) entry->value.ptr));
        CHECK_KEY_AND_SET_MESSAGE_INT(entry->key.str,
                                      SSS_SUDO_ITEM_USE_LOGIN_SHELL,
                                      contents->use_login_shell,
                                      ((char *) entry->value.ptr));
        CHECK_KEY_AND_SET_MESSAGE_INT(entry->key.str,
                                      SSS_SUDO_ITEM_USE_RUN_SHELL,
                                      contents->use_run_shell,
                                      ((char *) entry->value.ptr));
        CHECK_KEY_AND_SET_MESSAGE_INT(entry->key.str,
                                      SSS_SUDO_ITEM_USE_PRE_GROUPS,
                                      contents->use_preserve_groups,
                                      ((char *) entry->value.ptr));
        CHECK_KEY_AND_SET_MESSAGE_INT(entry->key.str,
                                      SSS_SUDO_ITEM_USE_IGNORE_TICKET,
                                      contents->use_ignore_ticket,
                                      ((char *) entry->value.ptr));
        CHECK_KEY_AND_SET_MESSAGE_INT(entry->key.str,
                                      SSS_SUDO_ITEM_USE_NON_INTERACTIVE,
                                      contents->use_noninteractive,
                                      ((char *) entry->value.ptr));
        CHECK_KEY_AND_SET_MESSAGE_INT(entry->key.str,
                                      SSS_SUDO_ITEM_DEBUG_LEVEL,
                                      contents->debug_level,
                                      ((char *) entry->value.ptr));
        CHECK_KEY_AND_SET_MESSAGE_INT(entry->key.str,
                                      SSS_SUDO_ITEM_CLI_PID,
                                      contents->cli_pid,
                                      ((char *) entry->value.ptr));
    }
    free(iter);
    return SSS_SBUS_CONV_SUCCESS;
}

errno_t evaluate_sudo_valid_rules(TALLOC_CTX* mem_ctx,
                                  struct sss_valid_sudorules * valid_rules,
                                  char * user_cmnd,
                                  char * user_args,
                                  char ** safe_cmnd,
                                  char ** safe_args,
                                  unsigned int * access){

    struct sss_sudorule_list * list_head = valid_rules->non_defaults , *current_node;
    struct ldb_message_element *el;
    int i=0;
    char * tmpcmd, *space;
    struct sudo_cmd_ctx * sudo_cmnd;
    struct sss_sudo_command_list * list_cmnds_head = NULL, *list_cmnds_node;

    *access = SUDO_DENY_ACCESS;
    DEBUG(0,("\n\n\nIn rule evaluation based on commands\n"));
    sudo_cmnd = talloc_zero(mem_ctx,struct sudo_cmd_ctx);
    if(!sudo_cmnd){
        DEBUG(0,("Failed to allocate command structure.\n"));
        return ENOMEM;
    }
    current_node = list_head;
    while(current_node != NULL) {

        el = ldb_msg_find_element(current_node->data,
                                  SYSDB_SUDO_COMMAND_ATTR);
        if (!el) {
            DEBUG(0, ("Failed to get sudo commands for sudorule\n"));
        }
        for (i = 0; i < el->num_values; i++) {
            tmpcmd = talloc_asprintf(mem_ctx,
                                     "%s",
                                     (const char *) (el->values[i].data));
            if (!tmpcmd) {
                DEBUG(0, ("Failed to build commands string - dn: %s\n",
                        ldb_dn_get_linearized(current_node->data->dn)));
                return ENOMEM;
            }
            /*
             * Make a list of commands inside an entry with commands with negation in the
             * front of the list and the commands without negation follows them. This helps
             * to endure that we are evaluating the commands with ! first.
             */

            if(tmpcmd[0]=='!') {
                list_cmnds_node =  talloc_zero(mem_ctx, struct sss_sudo_command_list);
                list_cmnds_node->values = &(el->values[i]);
                list_cmnds_node->next = NULL;
                list_cmnds_node->prev = NULL;
                DLIST_ADD( list_cmnds_head , list_cmnds_node);
            }
            else {
                list_cmnds_node =  talloc_zero(mem_ctx, struct sss_sudo_command_list);
                list_cmnds_node->values = &(el->values[i]);
                list_cmnds_node->next = NULL;
                list_cmnds_node->prev = NULL;
                DLIST_ADD_END( list_cmnds_head , list_cmnds_node, struct sss_sudo_command_list*);
            }
        }

        DLIST_FOR_EACH(list_cmnds_node, list_cmnds_head){
            tmpcmd = (char *)list_cmnds_node->values->data;

            DEBUG(0, ("sudoCommand under test: %s\n" ,tmpcmd));
            space = strchr(tmpcmd,' ');
            if(space) {
                *space = '\0';
                /*
                 * FIXME: breaking commands at space is not optimal, a patch is needed.
                 */
                sudo_cmnd->arg= (space +1);
            }
            else
                sudo_cmnd->arg = NULL;


            if(tmpcmd[0]=='!') {
                sudo_cmnd->fqcomnd = (tmpcmd+1);
                sudo_cmnd->negated = 1;
            }
            else if(strcmp(tmpcmd,"ALL")) {
                sudo_cmnd->fqcomnd=tmpcmd;
                sudo_cmnd->negated = 0;
            }
            else {
                *safe_cmnd = user_cmnd;
                *safe_args = user_args;
                return SUDO_ALLOW_ACCESS;
            }
            if (command_matches(mem_ctx,
                                sudo_cmnd->fqcomnd,
                                sudo_cmnd->arg,
                                user_cmnd,
                                user_args,
                                safe_cmnd,
                                safe_args) == SUDO_MATCH_TRUE){
                if(sudo_cmnd->negated)
                    *access = SUDO_DENY_ACCESS;
                else
                    *access = SUDO_ALLOW_ACCESS;
            }
            else
                *access = SUDO_DENY_ACCESS;
            DEBUG(0, ("%s matched and %s \n" ,tmpcmd,sudo_cmnd->negated?"negated":"not negated"));
        }


        current_node = current_node->next;
    }

    DEBUG(0,("Rule evaluation based on commands is over\n"));
    return EOK;

}

errno_t sudo_query_parse(TALLOC_CTX *mem_ctx,
                         struct DBusMessage *message,
                         struct sss_sudo_msg_contents **sudo_msg_packet){
    DBusMessageIter msg_iter;
    DBusMessageIter subItem;
    hash_table_t *settings_table;
    hash_table_t *env_table;
    char **ui;
    char **command_array;
    int count = 0 , ret =-1;
    struct sss_sudo_msg_contents *contents;

    contents = talloc_zero(mem_ctx,struct sss_sudo_msg_contents);
    if(!contents){
        DEBUG(0,("Failed to allocate sudo msg structure."));
        return SSS_SUDO_RESPONDER_MEMORY_ERR;
    }

    if (!dbus_message_iter_init(message, &msg_iter)) {
        DEBUG(0,( "Message received as empty!\n"));
        return SSS_SUDO_RESPONDER_MESSAGE_ERR;
    }

        if(DBUS_TYPE_STRUCT != dbus_message_iter_get_arg_type(&msg_iter)) {
            DEBUG(0,( "Argument is not struct!\n"));
            return SSS_SUDO_RESPONDER_MESSAGE_ERR;
        }
        else{
            dbus_message_iter_recurse(&msg_iter,&subItem);
        }

            if(DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&subItem)) {
                DEBUG(0,("UID failed"));
                return SSS_SUDO_RESPONDER_MESSAGE_ERR;
            }
            else {
                dbus_message_iter_get_basic(&subItem, &contents->userid);
                dbus_message_iter_next (&subItem);
            }

            if(DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&subItem)) {
                DEBUG(0,("CWD failed"));
                return SSS_SUDO_RESPONDER_MESSAGE_ERR;
            }
            else {
                dbus_message_iter_get_basic(&subItem, &contents->cwd);
                dbus_message_iter_next (&subItem);
            }

            if(DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&subItem)) {
                DEBUG(0,("TTY failed"));
                return SSS_SUDO_RESPONDER_MESSAGE_ERR;
            }
            else {
                dbus_message_iter_get_basic(&subItem, &contents->tty);
                dbus_message_iter_next (&subItem);
            }
            if(DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&subItem)) {
                DEBUG(0,("FQ Command failed"));
                return SSS_SUDO_RESPONDER_MESSAGE_ERR;
            }
            else {
                dbus_message_iter_get_basic(&subItem, &contents->fq_command);
            }

            DEBUG(0,("-----------Message---------\n"
                    "uid : %d\ncwd : %s\ntty : %s\nFQ Command: %s\n",contents->userid,contents->cwd,contents->tty,contents->fq_command));

            dbus_message_iter_next (&msg_iter);

            if(DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&msg_iter)) {
                DEBUG(0,("array size failed"));
                return SSS_SUDO_RESPONDER_MESSAGE_ERR;
            }
            else {
                dbus_message_iter_get_basic(&msg_iter, &contents->command_count);
                DEBUG(0,("Command array size: %d\n",contents->command_count));
            }
            dbus_message_iter_next (&msg_iter);

        command_array = (char**)malloc(contents->command_count*sizeof(char *));
        DEBUG(0,("command : "));

        if( DBUS_TYPE_ARRAY != dbus_message_iter_get_arg_type(&msg_iter)) {
            DEBUG(0,("Command array failed!\n"));
            return SSS_SUDO_RESPONDER_MESSAGE_ERR;
        }
        else{
            dbus_message_iter_recurse(&msg_iter,&subItem);
        }

            for(ui = command_array,count = contents->command_count; count--; ui++) {
                if(DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&subItem)) {
                    DEBUG(0,("string array content failed"));
                    return SSS_SUDO_RESPONDER_MESSAGE_ERR;

                }
                else {
                    dbus_message_iter_get_basic(&subItem, ui);
                    DEBUG(0,("%s ",*ui));
                    if(!dbus_message_iter_next (&subItem)) {
                        /*"Array ended. */
                        break;
                    }
                }
            }
            DEBUG(0,("\n"));

        contents->command = command_array;
        dbus_message_iter_next(&msg_iter);

                if( dbus_msg_iter_to_dhash(&msg_iter, &settings_table)!= SSS_SBUS_CONV_SUCCESS){
                    DEBUG(0,("settings table corrupted!\n"));
                    return SSS_SUDO_RESPONDER_MESSAGE_ERR;
                }
                contents->settings_table = settings_table;
                ret = load_settings(settings_table,contents);
                if (ret != SSS_SBUS_CONV_SUCCESS ){
                    DEBUG(0,("Settings table failed to parse!\n"));
                    return SSS_SUDO_RESPONDER_MESSAGE_ERR;
                }

                dbus_message_iter_next(&msg_iter);

                if( dbus_msg_iter_to_dhash(&msg_iter, &env_table)!= SSS_SBUS_CONV_SUCCESS){
                    DEBUG(0,("environment table corrupted!\n"));
                    return SSS_SUDO_RESPONDER_MESSAGE_ERR;
                }
    contents->env_table = env_table;
    *sudo_msg_packet = contents;

    DEBUG(0, ("-----------Message END---------\n"));
    return SSS_SUDO_RESPONDER_SUCCESS;

}

errno_t format_sudo_result_reply(TALLOC_CTX * mem_ctx,
                                 DBusMessage **reply_msg,
                                 struct sss_sudo_msg_contents *sudo_msg_packet,
                                 const char * result){

    dbus_uint32_t header = SSS_SUDO_REPLY_HEADER,command_size;
    DBusMessage *reply;
    DBusMessageIter msg_iter;
    DBusMessageIter subItem;
    char ** command_array;
    dbus_bool_t dbret;

    reply = *reply_msg;

    command_size = sudo_msg_packet->command_count;
    dbret = dbus_message_append_args(reply,
                                     DBUS_TYPE_UINT32, &header,
                                     DBUS_TYPE_STRING,&result,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(0, ("Failed to build sudo dbus reply\n"));
        return SSS_SUDO_RESPONDER_REPLY_ERR;
    }

    dbus_message_iter_init_append(reply, &msg_iter);

        if(!dbus_message_iter_open_container(&msg_iter,
                                             DBUS_TYPE_ARRAY,
                                             "s",
                                             &subItem)) {
            DEBUG(0, ("Out Of Memory!\n"));
            return SSS_SUDO_RESPONDER_REPLY_ERR;
        }

                for(command_array = sudo_msg_packet->command ; command_size-- ; command_array++) {

                    if (!dbus_message_iter_append_basic(&subItem,
                                                        DBUS_TYPE_STRING,
                                                        command_array)) {
                        DEBUG(0, ( "Out Of Memory!\n"));
                        return SSS_SUDO_RESPONDER_REPLY_ERR;
                    }
                }

        if (!dbus_message_iter_close_container(&msg_iter,&subItem)) {
            DEBUG(0, ( "Out Of Memory!\n"));
            return SSS_SUDO_RESPONDER_REPLY_ERR;
        }

    if(dbus_dhash_to_msg_iter(&sudo_msg_packet->env_table,&msg_iter) != SSS_SBUS_CONV_SUCCESS){
        DEBUG(0,("fatal: env message framing failed."));
        return SSS_SUDO_RESPONDER_DHASH_ERR;
    }

    *reply_msg = reply;

    return SSS_SUDO_RESPONDER_SUCCESS;

}

errno_t get_serialised_args(TALLOC_CTX* mem_ctx, char ** cmnd_args, int count, char ** arg_out){

    char * args = NULL;
    int i = 0 ;
    if(cmnd_args == NULL) {
        *arg_out = NULL;
        return EOK;
    }
    args = talloc_strdup(mem_ctx, (cmnd_args[0]?cmnd_args[0]:NULL));
    if(args == NULL && (cmnd_args == NULL || *cmnd_args ) ){
        DEBUG(0,("Linearizing the arguments failed\n"));
        return ENOMEM;
    }
    for ( i=1; i<count-1 ;i++){
        args = talloc_asprintf_append(args," %s",cmnd_args[i]);
        if(args == NULL ){
            DEBUG(0,("Linearizing the arguments failed\n"));
            return ENOMEM;
        }
    }
    *arg_out = args;
    return EOK;
}

static int sudo_query_validation(DBusMessage *message, struct sbus_connection *conn)
{
    struct sudo_client *sudocli;
    DBusMessage *reply = NULL;
    int ret = -1;
    void *data;
    char * result;
    char * user_args;
    char * safe_cmnd;
    char * safe_args;
    struct sss_sudo_msg_contents * msg;
    struct sss_valid_sudorules * valid_sudo_rules;
    unsigned int access_specifier = SUDO_DENY_ACCESS;

    TALLOC_CTX * tmpctx;


    data = sbus_conn_get_private_data(conn);
    sudocli = talloc_get_type(data, struct sudo_client);
    if (!sudocli) {
        DEBUG(0, ("Connection holds no valid init data exists \n",
                SSS_SUDO_RESPONDER_CONNECTION_ERR));
        ret = SSS_SUDO_RESPONDER_CONNECTION_ERR;
        goto done;
    }
    result = talloc_strdup(sudocli,SUDO_DENY_ACCESS_STR);

    /* First thing, cancel the timeout */
    DEBUG(4, ("Cancel SUDO client timeout [%p]\n", sudocli->timeout));
    talloc_zfree(sudocli->timeout);

    ret = sudo_query_parse(sudocli,
                           message,
                           &msg);
    if(ret != SSS_SUDO_RESPONDER_SUCCESS){
        DEBUG(0,( "message parser for sudo returned %d\n",ret));
        ret = SSS_SUDO_RESPONDER_PARSE_ERR;
        goto done;
    }
    DEBUG(0, ("-----------Message successfully Parsed---------\n"));
    talloc_set_destructor(sudocli, sudo_client_destructor);

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        DEBUG(0, ("Failed create a context for sudo rule processing\n"));
        ret = ENOMEM;
        goto done;
    }

    ret = find_sudorules_for_user_in_db_list(tmpctx,sudocli,msg, &valid_sudo_rules);
    if(ret != EOK ){
        DEBUG(0, ("finding sudorules with given criterion failed\n"));
        ret = SSS_SUDO_RESPONDER_PARSE_ERR;
        goto done;
    }

    ret = get_serialised_args(tmpctx,
                              (msg->command_count > 1)? msg->command+1: NULL,
                                                      msg->command_count-1,
                                                      & user_args);
    if(ret != EOK ){
        DEBUG(0, ("get_serialised_args() failed\n"));
        ret = SSS_SUDO_RESPONDER_PARSE_ERR;
        goto done;
    }

    ret = evaluate_sudo_valid_rules(tmpctx,
                                    valid_sudo_rules,
                                    msg->fq_command,
                                    user_args,
                                    &safe_cmnd,
                                    &safe_args,
                                    &access_specifier);
    if(ret != EOK ){
        DEBUG(0, ("sudo rule evaluation failed\n"));
        ret = SSS_SUDO_RESPONDER_PARSE_ERR;
        goto done;
    }

    if(access_specifier == SUDO_ALLOW_ACCESS){
        DEBUG(0,("EValuation returned a ALLOW_ACCESS ticket\n"));
        result = talloc_strdup(sudocli,SUDO_ALLOW_ACCESS_STR);
    }
    else
    {
        DEBUG(0,("EValuation returned a DENY_ACCESS ticket\n"));
    }


    /*
     * TODO: Evaluate the list of non eliminated sudo rules and make necessary
     * changed in command array and env table with result
     *
     *
     *reply that everything is ok
     */
    reply = dbus_message_new_method_return(message);
    if (!reply) {
        DEBUG(0, ("Dbus Out of memory!\n"));
        ret = SSS_SUDO_RESPONDER_REPLY_ERR;
        goto done;
    }

    ret = format_sudo_result_reply(sudocli,
                                   &reply,
                                   msg,
                                   result);
    if (ret != SSS_SUDO_RESPONDER_SUCCESS) {
        DEBUG(0, ("Dbus reply failed with error state %d\n",ret));
        ret = SSS_SUDO_RESPONDER_REPLY_ERR;
        goto done;
    }

    /* send reply back */
    sbus_conn_send_reply(conn, reply);
    ret = EOK;

    done:
    talloc_zfree(tmpctx);
    sudocli->initialized = true;
    /*if(message)
        dbus_message_unref(message);
    if(reply)
        dbus_message_unref(reply);

    sudocli->initialized = true;
    if(!conn)
        sbus_disconnect(conn);*/
    return ret;
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

    sudocli = talloc_zero(conn, struct sudo_client);
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
	/*
    static struct sss_cmd_table sss_cmds[] = {
                                              {SSS_SUDO_AUTHENTICATE, NULL},
                                              {SSS_SUDO_INVALIDATE, NULL},
                                              {SSS_SUDO_VALIDATE, NULL},
                                              {SSS_SUDO_LIST, NULL},
                                              {SSS_CLI_NULL, NULL}
    };
    */
	static struct sss_cmd_table sss_cmds[] = {{SSS_CLI_NULL, NULL}};

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

