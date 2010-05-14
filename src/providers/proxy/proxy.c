/*
   SSSD

   Proxy Module

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008-2009

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

#include <nss.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "providers/dp_backend.h"
#include "db/sysdb.h"
#include "proxy.h"
#include <dhash.h>

struct proxy_nss_ops {
    enum nss_status (*getpwnam_r)(const char *name, struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*getpwuid_r)(uid_t uid, struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*setpwent)(void);
    enum nss_status (*getpwent_r)(struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*endpwent)(void);

    enum nss_status (*getgrnam_r)(const char *name, struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*getgrgid_r)(gid_t gid, struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*setgrent)(void);
    enum nss_status (*getgrent_r)(struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*endgrent)(void);
    enum nss_status (*initgroups_dyn)(const char *user, gid_t group,
                                      long int *start, long int *size,
                                      gid_t **groups, long int limit,
                                      int *errnop);
};

struct proxy_ctx {
    struct be_ctx *be;
    int entry_cache_timeout;
    struct proxy_nss_ops ops;
};

struct proxy_auth_ctx {
    struct be_ctx *be;
    char *pam_target;

    uint32_t max_children;
    uint32_t running;
    uint32_t next_id;
    hash_table_t *request_table;
    struct sbus_connection *sbus_srv;
    int timeout_ms;
};

static int client_registration(DBusMessage *message,
                               struct sbus_connection *conn);

static struct sbus_method proxy_methods[] = {
    { DP_METHOD_REGISTER, client_registration },
    { NULL, NULL }
};

struct sbus_interface proxy_interface = {
    DP_INTERFACE,
    DP_PATH,
    SBUS_DEFAULT_VTABLE,
    proxy_methods,
    NULL
};

struct authtok_conv {
    uint32_t authtok_size;
    uint8_t *authtok;
};

struct proxy_client_ctx {
    struct be_req *be_req;
    struct proxy_auth_ctx *auth_ctx;
};

static void proxy_reply(struct be_req *req, int dp_err,
                        int error, const char *errstr);

static struct tevent_req *proxy_child_send(TALLOC_CTX *mem_ctx,
                                           struct proxy_auth_ctx *ctx,
                                           struct be_req *be_req);
static void proxy_child_done(struct tevent_req *child_req);
static void proxy_pam_handler(struct be_req *req) {
    struct pam_data *pd;
    struct proxy_auth_ctx *ctx;
    struct tevent_req *child_req = NULL;
    struct proxy_client_ctx *client_ctx;

    pd = talloc_get_type(req->req_data, struct pam_data);

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
            ctx = talloc_get_type(req->be_ctx->bet_info[BET_AUTH].pvt_bet_data,
                                  struct proxy_auth_ctx);
            break;
        case SSS_PAM_CHAUTHTOK:
        case SSS_PAM_CHAUTHTOK_PRELIM:
            ctx = talloc_get_type(req->be_ctx->bet_info[BET_CHPASS].pvt_bet_data,
                                  struct proxy_auth_ctx);
            break;
        case SSS_PAM_ACCT_MGMT:
            ctx = talloc_get_type(req->be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                                  struct proxy_auth_ctx);
            break;
        case SSS_PAM_SETCRED:
        case SSS_PAM_OPEN_SESSION:
        case SSS_PAM_CLOSE_SESSION:
            pd->pam_status = PAM_SUCCESS;
            proxy_reply(req, DP_ERR_OK, EOK, NULL);
            return;
        default:
            DEBUG(1, ("Unsupported PAM task.\n"));
            pd->pam_status = PAM_MODULE_UNKNOWN;
            proxy_reply(req, DP_ERR_OK, EINVAL, "Unsupported PAM task");
            return;
    }

    client_ctx = talloc(req, struct proxy_client_ctx);
    if (client_ctx == NULL) {
        proxy_reply(req, DP_ERR_FATAL, ENOMEM, NULL);
        return;
    }
    client_ctx->auth_ctx = ctx;
    client_ctx->be_req = req;

    /* Queue the request and spawn a child if there
     * is an available slot.
     */
    child_req = proxy_child_send(req, ctx, req);
    if (child_req == NULL) {
        /* Could not queue request
         * Return an error
         */
        proxy_reply(req, DP_ERR_FATAL, EINVAL, "Could not queue request\n");
        return;
    }
    tevent_req_set_callback(child_req, proxy_child_done, client_ctx);
    return;
}

struct pc_init_ctx;
struct proxy_child_ctx {
    struct proxy_auth_ctx *auth_ctx;
    struct be_req *be_req;
    struct pam_data *pd;

    uint32_t id;
    pid_t pid;
    bool running;

    struct sbus_connection *conn;
    struct tevent_timer *timer;

    struct tevent_req *init_req;
};

static int proxy_child_destructor(TALLOC_CTX *ctx)
{
    struct proxy_child_ctx *child_ctx =
            talloc_get_type(ctx, struct proxy_child_ctx);
    hash_key_t key;

    DEBUG(8, ("Removing proxy child id [%d]\n", child_ctx->id));
    key.type = HASH_KEY_ULONG;
    key.ul = child_ctx->id;
    hash_delete(child_ctx->auth_ctx->request_table, &key);
    return 0;
}

static struct tevent_req *proxy_child_init_send(TALLOC_CTX *mem_ctx,
                                              struct proxy_child_ctx *child_ctx,
                                              struct proxy_auth_ctx *auth_ctx);
static void proxy_child_init_done(struct tevent_req *subreq);
static struct tevent_req *proxy_child_send(TALLOC_CTX *mem_ctx,
                                           struct proxy_auth_ctx *auth_ctx,
                                           struct be_req *be_req)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct proxy_child_ctx *state;
    int hret;
    hash_key_t key;
    hash_value_t value;
    uint32_t first;

    req = tevent_req_create(mem_ctx, &state, struct proxy_child_ctx);
    if (req == NULL) {
        DEBUG(1, ("Could not send PAM request to child\n"));
        return NULL;
    }

    state->be_req = be_req;
    state->auth_ctx = auth_ctx;
    state->pd = talloc_get_type(be_req->req_data, struct pam_data);

    /* Find an available key */
    key.type = HASH_KEY_ULONG;
    key.ul = auth_ctx->next_id;

    first = auth_ctx->next_id;
    while (auth_ctx->next_id == 0 ||
            hash_has_key(auth_ctx->request_table, &key)) {
        /* Handle overflow, zero is a reserved value
         * Also handle the unlikely case where the next ID
         * is still awaiting being run
         */
        auth_ctx->next_id++;
        key.ul = auth_ctx->next_id;

        if (auth_ctx->next_id == first) {
            /* We've looped through all possible integers! */
            DEBUG(0, ("Serious error: queue is too long!\n"));
            talloc_zfree(req);
            return NULL;
        }
    }

    state->id = auth_ctx->next_id;
    auth_ctx->next_id++;

    value.type = HASH_VALUE_PTR;
    value.ptr = req;
    DEBUG(8, ("Queueing request [%d]\n", key.ul));
    hret = hash_enter(auth_ctx->request_table,
                      &key, &value);
    if (hret != HASH_SUCCESS) {
        DEBUG(1, ("Could not add request to the queue\n"));
        talloc_zfree(req);
        return NULL;
    }

    talloc_set_destructor((TALLOC_CTX *) state,
                          proxy_child_destructor);

    if (auth_ctx->running < auth_ctx->max_children) {
        /* There's an available slot; start a child
         * to handle the request
         */

        auth_ctx->running++;
        subreq = proxy_child_init_send(auth_ctx, state, auth_ctx);
        if (!subreq) {
            DEBUG(1, ("Could not fork child process\n"));
            auth_ctx->running--;
            talloc_zfree(req);
            return NULL;
        }
        tevent_req_set_callback(subreq, proxy_child_init_done, req);

        state->running = true;
    }
    else {
        /* If there was no available slot, it will be queued
         * until a slot is available
         */
        DEBUG(8, ("All available child slots are full, queuing request\n"));
    }
    return req;
}

struct pc_init_ctx {
    char *command;
    pid_t pid;
    struct tevent_timer *timeout;
    struct tevent_signal *sige;
    struct proxy_child_ctx *child_ctx;
    struct sbus_connection *conn;
};

static int pc_init_destructor (TALLOC_CTX *ctx)
{
    struct pc_init_ctx *init_ctx =
            talloc_get_type(ctx, struct pc_init_ctx);

    /* If the init request has died, forcibly kill the child */
    kill(init_ctx->pid, SIGKILL);
    return 0;
}

static void pc_init_sig_handler(struct tevent_context *ev,
                           struct tevent_signal *sige, int signum,
                           int count, void *__siginfo, void *pvt);
static void pc_init_timeout(struct tevent_context *ev,
                            struct tevent_timer *te,
                            struct timeval t, void *ptr);
static struct tevent_req *proxy_child_init_send(TALLOC_CTX *mem_ctx,
                                              struct proxy_child_ctx *child_ctx,
                                              struct proxy_auth_ctx *auth_ctx)
{
    struct tevent_req *req;
    struct pc_init_ctx *state;
    char **proxy_child_args;
    struct timeval tv;
    errno_t ret;
    pid_t pid;

    req = tevent_req_create(mem_ctx, &state, struct pc_init_ctx);
    if (req == NULL) {
        DEBUG(1, ("Could not create tevent_req\n"));
        return NULL;
    }

    state->child_ctx = child_ctx;

    state->command = talloc_asprintf(req,
            "%s/proxy_child -d %d%s%s --domain %s --id %d",
            SSSD_LIBEXEC_PATH, debug_level,
            (debug_timestamps ? "" : " --debug-timestamps=0"),
            (debug_to_file ? " --debug-to-files" : ""),
            auth_ctx->be->domain->name,
            child_ctx->id);
    if (state->command == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        return NULL;
    }

    DEBUG(7, ("Starting proxy child with args [%s]\n", state->command));

    pid = fork();
    if (pid < 0) {
        ret = errno;
        DEBUG(1, ("fork failed [%d][%s].\n", ret, strerror(ret)));
        talloc_zfree(req);
        return NULL;
    }

    if (pid == 0) { /* child */
        proxy_child_args = parse_args(state->command);
        execvp(proxy_child_args[0], proxy_child_args);

        ret = errno;
        DEBUG(0, ("Could not start proxy child [%s]: [%d][%s].\n",
                  state->command, ret, strerror(ret)));

        _exit(1);
    }

    else { /* parent */
        state->pid = pid;
        /* Make sure to kill the child process if we abort */
        talloc_set_destructor((TALLOC_CTX *)state, pc_init_destructor);

        state->sige = tevent_add_signal(auth_ctx->be->ev, req,
                                        SIGCHLD, SA_SIGINFO,
                                        pc_init_sig_handler, req);
        if (state->sige == NULL) {
            DEBUG(1, ("tevent_add_signal failed.\n"));
            talloc_zfree(req);
            return NULL;
        }

        /* Save the init request to the child context.
         * This is technically a layering violation,
         * but it's the only sane way to be able to
         * identify which client is which when it
         * connects to the backend in
         * client_registration()
         */
        child_ctx->init_req = req;

        /* Wait six seconds for the child to connect
         * This is because the connection handler will add
         * its own five-second timeout, and we don't want to
         * be faster here.
         */
        tv = tevent_timeval_current_ofs(6, 0);
        state->timeout = tevent_add_timer(auth_ctx->be->ev, req,
                                          tv, pc_init_timeout, req);

        /* processing will continue once the connection is received
         * in proxy_client_init()
         */
        return req;
    }
}

static void pc_init_sig_handler(struct tevent_context *ev,
                                struct tevent_signal *sige, int signum,
                                int count, void *__siginfo, void *pvt)
{
    int ret;
    int child_status;
    struct tevent_req *req;
    struct pc_init_ctx *init_ctx;

    if (count <= 0) {
        DEBUG(0, ("SIGCHLD handler called with invalid child count\n"));
        return;
    }

    req = talloc_get_type(pvt, struct tevent_req);
    init_ctx = tevent_req_data(req, struct pc_init_ctx);

    DEBUG(7, ("Waiting for child [%d].\n", init_ctx->pid));

    errno = 0;
    ret = waitpid(init_ctx->pid, &child_status, WNOHANG);

    if (ret == -1) {
        ret = errno;
        DEBUG(1, ("waitpid failed [%d][%s].\n", ret, strerror(ret)));
    } else if (ret == 0) {
        DEBUG(1, ("waitpid did not find a child with changed status.\n"));
    } else {
        if (WIFEXITED(child_status)) {
            DEBUG(4, ("child [%d] exited with status [%d].\n", ret,
                      WEXITSTATUS(child_status)));
            tevent_req_error(req, EIO);
        } else if (WIFSIGNALED(child_status)) {
            DEBUG(4, ("child [%d] was terminate by signal [%d].\n", ret,
                      WTERMSIG(child_status)));
            tevent_req_error(req, EIO);
        } else {
            if (WIFSTOPPED(child_status)) {
                DEBUG(1, ("child [%d] was stopped by signal [%d].\n", ret,
                          WSTOPSIG(child_status)));
            }
            if (WIFCONTINUED(child_status)) {
                DEBUG(1, ("child [%d] was resumed by delivery of SIGCONT.\n",
                          ret));
            }
            DEBUG(1, ("Child is still running, no new child is started.\n"));
            return;
        }
    }
}

static void pc_init_timeout(struct tevent_context *ev,
                            struct tevent_timer *te,
                            struct timeval t, void *ptr)
{
    struct tevent_req *req;
    struct pc_init_ctx *state;

    DEBUG(2, ("Client timed out before Identification!\n"));

    req = talloc_get_type(ptr, struct tevent_req);
    state = tevent_req_data(req, struct pc_init_ctx);

    tevent_req_error(req, ETIMEDOUT);
}

static errno_t proxy_child_init_recv(struct tevent_req *req,
                                   pid_t *pid,
                                   struct sbus_connection **conn)
{
    struct pc_init_ctx *state;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    state = tevent_req_data(req, struct pc_init_ctx);

    /* Unset the destructor since we initialized successfully.
     * We don't want to kill the child now that it's properly
     * set up.
     */
    talloc_set_destructor((TALLOC_CTX *)state, NULL);

    *pid = state->pid;
    *conn = state->conn;

    return EOK;
}

struct proxy_child_sig_ctx {
    struct proxy_auth_ctx *auth_ctx;
    pid_t pid;
};
static void proxy_child_sig_handler(struct tevent_context *ev,
                                    struct tevent_signal *sige, int signum,
                                    int count, void *__siginfo, void *pvt);
static struct tevent_req *proxy_pam_conv_send(TALLOC_CTX *mem_ctx,
                                              struct proxy_auth_ctx *auth_ctx,
                                              struct sbus_connection *conn,
                                              struct pam_data *pd,
                                              pid_t pid);
static void proxy_pam_conv_done(struct tevent_req *subreq);
static void proxy_child_init_done(struct tevent_req *subreq) {
    int ret;
    struct tevent_signal *sige;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct proxy_child_ctx *child_ctx =
            tevent_req_data(req, struct proxy_child_ctx);
    struct proxy_child_sig_ctx *sig_ctx;

    ret = proxy_child_init_recv(subreq, &child_ctx->pid, &child_ctx->conn);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(6, ("Proxy child init failed [%d]\n", ret));
        tevent_req_error(req, ret);
        return;
    }

    /* An initialized child is available, awaiting the PAM command */
    subreq = proxy_pam_conv_send(req, child_ctx->auth_ctx,
                                 child_ctx->conn, child_ctx->pd,
                                 child_ctx->pid);
    if (!subreq) {
        DEBUG(1,("Could not start PAM conversation\n"));
        tevent_req_error(req, EIO);
        return;
    }
    tevent_req_set_callback(subreq, proxy_pam_conv_done, req);

    /* Add a signal handler for the child under the auth_ctx,
     * that way if the child exits after completion of the
     * request, it will still be handled.
     */
    sig_ctx = talloc_zero(child_ctx->auth_ctx, struct proxy_child_sig_ctx);
    if(sig_ctx == NULL) {
        DEBUG(1, ("tevent_add_signal failed.\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }
    sig_ctx->auth_ctx = child_ctx->auth_ctx;
    sig_ctx->pid = child_ctx->pid;

    sige = tevent_add_signal(child_ctx->auth_ctx->be->ev,
                             child_ctx->auth_ctx,
                             SIGCHLD, SA_SIGINFO,
                             proxy_child_sig_handler,
                             sig_ctx);
    if (sige == NULL) {
        DEBUG(1, ("tevent_add_signal failed.\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }

    /* Steal the signal context onto the signal event
     * so that when the signal is freed, the context
     * will go with it.
     */
    talloc_steal(sige, sig_ctx);
}

static void remove_sige(struct tevent_context *ev,
                        struct tevent_immediate *imm,
                        void *pvt);
static void run_proxy_child_queue(struct tevent_context *ev,
                                  struct tevent_immediate *imm,
                                  void *pvt);
static void proxy_child_sig_handler(struct tevent_context *ev,
                                    struct tevent_signal *sige, int signum,
                                    int count, void *__siginfo, void *pvt)
{
    int ret;
    int child_status;
    struct proxy_child_sig_ctx *sig_ctx;
    struct tevent_immediate *imm;
    struct tevent_immediate *imm2;

    if (count <= 0) {
        DEBUG(0, ("SIGCHLD handler called with invalid child count\n"));
        return;
    }

    sig_ctx = talloc_get_type(pvt, struct proxy_child_sig_ctx);
    DEBUG(7, ("Waiting for child [%d].\n", sig_ctx->pid));

    errno = 0;
    ret = waitpid(sig_ctx->pid, &child_status, WNOHANG);

    if (ret == -1) {
        ret = errno;
        DEBUG(1, ("waitpid failed [%d][%s].\n", ret, strerror(ret)));
    } else if (ret == 0) {
        DEBUG(1, ("waitpid did not found a child with changed status.\n"));
    } else {
        if (WIFEXITED(child_status)) {
            DEBUG(4, ("child [%d] exited with status [%d].\n", ret,
                      WEXITSTATUS(child_status)));
        } else if (WIFSIGNALED(child_status)) {
            DEBUG(4, ("child [%d] was terminated by signal [%d].\n", ret,
                      WTERMSIG(child_status)));
        } else {
            if (WIFSTOPPED(child_status)) {
                DEBUG(1, ("child [%d] was stopped by signal [%d].\n", ret,
                          WSTOPSIG(child_status)));
            }
            if (WIFCONTINUED(child_status)) {
                DEBUG(1, ("child [%d] was resumed by delivery of SIGCONT.\n",
                          ret));
            }
            DEBUG(1, ("Child is still running, no new child is started.\n"));
            return;
        }

        imm = tevent_create_immediate(ev);
        if (imm == NULL) {
            DEBUG(1, ("tevent_create_immediate failed.\n"));
            return;
        }

        tevent_schedule_immediate(imm, ev, run_proxy_child_queue,
                                  sig_ctx->auth_ctx);

        /* schedule another immediate timer to delete the sigchld handler */
        imm2 = tevent_create_immediate(ev);
        if (imm == NULL) {
            DEBUG(1, ("tevent_create_immediate failed.\n"));
            return;
        }

        tevent_schedule_immediate(imm2, ev, remove_sige, sige);
    }

    return;
}

static void remove_sige(struct tevent_context *ev,
                        struct tevent_immediate *imm,
                        void *pvt)
{
    talloc_free(pvt);
}

struct proxy_conv_ctx {
    struct proxy_auth_ctx *auth_ctx;
    struct sbus_connection *conn;
    struct pam_data *pd;
    pid_t pid;
};
static void proxy_pam_conv_reply(DBusPendingCall *pending, void *ptr);
static struct tevent_req *proxy_pam_conv_send(TALLOC_CTX *mem_ctx,
                                              struct proxy_auth_ctx *auth_ctx,
                                              struct sbus_connection *conn,
                                              struct pam_data *pd,
                                              pid_t pid)
{
    errno_t ret;
    bool dp_ret;
    DBusMessage *msg;
    struct tevent_req *req;
    struct proxy_conv_ctx *state;

    req = tevent_req_create(mem_ctx, &state, struct proxy_conv_ctx);
    if (req == NULL) {
        return NULL;
    }

    state->auth_ctx = auth_ctx;
    state->conn = conn;
    state->pd = pd;
    state->pid = pid;

    msg = dbus_message_new_method_call(NULL,
                                       DP_PATH,
                                       DP_INTERFACE,
                                       DP_METHOD_PAMHANDLER);
    if (msg == NULL) {
        DEBUG(1, ("dbus_message_new_method_call failed.\n"));
        talloc_zfree(req);
        return NULL;
    }

    DEBUG(4, ("Sending request with the following data:\n"));
    DEBUG_PAM_DATA(4, pd);

    dp_ret = dp_pack_pam_request(msg, pd);
    if (!dp_ret) {
        DEBUG(1, ("Failed to build message\n"));
        dbus_message_unref(msg);
        talloc_zfree(req);
        return NULL;
    }

    ret = sbus_conn_send(state->conn, msg, state->auth_ctx->timeout_ms,
                         proxy_pam_conv_reply, req, NULL);
    if (ret != EOK) {
        dbus_message_unref(msg);
        talloc_zfree(req);
        return NULL;
    }

    dbus_message_unref(msg);
    return req;
}

static void proxy_pam_conv_reply(DBusPendingCall *pending, void *ptr)
{
    struct tevent_req *req;
    struct proxy_conv_ctx *state;
    DBusError dbus_error;
    DBusMessage *reply;
    int type;
    int ret;

    DEBUG(8, ("Handling pam conversation reply\n"));

    req = talloc_get_type(ptr, struct tevent_req);
    state = tevent_req_data(req, struct proxy_conv_ctx);

    dbus_error_init(&dbus_error);

    reply = dbus_pending_call_steal_reply(pending);
    dbus_pending_call_unref(pending);
    if (reply == NULL) {
        DEBUG(0, ("Severe error. A reply callback was called but no reply was"
                  "received and no timeout occurred\n"));
        state->pd->pam_status = PAM_SYSTEM_ERR;
        tevent_req_error(req, EIO);
    }

    type = dbus_message_get_type(reply);
    switch (type) {
        case DBUS_MESSAGE_TYPE_METHOD_RETURN:
            ret = dp_unpack_pam_response(reply, state->pd, &dbus_error);
            if (!ret) {
                DEBUG(0, ("Failed to parse reply.\n"));
                state->pd->pam_status = PAM_SYSTEM_ERR;
                dbus_message_unref(reply);
                tevent_req_error(req, EIO);
                return;
            }
            DEBUG(4, ("received: [%d][%s]\n",
                      state->pd->pam_status,
                      state->pd->domain));
            break;
        case DBUS_MESSAGE_TYPE_ERROR:
            DEBUG(0, ("Reply error [%s].\n",
                    dbus_message_get_error_name(reply)));
            state->pd->pam_status = PAM_SYSTEM_ERR;
            break;
        default:
            DEBUG(0, ("Default... what now?.\n"));
            state->pd->pam_status = PAM_SYSTEM_ERR;
    }
    dbus_message_unref(reply);

    /* Kill the child */
    kill(state->pid, SIGKILL);

    /* Conversation is finished */
    tevent_req_done(req);
}

static errno_t proxy_pam_conv_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void proxy_pam_conv_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = proxy_pam_conv_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(6, ("Proxy PAM conversation failed [%d]\n", ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int proxy_child_recv(struct tevent_req *req,
                          TALLOC_CTX *mem_ctx,
                          struct pam_data **pd)
{
    struct proxy_child_ctx *ctx;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    ctx = tevent_req_data(req, struct proxy_child_ctx);
    *pd = talloc_steal(mem_ctx, ctx->pd);

    return EOK;
}

static void proxy_child_done(struct tevent_req *req)
{
    struct proxy_client_ctx *client_ctx =
            tevent_req_callback_data(req, struct proxy_client_ctx);
    struct pam_data *pd;
    char *password;
    int ret;
    struct tevent_immediate *imm;

    ret = proxy_child_recv(req, client_ctx, &pd);
    talloc_zfree(req);
    if (ret != EOK) {
        /* Pam child failed */
        client_ctx->auth_ctx->running--;
        proxy_reply(client_ctx->be_req, DP_ERR_FATAL, ret,
                    "PAM child failed");

        /* Start the next auth in the queue, if any */
        imm = tevent_create_immediate(client_ctx->be_req->be_ctx->ev);
        if (imm == NULL) {
            DEBUG(1, ("tevent_create_immediate failed.\n"));
            return;
        }

        tevent_schedule_immediate(imm,
                                  client_ctx->be_req->be_ctx->ev,
                                  run_proxy_child_queue,
                                  client_ctx->auth_ctx);
        return;
    }

    /* Check if we need to save the cached credentials */
    if ((pd->cmd == SSS_PAM_AUTHENTICATE || pd->cmd == SSS_PAM_CHAUTHTOK) &&
            pd->pam_status == PAM_SUCCESS &&
            client_ctx->be_req->be_ctx->domain->cache_credentials) {
        password = talloc_strndup(client_ctx->be_req,
                                  (char *) pd->authtok,
                                  pd->authtok_size);
        if (!password) {
            /* password caching failures are not fatal errors */
            DEBUG(2, ("Failed to cache password\n"));
            goto done;
        }
        talloc_set_destructor((TALLOC_CTX *)password, password_destructor);

        ret = sysdb_cache_password(client_ctx,
                                   client_ctx->be_req->be_ctx->sysdb,
                                   client_ctx->be_req->be_ctx->domain,
                                   pd->user, password);

        /* password caching failures are not fatal errors */
        /* so we just log it any return */
        if (ret != EOK) {
            DEBUG(2, ("Failed to cache password (%d)[%s]!?\n",
                      ret, strerror(ret)));
        }
    }

done:
    proxy_reply(client_ctx->be_req, DP_ERR_OK, EOK, NULL);
}

static void run_proxy_child_queue(struct tevent_context *ev,
                                  struct tevent_immediate *imm,
                                  void *pvt)
{
    struct proxy_auth_ctx *auth_ctx;
    struct hash_iter_context_t *iter;
    struct hash_entry_t *entry;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct proxy_child_ctx *state;

    auth_ctx = talloc_get_type(pvt, struct proxy_auth_ctx);

    /* Launch next queued request */
    iter = new_hash_iter_context(auth_ctx->request_table);
    while ((entry = iter->next(iter)) != NULL) {
        req = talloc_get_type(entry->value.ptr, struct tevent_req);
        state = tevent_req_data(req, struct proxy_child_ctx);
        if (!state->running) {
            break;
        }
    }

    if (!entry) {
        /* Nothing pending on the queue */
        return;
    }

    if (auth_ctx->running < auth_ctx->max_children) {
        /* There's an available slot; start a child
         * to handle the request
         */
        auth_ctx->running++;
        subreq = proxy_child_init_send(auth_ctx, state, auth_ctx);
        if (!subreq) {
            DEBUG(1, ("Could not fork child process\n"));
            auth_ctx->running--;
            talloc_zfree(req);
            return;
        }
        tevent_req_set_callback(subreq, proxy_child_init_done, req);

        state->running = true;
    }
}

static void proxy_reply(struct be_req *req, int dp_err,
                        int error, const char *errstr)
{
    if (!req->be_ctx->offstat.offline) {
        /* This action took place online.
         * Fire any online callbacks if necessary.
         * Note: we're checking the offline value directly,
         * because if the activity took a long time to
         * complete, calling be_is_offline() might report false
         * incorrectly.
         */
        be_run_online_cb(req->be_ctx);
    }
    return req->fn(req, dp_err, error, errstr);
}

/* =Common-proxy-tevent_req-utils=========================================*/

#define DEFAULT_BUFSIZE 4096
#define MAX_BUF_SIZE 1024*1024 /* max 1MiB */

/* =Getpwnam-wrapper======================================================*/

static int delete_user(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                       struct sss_domain_info *domain, const char *name);

static int get_pw_name(TALLOC_CTX *mem_ctx,
                       struct proxy_ctx *ctx,
                       struct sysdb_ctx *sysdb,
                       struct sss_domain_info *dom,
                       const char *name)
{
    TALLOC_CTX *tmpctx;
    struct passwd *pwd;
    enum nss_status status;
    char *buffer;
    size_t buflen;
    int ret;

    DEBUG(7, ("Searching user by name (%s)\n", name));

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    pwd = talloc_zero(tmpctx, struct passwd);
    if (!pwd) {
        ret = ENOMEM;
        goto done;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(tmpctx, buflen);
    if (!buffer) {
        ret = ENOMEM;
        goto done;
    }

    /* FIXME: should we move this call outside the transaction to keep the
     * transaction as short as possible ? */
    status = ctx->ops.getpwnam_r(name, pwd, buffer, buflen, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:

        DEBUG(7, ("User %s not found.\n", name));
        ret = delete_user(tmpctx, sysdb, dom, name);
        if (ret) {
            goto done;
        }
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("User %s found: (%s, %d, %d)\n",
                  name, pwd->pw_name, pwd->pw_uid, pwd->pw_gid));

        /* uid=0 or gid=0 are invalid values */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(pwd->pw_uid, dom->id_min, dom->id_max) ||
            OUT_OF_ID_RANGE(pwd->pw_gid, dom->id_min, dom->id_max)) {

            DEBUG(2, ("User [%s] filtered out! (id out of range)\n", name));
            ret = delete_user(tmpctx, sysdb, dom, name);
            if (ret) {
                goto done;
            }
            break;
        }

        ret = sysdb_store_user(tmpctx, sysdb, dom,
                               pwd->pw_name,
                               pwd->pw_passwd,
                               pwd->pw_uid,
                               pwd->pw_gid,
                               pwd->pw_gecos,
                               pwd->pw_dir,
                               pwd->pw_shell,
                               NULL, ctx->entry_cache_timeout);
        if (ret) {
            goto done;
        }
        break;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        goto done;

    default:
        ret = EIO;
        goto done;
    }

done:
    talloc_zfree(tmpctx);
    if (ret) {
        DEBUG(2, ("proxy -> getpwnam_r failed for '%s' <%d>\n",
                  name, status));
    }
    return ret;
}

static int delete_user(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                       struct sss_domain_info *domain, const char *name)
{
    struct ldb_dn *dn;

    DEBUG(7, ("User %s does not exist (or is invalid) on remote server,"
              " deleting!\n", name));

    dn = sysdb_user_dn(sysdb, mem_ctx, domain->name, name);
    if (!dn) {
        return ENOMEM;
    }

    return sysdb_delete_entry(sysdb, dn, true);
}

/* =Getpwuid-wrapper======================================================*/

static int get_pw_uid(TALLOC_CTX *mem_ctx,
                      struct proxy_ctx *ctx,
                      struct sysdb_ctx *sysdb,
                      struct sss_domain_info *dom,
                      uid_t uid)
{
    TALLOC_CTX *tmpctx;
    struct passwd *pwd;
    enum nss_status status;
    char *buffer;
    size_t buflen;
    bool del_user = false;
    int ret;

    DEBUG(7, ("Searching user by uid (%d)\n", uid));

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    pwd = talloc_zero(tmpctx, struct passwd);
    if (!pwd) {
        ret = ENOMEM;
        DEBUG(1, ("proxy -> getpwuid_r failed for '%d': [%d] %s\n",
                  uid, ret, strerror(ret)));
        return ret;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(tmpctx, buflen);
    if (!buffer) {
        ret = ENOMEM;
        DEBUG(1, ("proxy -> getpwuid_r failed for '%d': [%d] %s\n",
                  uid, ret, strerror(ret)));
        return ret;
    }

    status = ctx->ops.getpwuid_r(uid, pwd, buffer, buflen, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:

        DEBUG(7, ("User %d not found.\n", uid));
        del_user = true;
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("User %d found (%s, %d, %d)\n",
                  uid, pwd->pw_name, pwd->pw_uid, pwd->pw_gid));

        /* uid=0 or gid=0 are invalid values */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(pwd->pw_uid, dom->id_min, dom->id_max) ||
            OUT_OF_ID_RANGE(pwd->pw_gid, dom->id_min, dom->id_max)) {

            DEBUG(2, ("User [%s] filtered out! (id out of range)\n",
                      pwd->pw_name));
            del_user = true;
            break;
        }

        ret = sysdb_store_user(tmpctx, sysdb, dom,
                               pwd->pw_name,
                               pwd->pw_passwd,
                               pwd->pw_uid,
                               pwd->pw_gid,
                               pwd->pw_gecos,
                               pwd->pw_dir,
                               pwd->pw_shell,
                               NULL, ctx->entry_cache_timeout);
        if (ret) {
            goto done;
        }
        break;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        goto done;

    default:
        ret = EIO;
        goto done;
    }

    if (del_user) {
        DEBUG(7, ("User %d does not exist (or is invalid) on remote server,"
                  " deleting!\n", uid));

        ret = sysdb_delete_user(tmpctx, sysdb, dom, NULL, uid);
        if (ret) {
            goto done;
        }
    }

done:
    talloc_zfree(tmpctx);
    if (ret) {
        DEBUG(2, ("proxy -> getpwuid_r failed for '%d' <%d>\n", uid, status));
    }
    return ret;
}

/* =Getpwent-wrapper======================================================*/

static int enum_users(TALLOC_CTX *mem_ctx,
                      struct proxy_ctx *ctx,
                      struct sysdb_ctx *sysdb,
                      struct sss_domain_info *dom)
{
    TALLOC_CTX *tmpctx;
    bool in_transaction = false;
    struct passwd *pwd;
    enum nss_status status;
    size_t buflen;
    char *buffer;
    char *newbuf;
    int ret;

    DEBUG(7, ("Enumerating users\n"));

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    pwd = talloc_zero(tmpctx, struct passwd);
    if (!pwd) {
        ret = ENOMEM;
        goto done;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(tmpctx, buflen);
    if (!buffer) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret) {
        goto done;
    }
    in_transaction = true;

    status = ctx->ops.setpwent();
    if (status != NSS_STATUS_SUCCESS) {
        ret = EIO;
        goto done;
    }

again:
    /* always zero out the pwd structure */
    memset(pwd, 0, sizeof(struct passwd));

    /* get entry */
    status = ctx->ops.getpwent_r(pwd, buffer, buflen, &ret);

    switch (status) {
    case NSS_STATUS_TRYAGAIN:
        /* buffer too small ? */
        if (buflen < MAX_BUF_SIZE) {
            buflen *= 2;
        }
        if (buflen > MAX_BUF_SIZE) {
            buflen = MAX_BUF_SIZE;
        }
        newbuf = talloc_realloc_size(tmpctx, buffer, buflen);
        if (!newbuf) {
            ret = ENOMEM;
            goto done;
        }
        buffer = newbuf;
        goto again;

    case NSS_STATUS_NOTFOUND:

        /* we are done here */
        DEBUG(7, ("Enumeration completed.\n"));

        ret = sysdb_transaction_commit(sysdb);
        in_transaction = false;
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("User found (%s, %d, %d)\n",
                  pwd->pw_name, pwd->pw_uid, pwd->pw_gid));

        /* uid=0 or gid=0 are invalid values */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(pwd->pw_uid, dom->id_min, dom->id_max) ||
            OUT_OF_ID_RANGE(pwd->pw_gid, dom->id_min, dom->id_max)) {

            DEBUG(2, ("User [%s] filtered out! (id out of range)\n",
                      pwd->pw_name));

            goto again; /* skip */
        }

        ret = sysdb_store_user(tmpctx, sysdb, dom,
                               pwd->pw_name,
                               pwd->pw_passwd,
                               pwd->pw_uid,
                               pwd->pw_gid,
                               pwd->pw_gecos,
                               pwd->pw_dir,
                               pwd->pw_shell,
                               NULL, ctx->entry_cache_timeout);
        if (ret) {
            /* Do not fail completely on errors.
             * Just report the failure to save and go on */
            DEBUG(2, ("Failed to store user %s. Ignoring.\n",
                      pwd->pw_name));
        }
        goto again; /* next */

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        break;

    default:
        DEBUG(2, ("proxy -> getpwent_r failed (%d)[%s]\n",
                  ret, strerror(ret)));
        break;
    }

done:
    talloc_zfree(tmpctx);
    if (in_transaction) {
        sysdb_transaction_cancel(sysdb);
    }
    ctx->ops.endpwent();
    return ret;
}

/* =Getgrnam-wrapper======================================================*/

#define DEBUG_GR_MEM(level, grp) \
    do { \
        if (debug_level >= level) { \
            if (!grp->gr_mem || !grp->gr_mem[0]) { \
                DEBUG(level, ("Group %s has no members!\n", \
                              grp->gr_name)); \
            } else { \
                int i = 0; \
                while (grp->gr_mem[i]) { \
                    /* count */ \
                    i++; \
                } \
                DEBUG(level, ("Group %s has %d members!\n", \
                              grp->gr_name, i)); \
            } \
        } \
    } while(0)

static int get_gr_name(TALLOC_CTX *mem_ctx,
                       struct proxy_ctx *ctx,
                       struct sysdb_ctx *sysdb,
                       struct sss_domain_info *dom,
                       const char *name)
{
    TALLOC_CTX *tmpctx;
    struct group *grp;
    enum nss_status status;
    char *buffer;
    char *newbuf;
    size_t buflen;
    bool delete_group = false;
    struct sysdb_attrs *members;
    int ret;

    DEBUG(7, ("Searching group by name (%s)\n", name));

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    grp = talloc(tmpctx, struct group);
    if (!grp) {
        ret = ENOMEM;
        DEBUG(1, ("proxy -> getgrnam_r failed for '%s': [%d] %s\n",
                  name, ret, strerror(ret)));
        return ret;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(tmpctx, buflen);
    if (!buffer) {
        ret = ENOMEM;
        DEBUG(1, ("proxy -> getgrnam_r failed for '%s': [%d] %s\n",
                  name, ret, strerror(ret)));
        return ret;
    }

    /* FIXME: should we move this call outside the transaction to keep the
     * transaction as short as possible ? */
again:
    /* always zero out the grp structure */
    memset(grp, 0, sizeof(struct group));

    status = ctx->ops.getgrnam_r(name, grp, buffer, buflen, &ret);

    switch (status) {
    case NSS_STATUS_TRYAGAIN:
        /* buffer too small ? */
        if (buflen < MAX_BUF_SIZE) {
            buflen *= 2;
        }
        if (buflen > MAX_BUF_SIZE) {
            buflen = MAX_BUF_SIZE;
        }
        newbuf = talloc_realloc_size(tmpctx, buffer, buflen);
        if (!newbuf) {
            ret = ENOMEM;
            goto done;
        }
        buffer = newbuf;
        goto again;

    case NSS_STATUS_NOTFOUND:

        DEBUG(7, ("Group %s not found.\n", name));
        delete_group = true;
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("Group %s found: (%s, %d)\n",
                  name, grp->gr_name, grp->gr_gid));

        /* gid=0 is an invalid value */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(grp->gr_gid, dom->id_min, dom->id_max)) {

                DEBUG(2, ("Group [%s] filtered out! (id out of range)\n",
                          name));
            delete_group = true;
            break;
        }

        DEBUG_GR_MEM(7, grp);

        if (grp->gr_mem && grp->gr_mem[0]) {
            members = sysdb_new_attrs(tmpctx);
            if (!members) {
                ret = ENOMEM;
                goto done;
            }
            ret = sysdb_attrs_users_from_str_list(members, SYSDB_MEMBER,
                                                  dom->name,
                                                  (const char **)grp->gr_mem);
            if (ret) {
                goto done;
            }
        } else {
            members = NULL;
        }

        ret = sysdb_store_group(tmpctx, sysdb, dom,
                                grp->gr_name,
                                grp->gr_gid,
                                members,
                                ctx->entry_cache_timeout);
        if (ret) {
            goto done;
        }
        break;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        goto done;

    default:
        goto done;
    }

    if (delete_group) {
        struct ldb_dn *dn;

        DEBUG(7, ("Group %s does not exist (or is invalid) on remote server,"
                  " deleting!\n", name));

        dn = sysdb_group_dn(sysdb, tmpctx, dom->name, name);
        if (!dn) {
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_delete_entry(sysdb, dn, true);
        if (ret) {
            goto done;
        }
    }

done:
    talloc_zfree(tmpctx);
    if (ret) {
        DEBUG(2, ("proxy -> getgrnam_r failed for '%s' <%d>\n",
                  name, status));
    }
    return ret;
}

/* =Getgrgid-wrapper======================================================*/

static int get_gr_gid(TALLOC_CTX *mem_ctx,
                      struct proxy_ctx *ctx,
                      struct sysdb_ctx *sysdb,
                      struct sss_domain_info *dom,
                      gid_t gid)
{
    TALLOC_CTX *tmpctx;
    struct group *grp;
    enum nss_status status;
    char *buffer;
    char *newbuf;
    size_t buflen;
    bool delete_group = false;
    struct sysdb_attrs *members;
    int ret;

    DEBUG(7, ("Searching group by gid (%d)\n", gid));

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    grp = talloc(tmpctx, struct group);
    if (!grp) {
        ret = ENOMEM;
        DEBUG(1, ("proxy -> getgrgid_r failed for '%d': [%d] %s\n",
                  gid, ret, strerror(ret)));
        return ret;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(tmpctx, buflen);
    if (!buffer) {
        ret = ENOMEM;
        DEBUG(1, ("proxy -> getgrgid_r failed for '%d': [%d] %s\n",
                  gid, ret, strerror(ret)));
        return ret;
    }

again:
    /* always zero out the group structure */
    memset(grp, 0, sizeof(struct group));

    status = ctx->ops.getgrgid_r(gid, grp, buffer, buflen, &ret);

    switch (status) {
    case NSS_STATUS_TRYAGAIN:
        /* buffer too small ? */
        if (buflen < MAX_BUF_SIZE) {
            buflen *= 2;
        }
        if (buflen > MAX_BUF_SIZE) {
            buflen = MAX_BUF_SIZE;
        }
        newbuf = talloc_realloc_size(tmpctx, buffer, buflen);
        if (!newbuf) {
            ret = ENOMEM;
            goto done;
        }
        buffer = newbuf;
        goto again;

    case NSS_STATUS_NOTFOUND:

        DEBUG(7, ("Group %d not found.\n", gid));
        delete_group = true;
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("Group %d found (%s, %d)\n",
                  gid, grp->gr_name, grp->gr_gid));

        /* gid=0 is an invalid value */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(grp->gr_gid, dom->id_min, dom->id_max)) {

                DEBUG(2, ("Group [%s] filtered out! (id out of range)\n",
                          grp->gr_name));
            delete_group = true;
            break;
        }

        DEBUG_GR_MEM(7, grp);

        if (grp->gr_mem && grp->gr_mem[0]) {
            members = sysdb_new_attrs(tmpctx);
            if (!members) {
                ret = ENOMEM;
                goto done;
            }
            ret = sysdb_attrs_users_from_str_list(members, SYSDB_MEMBER,
                                                  dom->name,
                                                  (const char **)grp->gr_mem);
            if (ret) {
                goto done;
            }
        } else {
            members = NULL;
        }

        ret = sysdb_store_group(tmpctx, sysdb, dom,
                                grp->gr_name,
                                grp->gr_gid,
                                members,
                                ctx->entry_cache_timeout);
        if (ret) {
            goto done;
        }
        break;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        goto done;

    default:
        ret = EIO;
        goto done;
    }

    if (delete_group) {

        DEBUG(7, ("Group %d does not exist (or is invalid) on remote server,"
                  " deleting!\n", gid));

        ret = sysdb_delete_group(tmpctx, sysdb, dom, NULL, gid);
        if (ret) {
            goto done;
        }
    }

done:
    talloc_zfree(tmpctx);
    if (ret) {
        DEBUG(2, ("proxy -> getgrgid_r failed for '%d' <%d>\n",
                  gid, status));
    }
    return ret;
}

/* =Getgrent-wrapper======================================================*/

static int enum_groups(TALLOC_CTX *mem_ctx,
                       struct proxy_ctx *ctx,
                       struct sysdb_ctx *sysdb,
                       struct sss_domain_info *dom)
{
    TALLOC_CTX *tmpctx;
    bool in_transaction = false;
    struct group *grp;
    enum nss_status status;
    size_t buflen;
    char *buffer;
    struct sysdb_attrs *members;
    char *newbuf;
    int ret;

    DEBUG(7, ("Enumerating groups\n"));

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    grp = talloc(tmpctx, struct group);
    if (!grp) {
        ret = ENOMEM;
        goto done;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(tmpctx, buflen);
    if (!buffer) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret) {
        goto done;
    }
    in_transaction = true;

    status = ctx->ops.setgrent();
    if (status != NSS_STATUS_SUCCESS) {
        ret = EIO;
        goto done;
    }

again:
    /* always zero out the grp structure */
    memset(grp, 0, sizeof(struct group));

    /* get entry */
    status = ctx->ops.getgrent_r(grp, buffer, buflen, &ret);

    switch (status) {
    case NSS_STATUS_TRYAGAIN:
        /* buffer too small ? */
        if (buflen < MAX_BUF_SIZE) {
            buflen *= 2;
        }
        if (buflen > MAX_BUF_SIZE) {
            buflen = MAX_BUF_SIZE;
        }
        newbuf = talloc_realloc_size(tmpctx, buffer, buflen);
        if (!newbuf) {
            ret = ENOMEM;
            goto done;
        }
        buffer = newbuf;
        goto again;

    case NSS_STATUS_NOTFOUND:

        /* we are done here */
        DEBUG(7, ("Enumeration completed.\n"));

        ret = sysdb_transaction_commit(sysdb);
        in_transaction = false;
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("Group found (%s, %d)\n",
                  grp->gr_name, grp->gr_gid));

        /* gid=0 is an invalid value */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(grp->gr_gid, dom->id_min, dom->id_max)) {

                DEBUG(2, ("Group [%s] filtered out! (id out of range)\n",
                          grp->gr_name));

            goto again; /* skip */
        }

        DEBUG_GR_MEM(7, grp);

        if (grp->gr_mem && grp->gr_mem[0]) {
            members = sysdb_new_attrs(tmpctx);
            if (!members) {
                ret = ENOMEM;
                goto done;
            }
            ret = sysdb_attrs_users_from_str_list(members, SYSDB_MEMBER,
                                                  dom->name,
                                                  (const char **)grp->gr_mem);
            if (ret) {
                goto done;
            }
        } else {
            members = NULL;
        }

        ret = sysdb_store_group(tmpctx, sysdb, dom,
                                grp->gr_name,
                                grp->gr_gid,
                                members,
                                ctx->entry_cache_timeout);
        if (ret) {
            /* Do not fail completely on errors.
             * Just report the failure to save and go on */
            DEBUG(2, ("Failed to store group. Ignoring.\n"));
        }
        goto again; /* next */

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        break;

    default:
        DEBUG(2, ("proxy -> getgrent_r failed (%d)[%s]\n",
                  ret, strerror(ret)));
        break;
    }

done:
    talloc_zfree(tmpctx);
    if (in_transaction) {
        sysdb_transaction_cancel(sysdb);
    }
    ctx->ops.endgrent();
    return ret;
}


/* =Initgroups-wrapper====================================================*/

static int get_initgr_groups_process(TALLOC_CTX *memctx,
                                     struct proxy_ctx *ctx,
                                     struct sysdb_ctx *sysdb,
                                     struct sss_domain_info *dom,
                                     struct passwd *pwd);

static int get_initgr(TALLOC_CTX *mem_ctx,
                      struct proxy_ctx *ctx,
                      struct sysdb_ctx *sysdb,
                      struct sss_domain_info *dom,
                      const char *name)
{
    TALLOC_CTX *tmpctx;
    bool in_transaction = false;
    struct passwd *pwd;
    enum nss_status status;
    char *buffer;
    size_t buflen;
    int ret;

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    pwd = talloc_zero(tmpctx, struct passwd);
    if (!pwd) {
        ret = ENOMEM;
        goto done;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(tmpctx, buflen);
    if (!buffer) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret) {
        goto done;
    }
    in_transaction = true;

    /* FIXME: should we move this call outside the transaction to keep the
     * transaction as short as possible ? */
    status = ctx->ops.getpwnam_r(name, pwd, buffer, buflen, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:

        DEBUG(7, ("User %s not found.\n", name));
        ret = delete_user(tmpctx, sysdb, dom, name);
        if (ret) {
            goto done;
        }
        break;

    case NSS_STATUS_SUCCESS:

        /* uid=0 or gid=0 are invalid values */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(pwd->pw_uid, dom->id_min, dom->id_max) ||
            OUT_OF_ID_RANGE(pwd->pw_gid, dom->id_min, dom->id_max)) {

            DEBUG(2, ("User [%s] filtered out! (id out of range)\n",
                      name));
            ret = delete_user(tmpctx, sysdb, dom, name);
            break;
        }

        ret = sysdb_store_user(tmpctx, sysdb, dom,
                               pwd->pw_name,
                               pwd->pw_passwd,
                               pwd->pw_uid,
                               pwd->pw_gid,
                               pwd->pw_gecos,
                               pwd->pw_dir,
                               pwd->pw_shell,
                               NULL, ctx->entry_cache_timeout);
        if (ret) {
            goto done;
        }

        ret = get_initgr_groups_process(tmpctx, ctx, sysdb, dom, pwd);
        if (ret == EOK) {
            ret = sysdb_transaction_commit(sysdb);
            in_transaction = true;
        }
        break;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        break;

    default:
        DEBUG(2, ("proxy -> getpwnam_r failed for '%s' <%d>\n",
                  name, status));
        ret = EIO;
        break;
    }

done:
    talloc_zfree(tmpctx);
    if (in_transaction) {
        sysdb_transaction_cancel(sysdb);
    }
    return ret;
}

static int get_initgr_groups_process(TALLOC_CTX *memctx,
                                     struct proxy_ctx *ctx,
                                     struct sysdb_ctx *sysdb,
                                     struct sss_domain_info *dom,
                                     struct passwd *pwd)
{
    enum nss_status status;
    long int limit;
    long int size;
    long int num;
    long int num_gids;
    gid_t *gids;
    int ret;
    int i;

    num_gids = 0;
    limit = 4096;
    num = 4096;
    size = num*sizeof(gid_t);
    gids = talloc_size(memctx, size);
    if (!gids) {
        return ENOMEM;
    }

again:
    /* FIXME: should we move this call outside the transaction to keep the
     * transaction as short as possible ? */
    status = ctx->ops.initgroups_dyn(pwd->pw_name, pwd->pw_gid, &num_gids,
                                     &num, &gids, limit, &ret);
    switch (status) {
    case NSS_STATUS_TRYAGAIN:
        /* buffer too small ? */
        if (size < MAX_BUF_SIZE) {
            num *= 2;
            size = num*sizeof(gid_t);
        }
        if (size > MAX_BUF_SIZE) {
            size = MAX_BUF_SIZE;
            num = size/sizeof(gid_t);
        }
        limit = num;
        gids = talloc_realloc_size(memctx, gids, size);
        if (!gids) {
            return ENOMEM;
        }
        goto again; /* retry with more memory */

    case NSS_STATUS_SUCCESS:
        DEBUG(4, ("User [%s] appears to be member of %lu groups\n",
                  pwd->pw_name, num_gids));

        for (i = 0; i < num_gids; i++) {
            ret = get_gr_gid(memctx, ctx, sysdb, dom, gids[i]);
            if (ret) {
                return ret;
            }
        }
        break;

    default:
        DEBUG(2, ("proxy -> initgroups_dyn failed (%d)[%s]\n",
                  ret, strerror(ret)));
        ret = EIO;
        break;
    }

    return ret;
}

/* =Proxy_Id-Functions====================================================*/

static void proxy_get_account_info(struct be_req *breq)
{
    struct be_acct_req *ar;
    struct proxy_ctx *ctx;
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    uid_t uid;
    gid_t gid;
    int ret;

    ar = talloc_get_type(breq->req_data, struct be_acct_req);
    ctx = talloc_get_type(breq->be_ctx->bet_info[BET_ID].pvt_bet_data, struct proxy_ctx);
    ev = breq->be_ctx->ev;
    sysdb = breq->be_ctx->sysdb;
    domain = breq->be_ctx->domain;

    if (be_is_offline(breq->be_ctx)) {
        return proxy_reply(breq, DP_ERR_OFFLINE, EAGAIN, "Offline");
    }

    /* for now we support only core attrs */
    if (ar->attr_type != BE_ATTR_CORE) {
        return proxy_reply(breq, DP_ERR_FATAL, EINVAL, "Invalid attr type");
    }

    switch (ar->entry_type & 0xFFF) {
    case BE_REQ_USER: /* user */
        switch (ar->filter_type) {
        case BE_FILTER_NAME:
            if (strchr(ar->filter_value, '*')) {
                ret = enum_users(breq, ctx, sysdb, domain);
            } else {
                ret = get_pw_name(breq, ctx, sysdb, domain, ar->filter_value);
            }
            break;

        case BE_FILTER_IDNUM:
            if (strchr(ar->filter_value, '*')) {
                return proxy_reply(breq, DP_ERR_FATAL,
                                   EINVAL, "Invalid attr type");
            } else {
                char *endptr;
                errno = 0;
                uid = (uid_t)strtol(ar->filter_value, &endptr, 0);
                if (errno || *endptr || (ar->filter_value == endptr)) {
                    return proxy_reply(breq, DP_ERR_FATAL,
                                       EINVAL, "Invalid attr type");
                }
                ret = get_pw_uid(breq, ctx, sysdb, domain, uid);
            }
            break;
        default:
            return proxy_reply(breq, DP_ERR_FATAL,
                               EINVAL, "Invalid filter type");
        }
        break;

    case BE_REQ_GROUP: /* group */
        switch (ar->filter_type) {
        case BE_FILTER_NAME:
            if (strchr(ar->filter_value, '*')) {
                ret = enum_groups(breq, ctx, sysdb, domain);
            } else {
                ret = get_gr_name(breq, ctx, sysdb, domain, ar->filter_value);
            }
            break;
        case BE_FILTER_IDNUM:
            if (strchr(ar->filter_value, '*')) {
                return proxy_reply(breq, DP_ERR_FATAL,
                                   EINVAL, "Invalid attr type");
            } else {
                char *endptr;
                errno = 0;
                gid = (gid_t)strtol(ar->filter_value, &endptr, 0);
                if (errno || *endptr || (ar->filter_value == endptr)) {
                    return proxy_reply(breq, DP_ERR_FATAL,
                                       EINVAL, "Invalid attr type");
                }
                ret = get_gr_gid(breq, ctx, sysdb, domain, gid);
            }
            break;
        default:
            return proxy_reply(breq, DP_ERR_FATAL,
                               EINVAL, "Invalid filter type");
        }
        break;

    case BE_REQ_INITGROUPS: /* init groups for user */
        if (ar->filter_type != BE_FILTER_NAME) {
            return proxy_reply(breq, DP_ERR_FATAL,
                               EINVAL, "Invalid filter type");
        }
        if (strchr(ar->filter_value, '*')) {
            return proxy_reply(breq, DP_ERR_FATAL,
                               EINVAL, "Invalid filter value");
        }
        if (ctx->ops.initgroups_dyn == NULL) {
            return proxy_reply(breq, DP_ERR_FATAL,
                               ENODEV, "Initgroups call not supported");
        }
        ret = get_initgr(breq, ctx, sysdb, domain, ar->filter_value);
        break;

    default: /*fail*/
        return proxy_reply(breq, DP_ERR_FATAL,
                           EINVAL, "Invalid request type");
    }

    if (ret) {
        if (ret == ENXIO) {
            DEBUG(2, ("proxy returned UNAVAIL error, going offline!\n"));
            be_mark_offline(breq->be_ctx);
        }
        proxy_reply(breq, DP_ERR_FATAL, ret, NULL);
        return;
    }
    proxy_reply(breq, DP_ERR_OK, EOK, NULL);
}

static void proxy_shutdown(struct be_req *req)
{
    /* TODO: Clean up any internal data */
    req->fn(req, DP_ERR_OK, EOK, NULL);
}

static void proxy_auth_shutdown(struct be_req *req)
{
    talloc_free(req->be_ctx->bet_info[BET_AUTH].pvt_bet_data);
    req->fn(req, DP_ERR_OK, EOK, NULL);
}

struct bet_ops proxy_id_ops = {
    .handler = proxy_get_account_info,
    .finalize = proxy_shutdown
};

struct bet_ops proxy_auth_ops = {
    .handler = proxy_pam_handler,
    .finalize = proxy_auth_shutdown
};

struct bet_ops proxy_access_ops = {
    .handler = proxy_pam_handler,
    .finalize = proxy_auth_shutdown
};

struct bet_ops proxy_chpass_ops = {
    .handler = proxy_pam_handler,
    .finalize = proxy_auth_shutdown
};

static void *proxy_dlsym(void *handle, const char *functemp, char *libname)
{
    char *funcname;
    void *funcptr;

    funcname = talloc_asprintf(NULL, functemp, libname);
    if (funcname == NULL) return NULL;

    funcptr = dlsym(handle, funcname);
    talloc_free(funcname);

    return funcptr;
}

int sssm_proxy_id_init(struct be_ctx *bectx,
                       struct bet_ops **ops, void **pvt_data)
{
    struct proxy_ctx *ctx;
    char *libname;
    char *libpath;
    void *handle;
    int ret;

    ctx = talloc_zero(bectx, struct proxy_ctx);
    if (!ctx) {
        return ENOMEM;
    }
    ctx->be = bectx;

    ret = confdb_get_int(bectx->cdb, ctx, bectx->conf_path,
                         CONFDB_DOMAIN_ENTRY_CACHE_TIMEOUT, 600,
                         &ctx->entry_cache_timeout);
    if (ret != EOK) goto done;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                            CONFDB_PROXY_LIBNAME, NULL, &libname);
    if (ret != EOK) goto done;
    if (libname == NULL) {
        ret = ENOENT;
        goto done;
    }

    libpath = talloc_asprintf(ctx, "libnss_%s.so.2", libname);
    if (!libpath) {
        ret = ENOMEM;
        goto done;
    }

    handle = dlopen(libpath, RTLD_NOW);
    if (!handle) {
        DEBUG(0, ("Unable to load %s module with path, error: %s\n",
                  libpath, dlerror()));
        ret = ELIBACC;
        goto done;
    }

    ctx->ops.getpwnam_r = proxy_dlsym(handle, "_nss_%s_getpwnam_r", libname);
    if (!ctx->ops.getpwnam_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getpwuid_r = proxy_dlsym(handle, "_nss_%s_getpwuid_r", libname);
    if (!ctx->ops.getpwuid_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.setpwent = proxy_dlsym(handle, "_nss_%s_setpwent", libname);
    if (!ctx->ops.setpwent) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getpwent_r = proxy_dlsym(handle, "_nss_%s_getpwent_r", libname);
    if (!ctx->ops.getpwent_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.endpwent = proxy_dlsym(handle, "_nss_%s_endpwent", libname);
    if (!ctx->ops.endpwent) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getgrnam_r = proxy_dlsym(handle, "_nss_%s_getgrnam_r", libname);
    if (!ctx->ops.getgrnam_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getgrgid_r = proxy_dlsym(handle, "_nss_%s_getgrgid_r", libname);
    if (!ctx->ops.getgrgid_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.setgrent = proxy_dlsym(handle, "_nss_%s_setgrent", libname);
    if (!ctx->ops.setgrent) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getgrent_r = proxy_dlsym(handle, "_nss_%s_getgrent_r", libname);
    if (!ctx->ops.getgrent_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.endgrent = proxy_dlsym(handle, "_nss_%s_endgrent", libname);
    if (!ctx->ops.endgrent) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.initgroups_dyn = proxy_dlsym(handle, "_nss_%s_initgroups_dyn",
                                                  libname);
    if (!ctx->ops.initgroups_dyn) {
        DEBUG(1, ("The '%s' library does not provides the "
                  "_nss_XXX_initgroups_dyn function!\n"
                  "initgroups will be slow as it will require "
                  "full groups enumeration!\n", libname));
    }

    *ops = &proxy_id_ops;
    *pvt_data = ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

struct proxy_client {
    struct proxy_auth_ctx *proxy_auth_ctx;
    struct sbus_connection *conn;
    struct tevent_timer *timeout;
    bool initialized;
};

static void init_timeout(struct tevent_context *ev,
                         struct tevent_timer *te,
                         struct timeval t, void *ptr);
static int proxy_client_init(struct sbus_connection *conn, void *data)
{
    struct proxy_auth_ctx *proxy_auth_ctx;
    struct proxy_client *proxy_cli;
    struct timeval tv;

    proxy_auth_ctx = talloc_get_type(data, struct proxy_auth_ctx);

    /* hang off this memory to the connection so that when the connection
     * is freed we can potentially call a destructor */

    proxy_cli = talloc_zero(conn, struct proxy_client);
    if (!proxy_cli) {
        DEBUG(0,("Out of memory?!\n"));
        talloc_zfree(conn);
        return ENOMEM;
    }
    proxy_cli->proxy_auth_ctx = proxy_auth_ctx;
    proxy_cli->conn = conn;
    proxy_cli->initialized = false;

    /* 5 seconds should be plenty */
    tv = tevent_timeval_current_ofs(5, 0);

    proxy_cli->timeout = tevent_add_timer(proxy_auth_ctx->be->ev, proxy_cli,
                                          tv, init_timeout, proxy_cli);
    if (!proxy_cli->timeout) {
        DEBUG(0,("Out of memory?!\n"));
        talloc_zfree(conn);
        return ENOMEM;
    }
    DEBUG(4, ("Set-up proxy client ID timeout [%p]\n", proxy_cli->timeout));

    /* Attach the client context to the connection context, so that it is
     * always available when we need to manage the connection. */
    sbus_conn_set_private_data(conn, proxy_cli);

    return EOK;
}

static void init_timeout(struct tevent_context *ev,
                         struct tevent_timer *te,
                         struct timeval t, void *ptr)
{
    struct proxy_client *proxy_cli;

    DEBUG(2, ("Client timed out before Identification [%p]!\n", te));

    proxy_cli = talloc_get_type(ptr, struct proxy_client);

    sbus_disconnect(proxy_cli->conn);
    talloc_zfree(proxy_cli);

    /* If we time out here, we will also time out to
     * pc_init_timeout(), so we'll finish the request
     * there.
     */
}

static int client_registration(DBusMessage *message,
                               struct sbus_connection *conn)
{
    dbus_uint16_t version = DATA_PROVIDER_VERSION;
    struct proxy_client *proxy_cli;
    DBusMessage *reply;
    DBusError dbus_error;
    dbus_uint16_t cli_ver;
    uint32_t cli_id;
    dbus_bool_t dbret;
    void *data;
    int hret;
    hash_key_t key;
    hash_value_t value;
    struct tevent_req *req;
    struct proxy_child_ctx *child_ctx;
    struct pc_init_ctx *init_ctx;

    data = sbus_conn_get_private_data(conn);
    proxy_cli = talloc_get_type(data, struct proxy_client);
    if (!proxy_cli) {
        DEBUG(0, ("Connection holds no valid init data\n"));
        return EINVAL;
    }

    /* First thing, cancel the timeout */
    DEBUG(4, ("Cancel proxy client ID timeout [%p]\n", proxy_cli->timeout));
    talloc_zfree(proxy_cli->timeout);

    dbus_error_init(&dbus_error);

    dbret = dbus_message_get_args(message, &dbus_error,
                                  DBUS_TYPE_UINT16, &cli_ver,
                                  DBUS_TYPE_UINT32, &cli_id,
                                  DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(1, ("Failed to parse message, killing connection\n"));
        if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
        sbus_disconnect(conn);
        /* FIXME: should we just talloc_zfree(conn) ? */
        return EIO;
    }

    DEBUG(4, ("Proxy client [%ld] connected\n", cli_id));

    /* Check the hash table */
    key.type = HASH_KEY_ULONG;
    key.ul = cli_id;
    if (!hash_has_key(proxy_cli->proxy_auth_ctx->request_table, &key)) {
        DEBUG(1, ("Unknown child ID. Killing the connection\n"));
        sbus_disconnect(proxy_cli->conn);
        return EIO;
    }

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
        DEBUG(0, ("Failed to build dbus reply\n"));
        dbus_message_unref(reply);
        sbus_disconnect(conn);
        return EIO;
    }

    /* send reply back */
    sbus_conn_send_reply(conn, reply);
    dbus_message_unref(reply);

    hret = hash_lookup(proxy_cli->proxy_auth_ctx->request_table, &key, &value);
    if (hret != HASH_SUCCESS) {
        DEBUG(1, ("Hash error [%d][%s]\n", hret, hash_error_string(hret)));
        sbus_disconnect(conn);
    }

    /* Signal that the child is up and ready to receive the request */
    req = talloc_get_type(value.ptr, struct tevent_req);
    child_ctx = tevent_req_data(req, struct proxy_child_ctx);

    if (!child_ctx->running) {
        /* This should hopefully be impossible, but protect
         * against it anyway. If we're not marked running, then
         * the init_req will be NULL below and things will
         * break.
         */
        DEBUG(1, ("Client connection from a request "
                  "that's not marked as running\n"));
        return EIO;
    }

    init_ctx = tevent_req_data(child_ctx->init_req, struct pc_init_ctx);
    init_ctx->conn = conn;
    tevent_req_done(child_ctx->init_req);
    child_ctx->init_req = NULL;

    return EOK;
}

int sssm_proxy_auth_init(struct be_ctx *bectx,
                         struct bet_ops **ops, void **pvt_data)
{
    struct proxy_auth_ctx *ctx;
    int ret;
    int hret;
    char *sbus_address;

    /* If we're already set up, just return that */
    if(bectx->bet_info[BET_AUTH].mod_name &&
       strcmp("proxy", bectx->bet_info[BET_AUTH].mod_name) == 0) {
        DEBUG(8, ("Re-using proxy_auth_ctx for this provider\n"));
        *ops = bectx->bet_info[BET_AUTH].bet_ops;
        *pvt_data = bectx->bet_info[BET_AUTH].pvt_bet_data;
        return EOK;
    }

    ctx = talloc_zero(bectx, struct proxy_auth_ctx);
    if (!ctx) {
        return ENOMEM;
    }
    ctx->be = bectx;
    ctx->timeout_ms = SSS_CLI_SOCKET_TIMEOUT/4;
    ctx->next_id = 1;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                            CONFDB_PROXY_PAM_TARGET, NULL,
                            &ctx->pam_target);
    if (ret != EOK) goto done;
    if (!ctx->pam_target) {
        DEBUG(1, ("Missing option proxy_pam_target.\n"));
        ret = EINVAL;
        goto done;
    }

    sbus_address = talloc_asprintf(ctx, "unix:path=%s/%s_%s", PIPE_PATH,
                                   PROXY_CHILD_PIPE, bectx->domain->name);
    if (sbus_address == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    ret = sbus_new_server(ctx, bectx->ev, sbus_address, &proxy_interface,
                          &ctx->sbus_srv, proxy_client_init, ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not set up sbus server.\n"));
        goto done;
    }

    /* Set up request hash table */
    /* FIXME: get max_children from configuration file */
    ctx->max_children = 10;

    hret = hash_create(ctx->max_children * 2, &ctx->request_table,
                       NULL, NULL);
    if (hret != HASH_SUCCESS) {
        DEBUG(0, ("Could not initialize request table\n"));
        ret = EIO;
        goto done;
    }

    *ops = &proxy_auth_ops;
    *pvt_data = ctx;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

int sssm_proxy_access_init(struct be_ctx *bectx,
                           struct bet_ops **ops, void **pvt_data)
{
    int ret;
    ret = sssm_proxy_auth_init(bectx, ops, pvt_data);
    *ops = &proxy_access_ops;
    return ret;
}

int sssm_proxy_chpass_init(struct be_ctx *bectx,
                           struct bet_ops **ops, void **pvt_data)
{
    int ret;
    ret = sssm_proxy_auth_init(bectx, ops, pvt_data);
    *ops = &proxy_chpass_ops;
    return ret;
}