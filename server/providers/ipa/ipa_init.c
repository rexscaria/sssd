/*
    SSSD

    IPA Provider Initialization functions

    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include "providers/ipa/ipa_common.h"
#include "providers/krb5/krb5_auth.h"

struct ipa_options *ipa_options = NULL;

/* Id Handler */
struct bet_ops ipa_id_ops = {
    .handler = sdap_account_info_handler,
    .finalize = NULL
};

struct bet_ops ipa_auth_ops = {
    .handler = krb5_pam_handler,
    .finalize = NULL,
};

struct bet_ops ipa_chpass_ops = {
    .handler = krb5_pam_handler,
    .finalize = NULL,
};

int sssm_ipa_init(struct be_ctx *bectx,
                  struct bet_ops **ops,
                  void **pvt_data)
{
    struct sdap_id_ctx *ctx;
    int ret;

    if (!ipa_options) {
        ipa_get_options(bectx, bectx->cdb,
                        bectx->conf_path,
                        bectx->domain, &ipa_options);
    }
    if (!ipa_options) {
        return ENOMEM;
    }

    ctx = talloc_zero(bectx, struct sdap_id_ctx);
    if (!ctx) {
        return ENOMEM;
    }
    ctx->be = bectx;

    ret = ipa_get_id_options(ctx, bectx->cdb,
                             bectx->conf_path,
                             ipa_options, &ctx->opts);
    if (ret != EOK) {
        goto done;
    }

    ret = setup_tls_config(ctx->opts->basic);
    if (ret != EOK) {
        DEBUG(1, ("setup_tls_config failed [%d][%s].\n",
                  ret, strerror(ret)));
        goto done;
    }

    ret = sdap_id_setup_tasks(ctx);
    if (ret != EOK) {
        goto done;
    }

    *ops = &ipa_id_ops;
    *pvt_data = ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

int sssm_ipa_auth_init(struct be_ctx *bectx,
                       struct bet_ops **ops,
                       void **pvt_auth_data)
{
    struct krb5_ctx *ctx = NULL;
    struct tevent_signal *sige;
    struct stat stat_buf;
    char *value = NULL;
    int int_value;
    int ret;

    ctx = talloc_zero(bectx, struct krb5_ctx);
    if (!ctx) {
        DEBUG(1, ("talloc failed.\n"));
        return ENOMEM;
    }

    ctx->action = INIT_PW;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                            CONFDB_KRB5_KDCIP, NULL, &value);
    if (ret != EOK) {
        goto fail;
    }

    if (value == NULL) {
        DEBUG(2, ("Missing krb5KDCIP, authentication might fail.\n"));
    } else {
        ret = setenv(SSSD_KRB5_KDC, value, 1);
        if (ret != EOK) {
            DEBUG(2, ("setenv %s failed, authentication might fail.\n",
                      SSSD_KRB5_KDC));
        }
    }
    ctx->kdcip = value;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                            CONFDB_KRB5_REALM, NULL, &value);
    if (ret != EOK) {
        goto fail;
    }

    if (value == NULL) {
        DEBUG(4, ("Missing krb5REALM authentication might fail.\n"));
    } else {
        ret = setenv(SSSD_KRB5_REALM, value, 1);
        if (ret != EOK) {
            DEBUG(2, ("setenv %s failed, authentication might fail.\n",
                      SSSD_KRB5_REALM));
        }
    }
    ctx->realm = value;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                            CONFDB_KRB5_CCACHEDIR, "/tmp", &value);
    if (ret != EOK) {
        goto fail;
    }

    ret = lstat(value, &stat_buf);
    if (ret != EOK) {
        DEBUG(1, ("lstat for [%s] failed: [%d][%s].\n",
                  value, errno, strerror(errno)));
        goto fail;
    }
    if (!S_ISDIR(stat_buf.st_mode)) {
        DEBUG(1, ("Value of krb5ccache_dir [%s] is not a directory.\n",
                  value));
        goto fail;
    }
    ctx->ccache_dir = value;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                            CONFDB_KRB5_CCNAME_TMPL,
                            "FILE:%d/krb5cc_%U_XXXXXX",
                            &value);
    if (ret != EOK) {
        goto fail;
    }

    if (value[0] != '/' && strncmp(value, "FILE:", 5) != 0) {
        DEBUG(1, ("Currently only file based credential caches are supported "
                  "and krb5ccname_template must start with '/' or 'FILE:'\n"));
        goto fail;
    }
    ctx->ccname_template = value;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                            CONFDB_KRB5_CHANGEPW_PRINC,
                            "kadmin/changepw",
                            &value);
    if (ret != EOK) {
        goto fail;
    }

    if (strchr(value, '@') == NULL) {
        value = talloc_asprintf_append(value, "@%s", ctx->realm);
        if (value == NULL) {
            DEBUG(7, ("talloc_asprintf_append failed.\n"));
            goto fail;
        }
    }
    ctx->changepw_principle = value;

    ret = setenv(SSSD_KRB5_CHANGEPW_PRINCIPLE, ctx->changepw_principle, 1);
    if (ret != EOK) {
        DEBUG(2, ("setenv %s failed, password change might fail.\n",
                  SSSD_KRB5_CHANGEPW_PRINCIPLE));
    }

    ret = confdb_get_int(bectx->cdb, ctx, bectx->conf_path,
                         CONFDB_KRB5_AUTH_TIMEOUT, 15, &int_value);
    if (ret != EOK) {
        goto fail;
    }
    if (int_value <= 0) {
        DEBUG(4, ("krb5auth_timeout has to be a positive value.\n"));
        goto fail;
    }
    ctx->auth_timeout = int_value;

/* TODO: set options */

    sige = tevent_add_signal(bectx->ev, ctx, SIGCHLD, SA_SIGINFO,
                             krb5_child_sig_handler, NULL);
    if (sige == NULL) {
        DEBUG(1, ("tevent_add_signal failed.\n"));
        ret = ENOMEM;
        goto fail;
    }

    *ops = &ipa_auth_ops;
    *pvt_auth_data = ctx;
    return EOK;

fail:
    talloc_free(ctx);
    return ret;
}

int sssm_ipa_chpass_init(struct be_ctx *bectx,
                         struct bet_ops **ops,
                         void **pvt_auth_data)
{
    return sssm_ipa_auth_init(bectx, ops, pvt_auth_data);
}