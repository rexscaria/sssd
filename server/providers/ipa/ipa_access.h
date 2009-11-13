/*
    SSSD

    IPA Backend Module -- Access control

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#ifndef _IPA_ACCESS_H_
#define _IPA_ACCESS_H_

#include "providers/ldap/ldap_common.h"

enum ipa_access_mode {
    IPA_ACCESS_DENY = 0,
    IPA_ACCESS_ALLOW
};

struct ipa_access_ctx {
    struct sdap_id_ctx *sdap_ctx;
    struct dp_option *ipa_options;
    struct time_rules_ctx *tr_ctx;
};

struct hbac_ctx {
    struct sdap_id_ctx *sdap_ctx;
    struct dp_option *ipa_options;
    struct time_rules_ctx *tr_ctx;
    struct be_req *be_req;
    struct pam_data *pd;
    struct hbac_host_info **hbac_host_info;
    struct sysdb_attrs **hbac_rule_list;
    size_t hbac_rule_count;
    const char *user_dn;
    size_t groups_count;
    const char **groups;
};

void ipa_access_handler(struct be_req *be_req);

#endif /* _IPA_ACCESS_H_ */