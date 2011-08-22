 /*
   SSSD

   SUDO Responder - match_sudo_cmnd.c

   Copyright (C)  Arun Scaria <arunscaria91@gmail.com> (2011)

   Courtesy : The idea and the base logic for this module is derived from
   the sudo source writtern by Todd C. Miller <Todd.Miller@courtesan.com>.

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
#include<fnmatch.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <talloc.h>
#include <string.h>
#include <stdlib.h>

#include "match_sudo.h"

#define has_meta(s) (strpbrk((s), "\\?*[]") != NULL)


int command_args_match(char *sudoers_cmnd,
                       char *sudoers_args,
                       char *user_cmnd,
                       char *user_args) {
    int flags = 0;

    /*
     * If no args specified in sudoers, any user args are allowed.
     * If the empty string is specified in sudoers, no user args are allowed.
     */
    if (!sudoers_args ||
            (!user_args && sudoers_args && !strcmp("\"\"", sudoers_args)))
        return SUDO_MATCH_TRUE;
    /*
     * If args are specified in sudoers, they must match the user args.
     * If running as sudoedit, all args are assumed to be paths.
     */
    if (sudoers_args) {
        /* For sudoedit, all args are assumed to be pathnames. */
        if (strcmp(sudoers_cmnd, "sudoedit") == 0)
            flags = FNM_PATHNAME;
        if (fnmatch(sudoers_args, user_args ? user_args : "", flags) == 0)
            return SUDO_MATCH_TRUE;
    }
    return SUDO_MATCH_FALSE;
}

int command_matches_fnmatch(TALLOC_CTX * memctx,
                            char *sudoers_cmnd,
                            char *sudoers_args,
                            char *user_cmnd,
                            char *user_args,
                            char ** safe_cmnd,
                            char ** safe_args) {
    /*
     * Return true if fnmatch(3) succeeds AND
     *  a) there are no args in sudoers OR
     *  b) there are no args on command line and none required by sudoers OR
     *  c) there are args in sudoers and on command line and they match
     * else return false.
     */
    if (fnmatch(sudoers_cmnd, user_cmnd, FNM_PATHNAME) != 0)
        return SUDO_MATCH_FALSE;
    if (command_args_match(sudoers_cmnd, sudoers_args,user_cmnd,user_args)) {
        *safe_cmnd = talloc_strdup(memctx,user_cmnd);
        *safe_args = talloc_strdup(memctx,user_args);
        return SUDO_MATCH_TRUE;
    } else
        return SUDO_MATCH_FALSE;
}


int command_matches(TALLOC_CTX * memctx,
                    char *sudoers_cmnd,
                    char *sudoers_args,
                    char *user_cmnd,
                    char *user_args,
                    char ** safe_cmnd,
                    char ** safe_args)
{
    /* Check for pseudo-commands */
    if (sudoers_cmnd[0] != '/') {
        /*
         * Return true if both sudoers_cmnd and user_cmnd are "sudoedit" AND
         *  a) there are no args in sudoers OR
         *  b) there are no args on command line and none req by sudoers OR
         *  c) there are args in sudoers and on command line and they match
         */
        if (strcmp(sudoers_cmnd, "sudoedit") != 0 ||
                strcmp(user_cmnd, "sudoedit") != 0)
            return SUDO_MATCH_FALSE;
        if (command_args_match(sudoers_cmnd, sudoers_args,user_cmnd,user_args)){
            *safe_cmnd = talloc_strdup(memctx, sudoers_cmnd);
            *safe_args = talloc_strdup(memctx, sudoers_args);
            return SUDO_MATCH_TRUE;
        } else
            return SUDO_MATCH_FALSE;
    }

    // if (has_meta(sudoers_cmnd)) {
    /*
     * If sudoers_cmnd has meta characters in it, we need to
     * use glob(3) and/or fnmatch(3) to do the matching.
     */
    return command_matches_fnmatch(memctx,sudoers_cmnd, sudoers_args,user_cmnd,user_args,safe_cmnd, safe_args);
    // }
    //return command_matches_normal(sudoers_cmnd, sudoers_args,user_cmnd,user_args);
}



