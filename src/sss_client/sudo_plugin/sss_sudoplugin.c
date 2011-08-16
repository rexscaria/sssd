/*
    SSSD

    sss_sudo_plugin.c

    Authors:
        Arun Scaria <arunscaria91@gmail.com>

    Copyright (C) 2011 Arun Scaria <arunscaria91@gmail.com>.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    The coding of some of the components in this programe is based on the 
    code adapted from the sudo project at www.sudo.ws

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>


 */



/*
 * Define to the version of sudo package
 * This declaration is to be removed and
 * it is to be imported from config.h
 */
#define SUDO_PACKAGE_STRING "sudo 1.8.1"

#ifndef _PATH_VI
#define _PATH_VI "/bin/vi"
#endif

#include "config.h"
#include<unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdint.h>

#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */


#ifdef HAVE_STRING_H
# if defined(HAVE_MEMORY_H) && !defined(STDC_HEADERS)
#  include <memory.h>
# endif
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */


#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>

#include "missing.h"
#include <sudo_plugin.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <dbus/dbus.h>
#include "dhash.h"

#include "sss_sudo_cli.h"

#include "sbus/sssd_dbus_messages_helpers.h"


#ifdef __TANDEM
/* If it is a tandem system */
# define ROOT_UID       65535
#else
/* If it is a normal system */
# define ROOT_UID       0
#endif

#undef TRUE
#define TRUE 1
#undef FALSE
#define FALSE 0
#undef ERROR
#define ERROR -1

#undef  SSS_SUDO_PLUGIN_VERSION
#define SSS_SUDO_PLUGIN_VERSION "1.0.0"

#undef  SSS_SUDO_IO_PLUGIN_VERSION
#define SSS_SUDO_IO_PLUGIN_VERSION "1.0.0"


#undef  SSS_SUDO_PAM_SERVICE
#define SSS_SUDO_PAM_SERVICE "sudo"


#define CHECK_AND_RETURN_BOOL_STRING(obj)  ((obj)?"TRUE":"FALSE")

struct plugin_state {
    char * const *envp;
    char * const *settings;
    char * const *user_info;
} plugin_state;
static sudo_conv_t sudo_conv;
static sudo_printf_t sudo_log;
static uid_t runas_uid = ROOT_UID;
static gid_t runas_gid = -1;
static int use_sudoedit;
static int debug_level;

/*
 * user_info_struct strucure stores the user info. The lines and cols are 
 *  number of columns and lines user terminal supports. Most 
 * probably it can be avoided. But I'm keeping it till the final
 * code.
 */

struct user_info_struct
{
    char *username;
    int lines;
    int cols;
}user_information;


/* The sss_sudo_msg_contents have the message components to be
 * passed to SSSD responder.
 */

struct sss_sudo_msg_contents msg;

static struct pam_conv conv = {
                               misc_conv,
                               NULL
};


#define GET_BOOL_STRING(x) ((x)? strdup("TRUE") : strdup("FALSE"))

void print_sudo_items(void)
{

    D(("Sending data to sssd sudo responder."));
    D(("UserID: %d", msg.userid));
    D(("TTY: %s", CHECK_AND_RETURN_PI_STRING(msg.tty)));
    D(("CWD: %s", CHECK_AND_RETURN_PI_STRING(msg.cwd)));
    D(("Run as user: %s", CHECK_AND_RETURN_PI_STRING(msg.runas_user)));
    D(("Run as group: %s", CHECK_AND_RETURN_PI_STRING(msg.runas_group)));
    D(("Prompt: %s", CHECK_AND_RETURN_PI_STRING(msg.prompt)));
    D(("Network Address: %s",CHECK_AND_RETURN_PI_STRING(msg.network_addrs)));
    D(("Use sudo edit: %s",CHECK_AND_RETURN_BOOL_STRING(msg.use_sudoedit)));
    D(("Use set home: %s",CHECK_AND_RETURN_BOOL_STRING(msg.use_set_home)));
    D(("Use preserve environment: %s",CHECK_AND_RETURN_BOOL_STRING(msg.use_preserve_environment)));
    D(("Use implied shell: %s",CHECK_AND_RETURN_BOOL_STRING(msg.use_implied_shell)));
    D(("Use login shell: %s",CHECK_AND_RETURN_BOOL_STRING(msg.use_login_shell)));
    D(("Use run shell: %s",CHECK_AND_RETURN_BOOL_STRING(msg.use_run_shell))); 
    D(("Use preserve groups: %s",CHECK_AND_RETURN_BOOL_STRING(msg.use_preserve_groups)));
    D(("Use ignore ticket: %s",CHECK_AND_RETURN_BOOL_STRING(msg.use_ignore_ticket)));
    D(("Use non interactive mode: %s",CHECK_AND_RETURN_BOOL_STRING(msg.use_noninteractive)));
    D(("Use debug level: %s",CHECK_AND_RETURN_BOOL_STRING(msg.use_sudoedit)));
    D(("Command: %s", CHECK_AND_RETURN_PI_STRING(*msg.command)));
    /* add env var list */
    D(("Cli_PID: %d", msg.cli_pid));
}


/* initialise size of message contents as zero and boolean values as FALSE */
void init_size_of_msg_contents( void )
{
    msg.userid=-1;

    msg.use_sudoedit = FALSE;
    msg.use_set_home = FALSE;
    msg.use_preserve_environment = FALSE;
    msg.use_implied_shell = FALSE;
    msg.use_login_shell = FALSE;
    msg.use_run_shell = FALSE;
    msg.use_preserve_groups = FALSE;
    msg.use_ignore_ticket = FALSE;
    msg.use_noninteractive = FALSE;

    msg.debug_level=0;

    msg.command_count=0;

    msg.cli_pid = getpid();
}

/*
 * Plugin policy open function. This is called at opening the
 * plugin by sudo utility.
 * 
 */
int policy_open(unsigned int version,
                sudo_conv_t conversation,
                sudo_printf_t sudo_printf,
                char * const settings[],
                char * const user_info[],
                char * const user_env[])
{
    char * const *ui;
    struct passwd *pw;
    const char *runas_user = NULL;
    struct group *gr;
    const char *runas_group = NULL;


    if (sudo_conv == NULL) sudo_conv = conversation;
    if (sudo_log == NULL)  sudo_log = sudo_printf;

    /* Check the version of sudo plugin api */
    if (SUDO_API_VERSION_GET_MAJOR(version) != SUDO_API_VERSION_MAJOR) {
        sudo_log(SUDO_CONV_ERROR_MSG,
                 "The sss sudo plugin requires API version %d.x\n",
                 SUDO_API_VERSION_MAJOR);
        return ERROR;
    }

    init_size_of_msg_contents();


    for (ui = settings; *ui != NULL; ui++) {

        /* get the debug level */
        if (strncmp(*ui, "debug_level=", sizeof("debug_level=") - 1) == 0) {
            debug_level = atoi(*ui + sizeof("debug_level=") - 1);
            msg.debug_level = debug_level;
        }

        /*
         *check if the user specified the -E flag, indicating that
         *the user wishes to preserve the environment.
         *
         */

        else if (strncmp(*ui, "preserve_environment=", sizeof("preserve_environment=") - 1) == 0) {
            if (strcasecmp(*ui + sizeof("preserve_environment=") - 1, "true") == 0)
                msg.use_preserve_environment = TRUE;
        }

        /*
         * check if the user specified the -H flag. If true, set the
         * HOME environment variable to the target user's home directory.
         */

        else if (strncmp(*ui, "set_home=", sizeof("set_home=") - 1) == 0) {
            if (strcasecmp(*ui + sizeof("set_home=") - 1, "true") == 0)
                msg.use_set_home = TRUE;
        }

        /*
         * check if the user specified the -s flag, indicating that the
         * user wishes to run a shell.
         */

        else if (strncmp(*ui, "run_shell=", sizeof("run_shell=") - 1) == 0) {
            if (strcasecmp(*ui + sizeof("run_shell=") - 1, "true") == 0)
                msg.use_run_shell = TRUE;
        }

        /*
         * Check if the user specified the -i flag, indicating that the
         * user wishes to run a login shell.
         */

        else if (strncmp(*ui, "login_shell=", sizeof("login_shell=") - 1) == 0) {
            if (strcasecmp(*ui + sizeof("login_shell=") - 1, "true") == 0)
                msg.use_login_shell = TRUE;
        }

        /*
         * check to see whether user specified the -k flag along with a
         * command, indicating that the user wishes to ignore any cached
         * authentication credentials.
         */

        else if (strncmp(*ui, "ignore_ticket=", sizeof("ignore_ticket=") - 1) == 0) {
            if (strcasecmp(*ui + sizeof("ignore_ticket=") - 1, "true") == 0)
                msg.use_ignore_ticket = TRUE;
        }

        /*
         * The prompt to use when requesting a password, if specified
         * via the -p flag.
         */

        else if (strncmp(*ui, "prompt=", sizeof("prompt=") - 1) == 0) {
            msg.prompt = strdup(*ui + sizeof("prompt=") - 1);
        }

        /* Find the user to be run as */

        else if (strncmp(*ui, "runas_user=", sizeof("runas_user=") - 1) == 0) {
            msg.runas_user = strdup(*ui + sizeof("runas_user=") - 1);
            runas_user = msg.runas_user;
        }

        /* Find the group to be run as */

        else if (strncmp(*ui, "runas_group=", sizeof("runas_group=") - 1) == 0) {
            msg.runas_group = strdup(*ui + sizeof("runas_group=") - 1);
            runas_group = msg.runas_group;
        }

        /*
         * To get thhe command name that sudo was run as, typically
         * "sudo" or "sudoedit". setprogname() is only supported in BSD
         * No need to include it now.
         *
         * 	else if (strncmp(*ui, "progname=", sizeof("progname=") - 1) == 0) {
         * 		setprogname(*ui + sizeof("progname=") - 1);
         * 	}
         *
         */

        /* Check to see if sudo was called as sudoedit or with -e flag. */

        else if (strncmp(*ui, "sudoedit=", sizeof("sudoedit=") - 1) == 0) {
            if (strcasecmp(*ui + sizeof("sudoedit=") - 1, "true") == 0)
                use_sudoedit = TRUE;
            msg.use_sudoedit = use_sudoedit;
        }

        /* This plugin doesn't support running sudo with no arguments. */

        else if (strncmp(*ui, "implied_shell=", sizeof("implied_shell=") - 1) == 0) {
            if (strcasecmp(*ui + sizeof("implied_shell=") - 1, "true") == 0)
                return -2;
            /* usage error */
        }

        /*
         *check to see whether user specified the -P flag, indicating
         *that the user wishes to preserve the group vector instead of
         *setting it based on the runas user.
         */

        else if (strncmp(*ui, "preserve_groups=", sizeof("preserve_groups=") - 1) == 0) {
            if (strcasecmp(*ui + sizeof("preserve_groups=") - 1, "true") == 0)
                msg.use_preserve_groups = TRUE;
        }

        /*
         * check to see whether user specified the -n flag, indicating that
         * sudo should operate in non-interactive mode. The plugin may reject
         * a command run in non-interactive mode if user interaction is required.
         */

        else if (strncmp(*ui, "noninteractive=", sizeof("noninteractive=") - 1) == 0) {
            if (strcasecmp(*ui + sizeof("noninteractive=") - 1, "true") == 0)
                msg.use_noninteractive = TRUE;
        }

        /* to get network_addrs */

        else if (strncmp(*ui, "network_addrs=", sizeof("network_addrs=") - 1) == 0) {
            msg.network_addrs = strdup(*ui + sizeof("network_addrs=") - 1);
        }

        /* settings are over */
    }


    /* Build the user info */

    for (ui = user_info; *ui != NULL; ui++) {

        /* get user name */

        if (strncmp(*ui, "user=", sizeof("user=") - 1) == 0) {
            user_information.username = strdup(*ui + sizeof("user=") - 1);
        }

        /* get user id */
        else if (strncmp(*ui, "uid=", sizeof("uid=") - 1) == 0) {
            msg.userid = atoi(*ui + sizeof("uid=") - 1);
        }


        /* get cwd */
        else if (strncmp(*ui, "cwd=", sizeof("cwd=") - 1) == 0) {
            msg.cwd = strdup(*ui + sizeof("cwd=") - 1);
        }

        /* get tty */
        else if (strncmp(*ui, "tty=", sizeof("tty=") - 1) == 0) {
            msg.tty = strdup( *ui + sizeof("tty=") - 1);
        }

        /* get lines - to be removed at final code if no use */
        else if (strncmp(*ui, "lines=", sizeof("lines=") - 1) == 0) {
            user_information.lines = atoi(*ui + sizeof("lines=") - 1);
        }

        /* get cols  - to be removed at final code if no use */
        else if (strncmp(*ui, "cols=", sizeof("cols=") - 1) == 0) {
            user_information.cols = atoi(*ui + sizeof("cols=") - 1);
        }
    }



    if (runas_user != NULL) {
        if ((pw = getpwnam(runas_user)) == NULL) {
            sudo_log(SUDO_CONV_ERROR_MSG, "unknown user %s\n", runas_user);
            return 0;
        }
        runas_uid = pw->pw_uid;
    }
    if (runas_group != NULL) {
        if ((gr = getgrnam(runas_group)) == NULL) {
            sudo_log(SUDO_CONV_ERROR_MSG, "unknown group %s\n", runas_group);
            return 0;
        }
        runas_gid = gr->gr_gid;
    }

    /* fill Plugin state. */
    plugin_state.envp = user_env;
    msg.user_env = user_env;
    /* FIXME: Set a mechanism to handle environment */
    plugin_state.settings = settings;
    plugin_state.user_info = user_info;

    return 1;
}

/* Function to check if the command is available in the PATH */
char * find_in_path(char *command, char **envp)
{
    struct stat sb;
    char *path;
    char *path0;
    char **ep;
    char *cp = NULL;
    char pathbuf[PATH_MAX];
    char *qualified = NULL;

    if (strchr(command, '/') != NULL)
        return command;

    path = getenv("PATH");
    for (ep = plugin_state.envp; *ep != NULL; ep++) {
        if (strncmp(*ep, "PATH=", 5) == 0) {
            path = *ep + 5;
            break;
        }
    }
    path = strdup(path);
    path0 = path;

    do {
        if ((cp = strchr(path, ':')))
            *cp = '\0';

        snprintf(pathbuf, sizeof(pathbuf), "%s/%s", *path ? path : ".", command);

        if (stat(pathbuf, &sb) == 0) {
            if (S_ISREG(sb.st_mode) && (sb.st_mode & 0000111)) {
                qualified = pathbuf;
                break;
            }
        }
        path = cp + 1;
    } while (cp != NULL);

    free(path0);
    return ((qualified != NULL) ? strdup(qualified) : NULL);
}

/*
 * Information about the command being run in the form
 * of "name=value" strings. These values are used by
 * sudo to set the execution environment when running a
 * command. The plugin is responsible for creating and
 * populating the vector, which must be terminated with a  NULL pointer.
 *
 */
char ** build_command_info(char *command)
{
    static char **command_info;
    int i = 0;

    /* Setup command info. */
    command_info = calloc(32, sizeof(char *));

    if (command_info == NULL)
        return NULL;

    if (asprintf(&command_info[i++],"%s=%s","command", command) == -1 ||
            asprintf(&command_info[i++], "runas_euid=%ld", (long)runas_uid) == -1 ||
            asprintf(&command_info[i++], "runas_uid=%ld", (long)runas_uid) == -1) {
        return NULL;
    }

    if (runas_gid != -1) {
        if (asprintf(&command_info[i++], "runas_gid=%ld", (long)runas_gid) == -1 ||
                asprintf(&command_info[i++], "runas_egid=%ld", (long)runas_gid) == -1) {
            return NULL;
        }
    }

    if (use_sudoedit) {
        command_info[i] = strdup("sudoedit=true");
        if (command_info[i++] == NULL){
            return NULL;
        }
    }

#ifdef USE_TIMEOUT
    command_info[i++] = "timeout=30";
#endif

    return command_info;
}


/* finds a valid editor for sudo edit or "sudo vi" */
char * find_editor(int nfiles, char * const files[], char **argv_out[])
{
    char *cp;
    char **ep;
    char **nargv;
    char *editor;
    char *editor_path;
    int ac;
    int i;
    int nargc;
    int wasblank;

    /* Lookup EDITOR in user's environment. */
    editor = _PATH_VI;
    for (ep = plugin_state.envp; *ep != NULL; ep++) {
        if (strncmp(*ep, "EDITOR=", 7) == 0) {
            editor = *ep + 7;
            break;
        }
    }

    editor = strdup(editor);
    if (editor == NULL) {
        sudo_log(SUDO_CONV_ERROR_MSG, "unable to allocate memory\n");
        return NULL;
    }

    /*
     * Split editor into an argument vector; editor is reused (do not free).
     * The EDITOR environment variables may contain command
     * line args so look for those and alloc space for them too.
     */
    nargc = 1;
    for (wasblank = 0, cp = editor; *cp != '\0'; cp++) {

        if (isblank((unsigned char) *cp)) {
            wasblank = 1;
        }
        else if (wasblank) {
            wasblank = 0;
            nargc++;
        }
    }

    /* If we can't find the editor in the user's PATH, give up. */
    cp = strtok(editor, " \t");
    if (cp == NULL ||
            (editor_path = find_in_path(editor, plugin_state.envp)) == NULL) {
        return NULL;
    }

    nargv = (char **) malloc((nargc + 1 + nfiles + 1) * sizeof(char *));
    if (nargv == NULL) {
        sudo_log(SUDO_CONV_ERROR_MSG, "unable to allocate memory\n");
        return NULL;
    }

    for (ac = 0; cp != NULL && ac < nargc; ac++) {
        nargv[ac] = cp;
        cp = strtok(NULL, " \t");
    }
    nargv[ac++] = "--";
    for (i = 0; i < nfiles; )
        nargv[ac++] = files[i++];
    nargv[ac] = NULL;

    *argv_out = nargv;
    return editor_path;
}


void delete_callback(hash_entry_t *entry, hash_destroy_enum type, void *pvt)
{
    if (entry->value.type == HASH_VALUE_PTR)
        free(entry->value.ptr);
}


int create_env_hash_table(char ** env, hash_table_t ** table_out) {

    hash_table_t *local_table = NULL;
    hash_key_t   key;
    hash_value_t value;

    char * tmp;
    char **ui;

    int err_h;

    err_h =  hash_create((unsigned long)INIT_ENV_TABLE_SIZE,
                         &local_table,
                         delete_callback,
                         NULL);
    if (err_h != HASH_SUCCESS) {
        fprintf(stderr, "couldn't create hash table (%s)\n", hash_error_string(err_h));
        return err_h;
    }

    for(ui = (char **) msg.user_env; *ui!=NULL; ui++) {
        tmp = strchr(*ui,'=');
        *tmp = '\0';
        key.type = HASH_KEY_STRING;
        key.str = strdup(*ui);
        value.type = HASH_VALUE_PTR;
        value.ptr = tmp+1;

        if ((err_h = hash_enter(local_table, &key, &value)) != HASH_SUCCESS) {
            fprintf(stderr, "couldn't add to table \"%s\" (%s)\n", key.str, hash_error_string(err_h));
            return err_h;
        }
        *tmp = '=' ;
    }

    *table_out = local_table;

    return HASH_SUCCESS;
}

int create_settings_hash_table(hash_table_t ** table_out) {

    hash_table_t *local_table = NULL;
    hash_key_t   key;
    hash_value_t value;

    const char * truth = strdup("TRUE");
    const char * fallacy = strdup("FALSE");

    int err_h;

    err_h =  hash_create((unsigned long)INIT_SETTINGS_TABLE_SIZE,
                         &local_table,
                         delete_callback,
                         NULL);
    if (err_h != HASH_SUCCESS) {
        fprintf(stderr, "couldn't create hash table (%s)\n", hash_error_string(err_h));
        return err_h;
    }
    key.type = HASH_KEY_STRING;
    value.type = HASH_VALUE_PTR;
    if(msg.runas_user && *msg.runas_user ){
        key.str = strdup(SSS_SUDO_ITEM_RUSER);
        value.ptr = msg.runas_user;
        if ((err_h = hash_enter(local_table, &key, &value)) != HASH_SUCCESS) {
            fprintf(stderr, "cannot add to table \"%s\" (%s)\n", key.str, hash_error_string(err_h));
            return err_h;
        }
        free(key.str);
    }

    if(msg.runas_group && *msg.runas_group ){
        key.str = strdup(SSS_SUDO_ITEM_RGROUP);
        value.ptr = msg.runas_group;
        if ((err_h = hash_enter(local_table, &key, &value)) != HASH_SUCCESS) {
            fprintf(stderr, "cannot add to table \"%s\" (%s)\n", key.str, hash_error_string(err_h));
            return err_h;
        }
        free(key.str);
    }

    if(msg.prompt && *msg.prompt ){
        key.str = strdup(SSS_SUDO_ITEM_PROMPT);
        value.ptr = msg.prompt;
        if ((err_h = hash_enter(local_table, &key, &value)) != HASH_SUCCESS) {
            fprintf(stderr, "cannot add to table \"%s\" (%s)\n", key.str, hash_error_string(err_h));
            return err_h;
        }
        free(key.str);
    }

    if(msg.network_addrs && *msg.network_addrs ){
        key.str = strdup(SSS_SUDO_ITEM_NETADDR);
        value.ptr = msg.network_addrs;
        if ((err_h = hash_enter(local_table, &key, &value)) != HASH_SUCCESS) {
            fprintf(stderr, "cannot add to table \"%s\" (%s)\n", key.str, hash_error_string(err_h));
            return err_h;
        }
        free(key.str);
    }

    key.str = strdup(SSS_SUDO_ITEM_USE_SUDOEDIT);
    value.ptr = GET_BOOL_STRING(msg.use_sudoedit);
    if ((err_h = hash_enter(local_table, &key, &value)) != HASH_SUCCESS) {
        fprintf(stderr, "cannot add to table \"%s\" (%s)\n", key.str, hash_error_string(err_h));
        return err_h;
    }
    free(key.str);

    key.str = strdup(SSS_SUDO_ITEM_USE_SETHOME);
    value.ptr = GET_BOOL_STRING(msg.use_set_home);
    if ((err_h = hash_enter(local_table, &key, &value)) != HASH_SUCCESS) {
        fprintf(stderr, "cannot add to table \"%s\" (%s)\n", key.str, hash_error_string(err_h));
        return err_h;
    }
    free(key.str);

    key.str = strdup(SSS_SUDO_ITEM_USE_PRESERV_ENV);
    value.ptr = GET_BOOL_STRING(msg.use_preserve_environment);
    if ((err_h = hash_enter(local_table, &key, &value)) != HASH_SUCCESS) {
        fprintf(stderr, "cannot add to table \"%s\" (%s)\n", key.str, hash_error_string(err_h));
        return err_h;
    }
    free(key.str);

    key.str = strdup(SSS_SUDO_ITEM_USE_IMPLIED_SHELL);
    value.ptr  = GET_BOOL_STRING(msg.use_implied_shell);
    if ((err_h = hash_enter(local_table, &key, &value)) != HASH_SUCCESS) {
        fprintf(stderr, "cannot add to table \"%s\" (%s)\n", key.str, hash_error_string(err_h));
        return err_h;
    }
    free(key.str);


    key.str = strdup(SSS_SUDO_ITEM_USE_LOGIN_SHELL);
    value.ptr = GET_BOOL_STRING(msg.use_login_shell);
    if ((err_h = hash_enter(local_table, &key, &value)) != HASH_SUCCESS) {
        fprintf(stderr, "cannot add to table \"%s\" (%s)\n", key.str, hash_error_string(err_h));
        return err_h;
    }
    free(key.str);


    key.str = strdup(SSS_SUDO_ITEM_USE_RUN_SHELL);
    value.ptr = GET_BOOL_STRING(msg.use_run_shell);
    if ((err_h = hash_enter(local_table, &key, &value)) != HASH_SUCCESS) {
        fprintf(stderr, "cannot add to table \"%s\" (%s)\n", key.str, hash_error_string(err_h));
        return err_h;
    }
    free(key.str);


    key.str = strdup(SSS_SUDO_ITEM_USE_PRE_GROUPS);
    value.i = GET_BOOL_STRING(msg.use_preserve_groups);
    if ((err_h = hash_enter(local_table, &key, &value)) != HASH_SUCCESS) {
        fprintf(stderr, "cannot add to table \"%s\" (%s)\n", key.str, hash_error_string(err_h));
        return err_h;
    }
    free(key.str);


    key.str = strdup(SSS_SUDO_ITEM_USE_IGNORE_TICKET);
    value.ptr = GET_BOOL_STRING(msg.use_ignore_ticket);
    if ((err_h = hash_enter(local_table, &key, &value)) != HASH_SUCCESS) {
        fprintf(stderr, "cannot add to table \"%s\" (%s)\n", key.str, hash_error_string(err_h));
        return err_h;
    }
    free(key.str);


    key.str = strdup(SSS_SUDO_ITEM_USE_NON_INTERACTIVE);
    value.ptr =GET_BOOL_STRING(msg.use_noninteractive);
    if ((err_h = hash_enter(local_table, &key, &value)) != HASH_SUCCESS) {
        fprintf(stderr, "cannot add to table \"%s\" (%s)\n", key.str, hash_error_string(err_h));
        return err_h;
    }
    free(key.str);

    key.str = strdup(SSS_SUDO_ITEM_DEBUG_LEVEL);
    value.ptr = GET_BOOL_STRING(msg.debug_level);
    if ((err_h = hash_enter(local_table, &key, &value)) != HASH_SUCCESS) {
        fprintf(stderr, "cannot add to table \"%s\" (%s)\n", key.str, hash_error_string(err_h));
        return err_h;
    }
    free(key.str);

    key.str = strdup(SSS_SUDO_ITEM_CLI_PID);
    asprintf(&value.ptr,"%u",msg.cli_pid);
    if ((err_h = hash_enter(local_table, &key, &value)) != HASH_SUCCESS) {
        fprintf(stderr, "cannot add to table \"%s\" (%s)\n", key.str, hash_error_string(err_h));
        return err_h;
    }
    free(key.str);


    *table_out = local_table;

    return HASH_SUCCESS;
}




int validate_message_content( void )
{
    if(!msg.cwd && !*msg.cwd) {
        fprintf(stderr,"fatal: Current working directory is invalid.");
        return SSS_SUDO_VALIDATION_ERR;
    }
    if(!msg.tty && !*msg.tty) {
        fprintf(stderr,"fatal: Client terminal is invalid.");
        return SSS_SUDO_VALIDATION_ERR;
    }
    if(!msg.user_env && !*msg.user_env) {
        fprintf(stderr,"fatal: User environment is invalid.");
        return SSS_SUDO_VALIDATION_ERR;
    }
    if(!msg.command && !*msg.command) {
        fprintf(stderr,"fatal: Command to be executed is invalid.");
        return SSS_SUDO_VALIDATION_ERR;
    }

    return SSS_SUDO_VALIDATION_SUCCESS;
}

void free_connection(DBusConnection  *conn,
                     DBusError       *err,
                     hash_table_t   *settings_table,
                     DBusMessage *msg,
                     DBusMessage *reply ){

    if(msg != NULL)
        dbus_message_unref(msg);

    if(reply != NULL)
        dbus_message_unref(reply);

    if (err != NULL && dbus_error_is_set(err))
        dbus_error_free(err);

    if(settings_table != NULL)
        hash_destroy(settings_table);

    if(conn != NULL)
        dbus_connection_close(conn);

}


int sss_sudo_make_request(struct sss_cli_req_data *rd,
                          uint8_t **repbuf,
                          size_t *replen,
                          int *errnop)
{


    char ** command_array,**ui;
    char * result_str;
    int err_status,count;
    dbus_uint32_t status,command_array_out_size;

    DBusConnection* conn;
    DBusError err;

    DBusMessage* dbus_msg;
    DBusMessage* dbus_reply;
    DBusMessageIter msg_iter;
    DBusMessageIter sub_iter;

    dbus_bool_t ret=FALSE;

    hash_table_t *env_table = NULL;
    hash_table_t *settings_table = NULL;
    hash_table_t *env_table_out = NULL;

    fprintf(stdout,"Calling remote method to pack message\n");

    if(validate_message_content() !=  SSS_SUDO_VALIDATION_SUCCESS) {
        return SSS_SUDO_VALIDATION_ERR;
    }


    err_status = create_env_hash_table(msg.user_env,&env_table);
    if(err_status != HASH_SUCCESS) {
        fprintf(stderr, "ccouldn't create table: %s\n", hash_error_string(err_status));
        return SSS_SUDO_MESSAGE_ERR;
    }


    err_status = create_settings_hash_table(&settings_table);
    if(err_status != HASH_SUCCESS) {
        fprintf(stderr, "ccouldn't create table: %s\n", hash_error_string(err_status));
        return SSS_SUDO_MESSAGE_ERR;
    }

    /* initialise the errors */
    dbus_error_init(&err);

    /* connect to the system bus and check for errors */
    conn = dbus_connection_open_private(SSS_SUDO_SERVICE_PIPE, &err);

    if (dbus_error_is_set(&err)) {
        fprintf(stderr, "Connection Error (%s)\n", err.message);
        dbus_error_free(&err);
        return SSS_SUDO_CONNECTION_ERR;
    }
    if (NULL == conn) {
        return SSS_SUDO_CONNECTION_ERR;
    }


    /* create a new method call and check for errors */
    dbus_msg = dbus_message_new_method_call( NULL, 		        /*    target    */
                                             SUDO_SERVER_PATH,        /*    object    */
                                             SUDO_SERVER_INTERFACE,  /*   interface  */
                                             SUDO_METHOD_QUERY);    /*  method name */
    if (NULL == dbus_msg) {
        fprintf(stderr, "Message Null\n");
        free_connection(conn,&err,settings_table,(DBusMessage *)NULL,(DBusMessage *)NULL);
        return SSS_SUDO_MESSAGE_ERR;
    }

    /* append arguments */


    dbus_message_iter_init_append(dbus_msg, &msg_iter);
    if(dbus_error_is_set(&err)){
        fprintf(stderr, "Failed to initialize the iterator.\n");
        free_connection(conn,&err,settings_table,dbus_msg,(DBusMessage *)NULL);
        return SSS_SUDO_MESSAGE_ERR;
    }


    if(!dbus_message_iter_open_container(&msg_iter,
                                         DBUS_TYPE_STRUCT,
                                         NULL,
                                         &sub_iter)) {
        fprintf(stderr, "Out Of Memory!\n");
        free_connection(conn,&err,settings_table,dbus_msg,(DBusMessage *)NULL);
        return SSS_SUDO_MESSAGE_ERR;
    }
    if (!dbus_message_iter_append_basic(&sub_iter,
                                        DBUS_TYPE_UINT32,
                                        &msg.userid)) {
        fprintf(stderr, "Out Of Memory!\n");
        free_connection(conn,&err,settings_table,dbus_msg,(DBusMessage *)NULL);
        return SSS_SUDO_MESSAGE_ERR;
    }

    if (!dbus_message_iter_append_basic(&sub_iter,
                                        DBUS_TYPE_STRING,
                                        &msg.cwd)) {
        fprintf(stderr, "Out Of Memory!\n");
        free_connection(conn,&err,settings_table,dbus_msg,(DBusMessage *)NULL);
        return SSS_SUDO_MESSAGE_ERR;
    }



    if (!dbus_message_iter_append_basic(&sub_iter,
                                        DBUS_TYPE_STRING,
                                        &msg.tty)) {
        fprintf(stderr, "Out Of Memory!\n");
        free_connection(conn,&err,settings_table,dbus_msg,(DBusMessage *)NULL);
        return SSS_SUDO_MESSAGE_ERR;
    }
    if (!dbus_message_iter_append_basic(&sub_iter,
                                        DBUS_TYPE_STRING,
                                        &msg.fq_command)) {
        fprintf(stderr, "Out Of Memory! - at FQ command\n");
        free_connection(conn,&err,settings_table,dbus_msg,(DBusMessage *)NULL);
        return SSS_SUDO_MESSAGE_ERR;
    }

    if (!dbus_message_iter_close_container(&msg_iter,&sub_iter)) {
        fprintf(stderr, "Out Of Memory!\n");
        free_connection(conn,&err,settings_table,dbus_msg,(DBusMessage *)NULL);
        return SSS_SUDO_MESSAGE_ERR;
    }

    if (!dbus_message_iter_append_basic(&msg_iter,
                                        DBUS_TYPE_UINT32,
                                        &msg.command_count)) {
        fprintf(stderr, "Out Of Memory!\n");
        free_connection(conn,&err,settings_table,dbus_msg,(DBusMessage *)NULL);
        return SSS_SUDO_MESSAGE_ERR;
    }

    if(!dbus_message_iter_open_container(&msg_iter,
                                         DBUS_TYPE_ARRAY,
                                         "s",
                                         &sub_iter)) {
        fprintf(stderr, "Out Of Memory!\n");
        free_connection(conn,&err,settings_table,dbus_msg,(DBusMessage *)NULL);
        return SSS_SUDO_MESSAGE_ERR;
    }

    for(command_array = msg.command ; *command_array != NULL ; command_array++) {

        if (!dbus_message_iter_append_basic(&sub_iter,
                                            DBUS_TYPE_STRING,
                                            command_array)) {
            fprintf(stderr, "Out Of Memory!\n");
            free_connection(conn,&err,settings_table,dbus_msg,(DBusMessage *)NULL);
            return SSS_SUDO_MESSAGE_ERR;
        }

    }

    if (!dbus_message_iter_close_container(&msg_iter,&sub_iter)) {
        fprintf(stderr, "Out Of Memory!\n");
        free_connection(conn,&err,settings_table,dbus_msg,(DBusMessage *)NULL);
        return SSS_SUDO_MESSAGE_ERR;
    }
    ////////

    if(dbus_dhash_to_msg_iter(&settings_table,&msg_iter) != SSS_SBUS_CONV_SUCCESS){
        fprintf(stderr,"fatal: message framing failed.");
        free_connection(conn,&err,settings_table,dbus_msg,(DBusMessage *)NULL);
        return SSS_SUDO_MESSAGE_ERR;
    }

    if(dbus_dhash_to_msg_iter(&env_table,&msg_iter) != SSS_SBUS_CONV_SUCCESS){
        fprintf(stderr,"fatal: message framing failed.");
        free_connection(conn,&err,settings_table,dbus_msg,(DBusMessage *)NULL);
        return SSS_SUDO_MESSAGE_ERR;
    }

    hash_destroy(settings_table);

    /* send message and get a handle for a reply */
    dbus_reply = dbus_connection_send_with_reply_and_block (conn,dbus_msg,
                                                            -1,
                                                            &err);
    fprintf(stdout,"Request Sent\n");
    if (dbus_error_is_set(&err)) {
        fprintf(stderr, "Connection send-reply Error (%s)\n", err.message);
        free_connection(conn,&err,(hash_table_t *)NULL,dbus_msg,(DBusMessage *)NULL);
        return SSS_SUDO_REPLY_ERR;
    }
    if (NULL == dbus_reply) {
        fprintf(stderr, "reply failed\n");
        free_connection(conn,&err,(hash_table_t *)NULL,dbus_msg,(DBusMessage *)NULL);
        return SSS_SUDO_REPLY_ERR;
    }

    ret = dbus_message_get_args(dbus_reply,
                                &err,
                                DBUS_TYPE_UINT32,&status,
                                DBUS_TYPE_STRING,&result_str,
                                DBUS_TYPE_ARRAY,DBUS_TYPE_STRING,&command_array,
                                &command_array_out_size,
                                DBUS_TYPE_INVALID);
    if (!ret) {
        fprintf (stderr,"Failed to parse reply, killing connection\n");
        free_connection(conn,&err,(hash_table_t *)NULL,dbus_msg,dbus_reply);
        return SSS_SUDO_REPLY_ERR;
    }

    fprintf(stdout,"----------Reply--------:\n"
            "Header : %d \nResult status : %s\n"
            "Command : ", status,result_str);

    for(count =0;count< command_array_out_size;count++){
        printf("%s ", command_array[count]);
    }
    if (!dbus_message_iter_init(dbus_reply, &msg_iter)) {
        fprintf(stderr, "Reply iterator failed!\n");
        free_connection(conn,&err,(hash_table_t *)NULL,dbus_msg,dbus_reply);
        return SSS_SUDO_REPLY_ERR;
    }

    printf("\n");
    dbus_message_iter_next(&msg_iter);
    dbus_message_iter_next(&msg_iter);
    dbus_message_iter_next(&msg_iter);

    if(dbus_msg_iter_to_dhash(&msg_iter, &env_table_out) != SSS_SBUS_CONV_SUCCESS){
        fprintf(stderr, "env message iterator corrupted!\n");
        free_connection(conn,&err,(hash_table_t *)NULL,dbus_msg,dbus_reply);
        return SSS_SUDO_REPLY_ERR;
    }
    printf("---------Reply End----------\n");

    /* free connection now */
    free_connection(conn,&err,(hash_table_t *)NULL,dbus_msg,dbus_reply);


    if(strncmp(result_str,"PASS",4)==0)
        return SSS_STATUS_SUCCESS;
    else
        return SSS_STATUS_FAILED;

}

void free_all( void )
{
    free(msg.cwd);
    free(msg.tty);
    free(msg.prompt);
    free(msg.runas_user);
    free(msg.runas_group);
    //free(msg.network_addrs);
    free(user_information.username);

}


int send_and_receive()
{
    int ret;
    int errnop;
    struct sss_cli_req_data rd;
    uint8_t *buf = NULL;
    uint8_t *repbuf = NULL;
    size_t replen;
    int _status = SSS_SUDO_SYSTEM_ERR;

    print_sudo_items();

    errnop = 0;
    ret = sss_sudo_make_request( &rd, &repbuf, &replen, &errnop);

    if (ret != SSS_SUDO_SUCCESS) {
        if (errnop != 0) {
            fprintf( stderr, "Request to sssd failed. %d", errnop);
        }
        _status = SSS_SUDO_SYSTEM_ERR;
        goto done;
    }

    /* check the reply signature */
    if (replen < (2*sizeof(int32_t))) {
        //D(("response not in expected format."));
        _status = SSS_SUDO_SYSTEM_ERR;
        goto done;
    }



    done:
    _status = SSS_SUDO_SUCCESS;

    if (_status == SSS_SUDO_SUCCESS)
        return _status;
    else
        return SSS_SUDO_FAILED;
}



/*
 * Plugin policy check function.
 * The check_policy function is called by sudo to determine
 * whether the user is allowed to run the specified commands.
 */
int  policy_check(int argc, char * const argv[],
                  char *env_add[], char **command_info_out[],
                  char **argv_out[], char **user_env_out[])
{
    char *command;
    pam_handle_t *pamh;
    char *pam_user;
    char *pam_action;
    int pam_ret;

    if (!argc || argv[0] == NULL) {
        sudo_log(SUDO_CONV_ERROR_MSG, "no command specified\n");
        return FALSE;
    }


    command = find_in_path(argv[0], plugin_state.envp);
    if (command == NULL) {
        sudo_log(SUDO_CONV_ERROR_MSG, "%s: command not found\n", argv[0]);
        return FALSE;
    }

    /* If "sudo vi" is run, auto-convert to sudoedit.  */
    if (strcmp(command, _PATH_VI) == 0)
        use_sudoedit = TRUE;

    if (use_sudoedit) {
        /* Rebuild argv using editor */
        command = find_editor(argc - 1, argv + 1, argv_out);
        if (command == NULL) {
            sudo_log(SUDO_CONV_ERROR_MSG, "unable to find valid editor\n");
            return ERROR;
        }
        use_sudoedit = TRUE;
    } else {
        /* No changes needd to argv */
        *argv_out = (char **)argv;
    }

    /* No changes to envp */
    *user_env_out = plugin_state.envp;

    /* Space for authentication */

    pam_action = strdup("auth");
    pam_user = user_information.username;

    sudo_log(SUDO_CONV_INFO_MSG, "\nCalling PAM with action: %s\nuser: %s\n", pam_action,pam_user);
    pam_ret = pam_start(SSS_SUDO_PAM_SERVICE, pam_user, &conv, &pamh);

    if (pam_ret != PAM_SUCCESS) {
        fprintf(stderr, "pam_start failed: %s\n", pam_strerror(pamh, pam_ret));
        return 0;
    }

    pam_ret = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
    switch(pam_ret) {
    case PAM_ABORT:
        fprintf(stderr, "pam_authenticate - aborted: %s\n", pam_strerror(pamh, pam_ret));
        pam_end(pamh, pam_ret);
        return 0;

    case PAM_AUTH_ERR:
        fprintf(stderr, "pam_authenticate - error: %s\n", pam_strerror(pamh, pam_ret));
        pam_end(pamh, pam_ret);
        return 0;

    case PAM_SUCCESS:
        fprintf(stdout, "pam_authenticate - success: %s\n", pam_strerror(pamh, pam_ret));
        break;

    case PAM_CRED_INSUFFICIENT:
        fprintf(stderr, "pam_authenticate - crendential not sufficient: %s\n", pam_strerror(pamh, pam_ret));
        pam_end(pamh, pam_ret);
        return 0;

    case PAM_AUTHINFO_UNAVAIL:
        fprintf(stderr, "pam_authenticate - authentication information not available: %s\n", pam_strerror(pamh, pam_ret));
        pam_end(pamh, pam_ret);
        return 0;

    case PAM_USER_UNKNOWN:
        fprintf(stderr, "pam_authenticate - check the user specified : %s\n", pam_strerror(pamh, pam_ret));
        pam_end(pamh, pam_ret);
        return 0;

    case PAM_MAXTRIES:
        fprintf(stderr, "pam_authenticate - maximum tries over : %s\n", pam_strerror(pamh, pam_ret));
        pam_end(pamh, pam_ret);
        return 0;

    default:
        fprintf(stderr, "pam_authenticate - unknown error : %s\n", pam_strerror(pamh, pam_ret));
        pam_end(pamh, pam_ret);
        return 0;

    }

    /* pam is success :) */
    pam_end(pamh, pam_ret);

    msg.fq_command = command;
    msg.command = (char **) argv;
    msg.command_count = argc;

    if(pam_ret==PAM_SUCCESS) {
        pam_ret = send_and_receive();
    }

    free(pam_action);
    free_all();
    /* Setup command info. */
    *command_info_out = build_command_info(command);
    if (*command_info_out == NULL) {
        sudo_log(SUDO_CONV_ERROR_MSG, "out of memory\n");
        return ERROR;
    }
    if(pam_ret==SSS_SUDO_SUCCESS)
        return TRUE;

    return FALSE;
}

int policy_list(int argc, char * const argv[], int verbose, const char *list_user)
{
    /*
     * List user's capabilities.
     */
    sudo_log(SUDO_CONV_INFO_MSG, "Validated users may run any command. Currently validation isn't coded. :/\n");
    return TRUE;
}



int policy_version(int verbose)
{
    sudo_log(SUDO_CONV_INFO_MSG, "%sv\nSudo Plugin API version %dv\nSSSD sudo plugin version %s\n", SUDO_PACKAGE_STRING,SUDO_API_VERSION,SSS_SUDO_PLUGIN_VERSION);
    return TRUE;
}


void policy_close(int exit_status, int error)
{
    /*
     * The close function is called when the command being run by sudo finishes.
     */
    if (error) {
        sudo_log(SUDO_CONV_ERROR_MSG, "\nCommand error: %s\n", strerror(error));
    }
    else {
        if (WIFEXITED(exit_status)) {
            sudo_log(SUDO_CONV_INFO_MSG, "\nCommand exited with status %d\n",
                     WEXITSTATUS(exit_status));
        } else if (WIFSIGNALED(exit_status)) {
            sudo_log(SUDO_CONV_INFO_MSG, "\nCommand killed by signal %d\n",
                     WTERMSIG(exit_status));
        }
    }
}



/* SUDO Plugin structure */
struct policy_plugin sss_sudo_policy = {
                                        SUDO_POLICY_PLUGIN,
                                        SUDO_API_VERSION,
                                        policy_open,
                                        policy_close,
                                        policy_version,
                                        policy_check,
                                        policy_list,
                                        NULL, /* validate */
                                        NULL /* invalidate */
};

/* IO_PLUGIN is not needed */






