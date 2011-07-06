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

#define PAM_DEBUG 1

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <dbus/dbus.h>

#include "sss_sudo_cli.h"




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


#define CHECK_AND_RETURN_BOOL_STRING(obj)  ((obj)?"FALSE":"TRUE")

static struct plugin_state {
    char **envp;
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

static struct user_info_struct
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





static void print_sudo_items()
{
    if (msg.userid < 0) return;
    D(("Sending data to sssd:: "));
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
static void init_size_of_msg_contents()
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
static int policy_open(unsigned int version, 
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
    plugin_state.envp = (char **)user_env;
    msg.user_env = (char **)user_env;
    /* FIXME: Set a mechanism to handle environment */
    plugin_state.settings = settings;
    plugin_state.user_info = user_info;

    return 1;
}

/* Function to check if the command is available in the PATH */
static char * find_in_path(char *command, char **envp)
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
static char ** build_command_info(char *command)
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
static char * find_editor(int nfiles, char * const files[], char **argv_out[])
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

void calc_nullable_status(dbus_uint32_t * status) 
{
  *status = 0x0000;
   if(msg.cwd)
      *status |= SSS_SUDO_ITEM_CWD;
   if(msg.tty)
      *status |= SSS_SUDO_ITEM_TTY;
   if(msg.runas_user)
      *status |= SSS_SUDO_ITEM_RUSER;
   if(msg.runas_group)
      *status |= SSS_SUDO_ITEM_RGROUP;
   if(msg.prompt)
      *status |= SSS_SUDO_ITEM_PROMPT;
   if(msg.network_addrs)
      *status |= SSS_SUDO_ITEM_NETADDR;
   if(msg.command)
      *status |= SSS_SUDO_ITEM_COMMAND;
   if(msg.user_env)
      *status |= SSS_SUDO_ITEM_USER_ENV;
  
}




int sss_sudo_make_request(struct sss_cli_req_data *rd,
                      uint8_t **repbuf, size_t *replen,
                      int *errnop)
{

   const char * truth = "TRUE";
   const char * fallacy = "FALSE";
   char ** command_array;
   int count;
   char *tmp;
   char **ui;
   
#define GET_BOOL_STRING(x) ((x)? &truth : &fallacy)
   
   DBusConnection* conn;
   DBusError err;
   
   DBusMessage* dbus_msg;
   DBusMessage* dbus_reply;
   DBusMessageIter msg_iter;
   DBusMessageIter sub_iter;
   DBusMessageIter dict_iter;
   
   dbus_uint32_t start_header;
   dbus_uint32_t status=0;
   dbus_bool_t ret=FALSE;
   dbus_uint32_t nullable_status= 0x0000;
   
   calc_nullable_status(&nullable_status);

   fprintf(stdout,"Calling remote method to pack message\n");
   
   /* initialise the errors */
   dbus_error_init(&err);

   /* connect to the system bus and check for errors */
   conn = dbus_connection_open_private(SSS_SUDO_SERVICE_PIPE, &err);
   if (dbus_error_is_set(&err)) { 
      fprintf(stderr, "Connection Error (%s)\n", err.message); 
      dbus_error_free(&err);
   }
   if (NULL == conn) { 
      return SSS_SUDO_SYSTEM_ERR; 
   }


   /* create a new method call and check for errors */
   dbus_msg = dbus_message_new_method_call( NULL, 		/*    target    */
                                      SUDO_SERVER_PATH,        /*    object    */
                                      SUDO_SERVER_INTERFACE,  /*   interface  */
                                      SUDO_METHOD_QUERY);    /*  method name */              
   if (NULL == dbus_msg) { 
      fprintf(stderr, "Message Null\n");
      if (dbus_error_is_set(&err)) 
	  dbus_error_free(&err);
      dbus_connection_close(conn);
      return SSS_SUDO_SYSTEM_ERR;
   }
   
   start_header = SSS_START_OF_SUDO_REQUEST;

   /* append arguments */
   
   
   dbus_message_iter_init_append(dbus_msg, &msg_iter);
       
   if (!dbus_message_iter_append_basic(&msg_iter, 
					DBUS_TYPE_UINT32, 
				       &start_header)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
   if (!dbus_message_iter_append_basic(&msg_iter, 
				       DBUS_TYPE_UINT32, 
				       &nullable_status)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
      
   if(!dbus_message_iter_open_container(&msg_iter,
					DBUS_TYPE_STRUCT,NULL,
					&sub_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
  if (!dbus_message_iter_append_basic(&sub_iter, 
				      DBUS_TYPE_UINT32, 
				      &msg.userid)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
  if(nullable_status & SSS_SUDO_ITEM_CWD){
    if (!dbus_message_iter_append_basic(&sub_iter, 
					DBUS_TYPE_STRING, 
					&msg.cwd)) {
	fprintf(stderr, "Out Of Memory!\n"); 
	exit(1);
    }
  }
   
  if(nullable_status & SSS_SUDO_ITEM_TTY){
    if (!dbus_message_iter_append_basic(&sub_iter, 
					DBUS_TYPE_STRING, 
					&msg.tty)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
    }
  }
      
   if (!dbus_message_iter_close_container(&msg_iter,&sub_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
   command_array =  (char *) malloc(msg.command_count* sizeof (char*));
   
   for(count = 0;count<msg.command_count;count++) {
     command_array[count] = msg.command[count];
   }
   
   
    if(nullable_status & SSS_SUDO_ITEM_COMMAND){
      
    if(!dbus_message_iter_open_container(&msg_iter,
					 DBUS_TYPE_ARRAY,"s",
					 &sub_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
   for(count =0; count<msg.command_count;count++){
     
      if (!dbus_message_iter_append_basic(&sub_iter, 
					  DBUS_TYPE_STRING, 
					  &command_array[count])) {
	  fprintf(stderr, "Out Of Memory!\n"); 
	  exit(1);
      } 
     
   }
   
   if (!dbus_message_iter_close_container(&msg_iter,&sub_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
	exit(1);
   }
   }
   ////////
   
   if(!dbus_message_iter_open_container(&msg_iter,
					 DBUS_TYPE_ARRAY,
					"{ss}",
					&sub_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
	exit(1);
   }
   
    if(nullable_status & SSS_SUDO_ITEM_RUSER){
   tmp = strdup("runasuser");
   
 	if(!dbus_message_iter_open_container(&sub_iter, 
					      DBUS_TYPE_DICT_ENTRY,NULL,
					      &dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
    
   if (!dbus_message_iter_append_basic(&dict_iter, 
					DBUS_TYPE_STRING,
				       &tmp)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if (!dbus_message_iter_append_basic(&dict_iter,
				      DBUS_TYPE_STRING,
				       &msg.runas_user)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   free(tmp);
   
    if (!dbus_message_iter_close_container(&sub_iter,&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
    }
    
    
     if(nullable_status & SSS_SUDO_ITEM_RGROUP){
	tmp = strdup("runasgroup");
	if(!dbus_message_iter_open_container(&sub_iter, DBUS_TYPE_DICT_ENTRY,NULL,&dict_iter)) {
	      fprintf(stderr, "Out Of Memory!\n"); 
	      exit(1);
	}
	if (!dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &tmp)) {
	      fprintf(stderr, "Out Of Memory!\n"); 
	      exit(1);
	}
	if (!dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &msg.runas_group)) {
	      fprintf(stderr, "Out Of Memory!\n"); 
	      exit(1);
	}
	free(tmp);
   
	if (!dbus_message_iter_close_container(&sub_iter,&dict_iter)) {
	      fprintf(stderr, "Out Of Memory!\n"); 
	      exit(1);
	}
   
    }
    
    
     if(nullable_status & SSS_SUDO_ITEM_PROMPT){
       if(!dbus_message_iter_open_container(&sub_iter, DBUS_TYPE_DICT_ENTRY,NULL,&dict_iter)) {
	      fprintf(stderr, "Out Of Memory!\n"); 
	      exit(1);
	}
      tmp = strdup("prompt");
  
      if (!dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &tmp)) {
	  fprintf(stderr, "Out Of Memory!\n"); 
	  exit(1);
      }
      if (!dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &msg.prompt)) {
	  fprintf(stderr, "Out Of Memory!\n"); 
	  exit(1);
      }
      free(tmp);
   
      if (!dbus_message_iter_close_container(&sub_iter,&dict_iter)) {
	  fprintf(stderr, "Out Of Memory!\n"); 
	  exit(1);
      }
  
    }
    
    
    
  if(nullable_status & SSS_SUDO_ITEM_NETADDR){
      if(!dbus_message_iter_open_container(&sub_iter, DBUS_TYPE_DICT_ENTRY,NULL,&dict_iter)) {
	  fprintf(stderr, "Out Of Memory!\n"); 
	  exit(1);
      }
      tmp = strdup("networkaddress");
     
      if (!dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &tmp)) {
	  fprintf(stderr, "Out Of Memory!\n"); 
	  exit(1);
      }
      if (!dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &msg.network_addrs)) {
	  fprintf(stderr, "Out Of Memory!\n"); 
	  exit(1);
      }
      free(tmp);
   
      if (!dbus_message_iter_close_container(&sub_iter,&dict_iter)) {
	   fprintf(stderr, "Out Of Memory!\n"); 
	   exit(1);
      }
   
  }
    
    
    
   
   tmp = strdup("use_sudoedit");
   if(!dbus_message_iter_open_container(&sub_iter, 
					DBUS_TYPE_DICT_ENTRY,NULL,
					&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
    
   if (!dbus_message_iter_append_basic(&dict_iter,
				      DBUS_TYPE_STRING,
				       &tmp)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if (!dbus_message_iter_append_basic(&dict_iter, 
					DBUS_TYPE_STRING, 
				       GET_BOOL_STRING(msg.use_sudoedit))) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   free(tmp);
   
    if (!dbus_message_iter_close_container(&sub_iter,&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if(!dbus_message_iter_open_container(&sub_iter, 
					DBUS_TYPE_DICT_ENTRY,
					NULL,
					&dict_iter)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
   
   tmp = strdup("use_set_home");
     
   if (!dbus_message_iter_append_basic(&dict_iter,
					DBUS_TYPE_STRING, 
				       &tmp)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if (!dbus_message_iter_append_basic(&dict_iter, 
					DBUS_TYPE_STRING, 
				       GET_BOOL_STRING(msg.use_set_home))) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   free(tmp);
   
    if (!dbus_message_iter_close_container(&sub_iter,&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
   
   if(!dbus_message_iter_open_container(&sub_iter,
					DBUS_TYPE_DICT_ENTRY,
					NULL,
					&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
   
   tmp = strdup("use_preserve_environment");
     
   if (!dbus_message_iter_append_basic(&dict_iter, 
					DBUS_TYPE_STRING, 
				       &tmp)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if (!dbus_message_iter_append_basic(&dict_iter,
				      DBUS_TYPE_STRING, 
				       GET_BOOL_STRING(msg.use_preserve_environment))) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   free(tmp);
   
    if (!dbus_message_iter_close_container(&sub_iter,&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
	exit(1);
   }
   if(!dbus_message_iter_open_container(&sub_iter, 
					DBUS_TYPE_DICT_ENTRY,
					NULL,
					&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
	exit(1);
   }
   
   tmp = strdup("use_implied_shell");
    
   if (!dbus_message_iter_append_basic(&dict_iter, 
				      DBUS_TYPE_STRING,
				      &tmp)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if (!dbus_message_iter_append_basic(&dict_iter, 
					DBUS_TYPE_STRING,
				       GET_BOOL_STRING(msg.use_implied_shell))) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   free(tmp);
   
    if (!dbus_message_iter_close_container(&sub_iter,&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if(!dbus_message_iter_open_container(&sub_iter, 
					DBUS_TYPE_DICT_ENTRY,
					NULL,
					&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
   tmp = strdup("use_login_shell");
     
   if (!dbus_message_iter_append_basic(&dict_iter, 
				      DBUS_TYPE_STRING,
				      &tmp)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if (!dbus_message_iter_append_basic(&dict_iter, 
				      DBUS_TYPE_STRING, 
				       GET_BOOL_STRING(msg.use_login_shell))) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   free(tmp);
   
    if (!dbus_message_iter_close_container(&sub_iter,&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if(!dbus_message_iter_open_container(&sub_iter, 
					DBUS_TYPE_DICT_ENTRY,
					NULL,
					&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
   
   tmp = strdup("use_run_shell");
     
   if (!dbus_message_iter_append_basic(&dict_iter, 
				      DBUS_TYPE_STRING, 
				      &tmp)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if (!dbus_message_iter_append_basic(&dict_iter, 
					DBUS_TYPE_STRING, 
				       GET_BOOL_STRING(msg.use_run_shell))) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   free(tmp);
   
   
    if (!dbus_message_iter_close_container(&sub_iter,&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if(!dbus_message_iter_open_container(&sub_iter, 
					DBUS_TYPE_DICT_ENTRY,
					NULL,
					&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
   
   tmp = strdup("use_preserve_groups");
     
   if (!dbus_message_iter_append_basic(&dict_iter, 
					DBUS_TYPE_STRING, 
				       &tmp)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if (!dbus_message_iter_append_basic(&dict_iter, 
				      DBUS_TYPE_STRING, 
				       GET_BOOL_STRING(msg.use_preserve_groups))) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   free(tmp);
   
    if (!dbus_message_iter_close_container(&sub_iter,&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if(!dbus_message_iter_open_container(&sub_iter, 
					DBUS_TYPE_DICT_ENTRY,
					NULL,
					&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
   
   tmp = strdup("use_ignore_ticket");
     
   if (!dbus_message_iter_append_basic(&dict_iter, 
				      DBUS_TYPE_STRING, 
				      &tmp)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if (!dbus_message_iter_append_basic(&dict_iter, 
					DBUS_TYPE_STRING, 
				       GET_BOOL_STRING(msg.use_ignore_ticket))) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   free(tmp);
   
    if (!dbus_message_iter_close_container(&sub_iter,&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if(!dbus_message_iter_open_container(&sub_iter, 
					DBUS_TYPE_DICT_ENTRY,
					NULL,
					&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
   tmp = strdup("use_noninteractive");
     
   if (!dbus_message_iter_append_basic(&dict_iter, 
				      DBUS_TYPE_STRING, 
				       &tmp)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if (!dbus_message_iter_append_basic(&dict_iter,
					DBUS_TYPE_STRING,
				       GET_BOOL_STRING(msg.use_noninteractive))) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   free(tmp);
   
    if (!dbus_message_iter_close_container(&sub_iter,&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if(!dbus_message_iter_open_container(&sub_iter, 
					DBUS_TYPE_DICT_ENTRY,
					NULL,
					&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
   tmp = strdup("use_debug_level");
     
   if (!dbus_message_iter_append_basic(&dict_iter, 
				      DBUS_TYPE_STRING, 
				       &tmp)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if (!dbus_message_iter_append_basic(&dict_iter, 
				      DBUS_TYPE_STRING, 
				       GET_BOOL_STRING(msg.debug_level))) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   free(tmp);
   
   
   
  
  
  
   if (!dbus_message_iter_close_container(&sub_iter,&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
    if (!dbus_message_iter_close_container(&msg_iter,&sub_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }


  /////
  
  
  
  if(!dbus_message_iter_open_container(&msg_iter,
					DBUS_TYPE_ARRAY,
				       "{ss}",
				       &sub_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
  
   for(ui = msg.user_env; *ui!=NULL;*ui++) {
   
     tmp = strchr(*ui,'=');
     
     *tmp = '\0';
      if(!dbus_message_iter_open_container(&sub_iter, 
					  DBUS_TYPE_DICT_ENTRY,NULL,
					   &dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
     
   if (!dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, ui)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   if (!dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &tmp+1)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   *tmp = '=' ;

    if (!dbus_message_iter_close_container(&sub_iter,&dict_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   
   }

if (!dbus_message_iter_close_container(&msg_iter,&sub_iter)) {
	fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }

   
   /* send message and get a handle for a reply */
   dbus_reply = dbus_connection_send_with_reply_and_block (conn,dbus_msg,
							   600,
							   &err);
   if (dbus_error_is_set(&err)) { 
      fprintf(stderr, "Connection send-reply Error (%s)\n", err.message); 
      dbus_error_free(&err);
      exit(1);
   }
   if (NULL == dbus_reply) { 
      fprintf(stderr, "reply failed\n"); 
      exit(1); 
   }
   
   
   fprintf(stdout,"Request Sent\n");
     

    ret = dbus_message_get_args(dbus_reply, &err,
                                  DBUS_TYPE_UINT16, &status,
                                  DBUS_TYPE_INVALID);
    if (!ret) {
        fprintf (stderr,"Failed to parse reply, killing connection\n");
        if (dbus_error_is_set(&err)) dbus_error_free(&err);
        dbus_connection_close(conn);
        return SSS_SUDO_SYSTEM_ERR;
    }
    
   fprintf(stdout,"Got Reply: %d\n", status);
   
   // free reply and close connection
   /* free message */
   dbus_message_unref(dbus_msg);
   dbus_message_unref(dbus_reply);
   dbus_connection_close(conn);

free(command_array);

return SSS_STATUS_SUCCESS;

}

void free_all()
{
  free(msg.cwd);
  free(msg.tty);
  free(msg.prompt);
  free(msg.runas_user);
  free(msg.runas_group);
  free(msg.network_addrs);
  free(user_information.username);
  
}


static int send_and_receive()
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
    _status = SSS_STATUS_SUCCESS;

    if (_status == SSS_STATUS_SUCCESS)
	return _status;
    else
	return SSS_STATUS_UNAVAIL;
}



/*
 * Plugin policy check function.
 * The check_policy function is called by sudo to determine
 * whether the user is allowed to run the specified commands.
 */
static int  policy_check(int argc, char * const argv[],
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

  msg.command = argv;
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
  if(pam_ret==SSS_STATUS_SUCCESS)
    return TRUE;

  return FALSE;
}

static int policy_list(int argc, char * const argv[], int verbose, const char *list_user)
{
    /*
     * List user's capabilities.
     */
    sudo_log(SUDO_CONV_INFO_MSG, "Validated users may run any command. Currently validation isn't coded. :/\n");
    return TRUE;
}



static int policy_version(int verbose)
{
    sudo_log(SUDO_CONV_INFO_MSG, "%sv\nSudo Plugin API version %dv\nSSSD sudo plugin version %s\n", SUDO_PACKAGE_STRING,SUDO_API_VERSION,SSS_SUDO_PLUGIN_VERSION);
    return TRUE;
}


static void policy_close(int exit_status, int error)
{
    /*
     * The close function is called when the command being run by sudo finishes.
     */
    if (error) {
	sudo_log(SUDO_CONV_ERROR_MSG, "\nCommand error: %s\n", strerror(error));
    } else {
        if (WIFEXITED(exit_status)) {
	    sudo_log(SUDO_CONV_INFO_MSG, "\nCommand exited with status %d\n",
		WEXITSTATUS(exit_status));
        } else if (WIFSIGNALED(exit_status)) {
	    sudo_log(SUDO_CONV_INFO_MSG, "\nCommand killed by signal %d\n",
		WTERMSIG(exit_status));
	  }
      }
}


/* IO_PLUGIN is not needed */


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



