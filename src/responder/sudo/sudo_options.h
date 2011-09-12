/*
 *
 *
 *  SSSD
 *
 * sudo_options.h
 *
 *  Copyright (C)  Arun Scaria <arunscaria91@gmail.com> (2011)

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

#ifndef SUDO_OPTIONS_H_
#define SUDO_OPTIONS_H_

#include <stdbool.h>

#define    SUDO_OPT_ALWAYS_SET_HOME           "always_set_home"
#define    SUDO_OPT_AUTHENTICATE              "authenticate"
#define    SUDO_OPT_CLOSE_FROM_OVERRIDE       "closefrom_override"
#define    SUDO_OPT_COMPRESS_IO               "compress_io"
#define    SUDO_OPT_ENV_EDITOR                "env_editor"
#define    SUDO_OPT_ENV_RESET                 "env_reset"
#define    SUDO_OPT_FAST_GLOB                 "fast_glob"
#define    SUDO_OPT_FQDN                      "fqdn"
#define    SUDO_OPT_IGNORE_DOT                "ignore_dot"
#define    SUDO_OPT_IGNORE_LOCAL_SUDOERS      "ignore_local_sudoers"
#define    SUDO_OPT_INSULT                    "insults"
#define    SUDO_OPT_LOG_HOST                  "log_host"
#define    SUDO_OPT_LOG_INPUT                 "log_input"
#define    SUDO_OPT_LOG_OUTPUT                "log_output"
#define    SUDO_OPT_LOG_YEAR                  "log_year"
#define    SUDO_OPT_LONG_OTP_PROMPT           "long_otp_prompt"
#define    SUDO_OPT_MAIL_ALWAYS               "mail_always"
#define    SUDO_OPT_MAIL_BADPASS              "mail_badpass"
#define    SUDO_OPT_MAIL_NO_HOST              "mail_no_host"
#define    SUDO_OPT_MAIL_NO_PERMS             "mail_no_perms"
#define    SUDO_OPT_MAIL_NO_USER              "mail_no_user"
#define    SUDO_OPT_NOEXEC                    "noexec"
#define    SUDO_OPT_PATH_INFO                 "path_info"
#define    SUDO_OPT_PASSPROMPT_OVERRIDE       "passprompt_override"
#define    SUDO_OPT_PRESERVE_GROUPS           "preserve_groups"
#define    SUDO_OPT_PWFEEDBACK                "pwfeedback"
#define    SUDO_OPT_REQUIRETTY                "requiretty"
#define    SUDO_OPT_ROOT_SUDO                 "root_sudo"
#define    SUDO_OPT_ROOTPW                    "rootpw"
#define    SUDO_OPT_RUNASPW                   "runaspw"
#define    SUDO_OPT_SET_HOME                  "set_home"
#define    SUDO_OPT_SET_LOGNAME               "set_logname"
#define    SUDO_OPT_SET_UTMP                  "set_utmp"
#define    SUDO_OPT_SETENV                    "setenv"
#define    SUDO_OPT_SHELL_NOARGS              "shell_noargs"
#define    SUDO_OPT_STAY_SETUID               "stay_setuid"
#define    SUDO_OPT_TARGETPW                  "targetpw"
#define    SUDO_OPT_TTY_TICKETS               "tty_tickets"
#define    SUDO_OPT_UMASK_OVERRIDE            "umask_override"
#define    SUDO_OPT_USE_PTY                   "use_pty"
#define    SUDO_OPT_UTMP_RUNAS                "utmp_runas"
#define    SUDO_OPT_VISIBLEPW                 "visiblepw"
#define    SUDO_OPT_CLOSEFROM                 "closefrom"
#define    SUDO_OPT_PASSWD_TRIES              "passwd_tries"
#define    SUDO_OPT_LOGLINELEN                "loglinelen"
#define    SUDO_OPT_PASSWD_TIMEOUT            "passwd_timeout"
#define    SUDO_OPT_TIMESTAMP_TIMEOUT         "timestamp_timeout"
#define    SUDO_OPT_UMASK                     "umask"
#define    SUDO_OPT_BADPASS_MESSAGE           "badpass_message"
#define    SUDO_OPT_EDITOR                    "editor"
#define    SUDO_OPT_IOLOG_DIR                 "iolog_dir"
#define    SUDO_OPT_IOLOG_FILE                "iolog_file"
#define    SUDO_OPT_MAILSUB                   "mailsub"
#define    SUDO_OPT_NOEXEC_FILE               "noexec_file"
#define    SUDO_OPT_PASSPROMPT                "passprompt"
#define    SUDO_OPT_RUNAS_DEFAULT             "runas_default"
#define    SUDO_OPT_SYSLOG_BADPRI             "syslog_badpri"
#define    SUDO_OPT_SYSLOG_GOODPRI            "syslog_goodpri"
#define    SUDO_OPT_SUDOERS_LOCALE            "sudoers_locale"
#define    SUDO_OPT_TIMESTAMPDIR              "timestampdir"
#define    SUDO_OPT_TIMESTAMPOWNER            "timestampowner"
#define    SUDO_OPT_ASKPASS                   "askpass"
#define    SUDO_OPT_ENV_FILE                  "env_file"
#define    SUDO_OPT_EXEMPT_GROUP              "exempt_group"
#define    SUDO_OPT_GROUP_PLUGIN              "group_plugin"
#define    SUDO_OPT_LECTURE                   "lecture"
#define    SUDO_OPT_LECTURE_FILE              "lecture_file"
#define    SUDO_OPT_LISTPW                    "listpw"
#define    SUDO_OPT_LOGFILE                   "logfile"
#define    SUDO_OPT_MAILERFLAGS               "mailerflags"
#define    SUDO_OPT_MAILERPATH                "mailerpath"
#define    SUDO_OPT_MAILFROM                  "mailfrom"
#define    SUDO_OPT_MAILTO                    "mailto"
#define    SUDO_OPT_SECURE_PATH               "secure_path"
#define    SUDO_OPT_SYSLOG                    "syslog"
#define    SUDO_OPT_VERIFYPW                  "verifypw"
#define    SUDO_OPT_ENV_CHECK                 "env_check"
#define    SUDO_OPT_ENV_DELETE                "env_delete"
#define    SUDO_OPT_ENV_KEEP                  "env_keep"

struct sss_sudo_options{

    bool log_host;
    bool log_input;
    bool log_output;
    bool log_year;
    bool long_otp_prompt;
    bool mail_always;
    bool mail_badpass;
    bool mail_no_host;
    bool mail_no_perms;
    bool mail_no_user;
    bool noexec;
    bool path_info;
    bool passprompt_override;
    bool preserve_groups;
    bool pwfeedback;
    bool requiretty;
    bool root_sudo;
    bool rootpw;
    bool runaspw;
    bool set_home;
    bool set_logname;
    bool set_utmp;
    bool setenv;
    bool shell_noargs;
    bool stay_setuid;
    bool targetpw;
    bool tty_tickets;
    bool umask_override;
    bool use_pty;
    bool utmp_runas;
    bool visiblepw;
    int closefrom;
    int passwd_tries;
    int loglinelen;
    int passwd_timeout;
    int timestamp_timeout;
    int umask;
    char * badpass_message;
    char * editor;
    char * iolog_dir;
    char * iolog_file;
    char * mailsub;
    char * noexec_file;
    char * passprompt;
    char * runas_default;
    char * syslog_badpri;
    char * syslog_goodpri;
    char * sudoers_locale;
    char * timestampdir;
    char * timestampowner;
    char * askpass;
    char * env_file;
    char * exempt_group;
    char * group_plugin;
    char * lecture;
    char * lecture_file;
    char * listpw;
    char * logfile;
    char * mailerflags;
    char * mailerpath;
    char * mailfrom;
    char * mailto;
    char * secure_path;
    char * syslog;
    char * verifypw;
    char * env_check;
    char * env_delete;
    char * env_keep;

};


#endif /* SUDO_OPTIONS_H_ */
