/*
 * PAM authentication module for SQLite
 *
 * SQLite port: Edin Kadribasic <edink@php.net>
 * Extended SQL configuration support by Wez Furlong <wez@thebrainroom.com>
 *
 * Based in part on pam_pgsql.c by David D.W. Downey ("pgpkeys") <david-downey@codecastle.com>
 *
 * Based in part on pam_unix.c of FreeBSD.
 *
 */

/* $Id: pam_sqlite.c,v 1.11 2003/07/17 13:47:07 wez Exp $ */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <time.h>
#include <sqlite3.h>
#if HAVE_CRYPT_H
#include <crypt.h>
#endif

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_PASSWORD
#include <security/pam_modules.h>
#include "pam_mod_misc.h"

#define PASSWORD_PROMPT         "Password: "
#define PASSWORD_PROMPT_NEW     "New password: "
#define PASSWORD_PROMPT_CONFIRM "Confirm new password: "
#define CONF                    "/etc/pam_sqlite.conf"

#define DBGLOG(x...)  if(options->debug) {                          \
                          openlog("PAM_sqlite", LOG_PID, LOG_AUTH); \
                          syslog(LOG_DEBUG, ##x);                   \
                          closelog();                               \
                      }
#define SYSLOG(x...)  do {                                          \
                          openlog("PAM_sqlite", LOG_PID, LOG_AUTH); \
                          syslog(LOG_INFO, ##x);                    \
                          closelog();                               \
                      } while(0);

typedef enum {
    PW_SHA512,
#if HAVE_MD5_CRYPT
    PW_MD5,
#endif
    PW_CRYPT,
} pw_scheme;

struct module_options {
    char *database;
    char *table;
    char *user_column;
    char *pwd_column;
    char *expired_column;
    char *newtok_column;
    pw_scheme pw_type;
    int debug;
    char *sql_verify;
    char *sql_check_expired;
    char *sql_check_newtok;
    char *sql_set_passwd;
};

#define GROW(x)        if (x > buflen - dest - 1) {    \
    char *grow;                                        \
    buflen += 256 + x;                                 \
    grow = realloc(buf, buflen + 256 + x);             \
    if (grow == NULL) { free(buf); return NULL; }      \
    buf = grow;                                        \
}

#define APPEND(str, len)    GROW(len); memcpy(buf + dest, str, len); dest += len
#define APPENDS(str)    len = strlen(str); APPEND(str, len)

static char * format_query(const char *template,
                           struct module_options *options,
                           const char *user,
                           const char *passwd)
{
    char *buf = malloc(256);
    int buflen = 256;
    int dest = 0, len;
    const char *src = template;
    char *pct;
    char *tmp;

    while (*src) {
        pct = strchr(src, '%');

        if (pct) {
            /* copy from current position to % char into buffer */
            if (pct != src) {
                len = pct - src;
                APPEND(src, len);
            }

            /* decode the escape */
            switch(pct[1]) {
                case 'U':    /* username */
                    if (user) {
                        tmp = sqlite3_mprintf("%q", user);
                        len = strlen(tmp);
                        APPEND(tmp, len);
                        sqlite3_free(tmp);
                    }
                    break;
                case 'P':    /* password */
                    if (passwd) {
                        tmp = sqlite3_mprintf("%q", passwd);
                        len = strlen(tmp);
                        APPEND(tmp, len);
                        sqlite3_free(tmp);
                    }
                    break;
                case 'O':    /* option value */
                    pct++;
                    switch (pct[1]) {
                        case 'p':    /* passwd */
                            APPENDS(options->pwd_column);
                            break;
                        case 'u':    /* username */
                            APPENDS(options->user_column);
                            break;
                        case 't':    /* table */
                            APPENDS(options->table);
                            break;
                        case 'x':    /* expired */
                            APPENDS(options->expired_column);
                            break;
                        case 'n':    /* newtok */
                            APPENDS(options->newtok_column);
                            break;
                    }
                    break;
                case '%':    /* quoted % sign */
                    APPEND(pct, 1);
                    break;
                default:    /* unknown */
                    APPEND(pct, 2);
                    break;
            }
            src = pct + 2;
        } else {
            /* copy rest of string into buffer and we're done */
            len = strlen(src);
            APPEND(src, len);
            break;
        }
    }

    buf[dest] = '\0';
    return buf;
}

static void get_module_options_from_file(const char *filename,
                                         struct module_options *opts,
                                         int warn);

/* private: parse and set the specified string option */
static void set_module_option(const char *option,
                              struct module_options *options)
{
    char *buf, *eq;
    char *val, *end;

    if(!option || !*option)
        return;

    buf = strdup(option);

    if((eq = strchr(buf, '='))) {
        end = eq - 1;
        val = eq + 1;
        if(end <= buf || !*val)
            return;
        while(end > buf && isspace(*end))
            end--;
        end++;
        *end = '\0';
        while(*val && isspace(*val))
            val++;
    } else {
        val = NULL;
    }

    DBGLOG("setting option: %s=>%s\n", buf, val);

    if(!strcmp(buf, "database")) {
        options->database = strdup(val);
    } else if(!strcmp(buf, "table")) {
        options->table = strdup(val);
    } else if(!strcmp(buf, "user_column")) {
        options->user_column = strdup(val);
    } else if(!strcmp(buf, "pwd_column")) {
        options->pwd_column = strdup(val);
    } else if(!strcmp(buf, "expired_column")) {
        options->expired_column = strdup(val);
    } else if(!strcmp(buf, "newtok_column")) {
        options->newtok_column = strdup(val);
    } else if(!strcmp(buf, "pw_type")) {
        options->pw_type = PW_SHA512;
        if(!strcmp(val, "crypt")) {
            options->pw_type = PW_CRYPT;
        }
#if HAVE_MD5_CRYPT
        else if(!strcmp(val, "md5")) {
            options->pw_type = PW_MD5;
        }
#endif
    } else if(!strcmp(buf, "debug")) {
        options->debug = 1;
    } else if (!strcmp(buf, "config_file")) {
        get_module_options_from_file(val, options, 1);
    } else if (!strcmp(buf, "sql_verify")) {
        options->sql_verify = strdup(val);
    } else if (!strcmp(buf, "sql_check_expired")) {
        options->sql_check_expired = strdup(val);
    } else if (!strcmp(buf, "sql_check_newtok")) {
        options->sql_check_newtok = strdup(val);
    } else if (!strcmp(buf, "sql_set_passwd")) {
        options->sql_set_passwd = strdup(val);
    }

    free(buf);
}

/* private: read module options from a config file */
static void get_module_options_from_file(const char *filename,
                                         struct module_options *opts,
                                         int warn)
{
    FILE *fp;

    if ((fp = fopen(filename, "r"))) {
        char line[1024];
        char *str, *end;

        while(fgets(line, sizeof(line), fp)) {
            str = line;
            end = line + strlen(line) - 1;
            while(*str && isspace(*str))
                str++;
            while(end > str && isspace(*end))
                end--;
            end++;
            *end = '\0';
            set_module_option(str, opts);
        }
        fclose(fp);
    } else if (warn) {
        SYSLOG("unable to read config file %s", filename);
    }
}

/* private: read module options from file or commandline */
static int get_module_options(int argc,
                              const char **argv,
                              struct module_options **options)
{
    int i, retval = 0;
    struct module_options *opts;

    opts = (struct module_options *)malloc(sizeof *opts);
    bzero(opts, sizeof(*opts));
    opts->pw_type = PW_SHA512;

    get_module_options_from_file(CONF, opts, 0);

    for(i = 0; i < argc; i++) {
        if(pam_std_option(&retval, argv[i]) == 0)
            continue;
        set_module_option(argv[i], opts);
    }
    *options = opts;

    return retval;
}

/* private: free module options returned by get_module_options() */
static void free_module_options(struct module_options *options)
{
    if(options->database)
        free(options->database);
    if(options->table)
        free(options->table);
    if(options->user_column)
        free(options->user_column);
    if(options->pwd_column)
        free(options->pwd_column);
    if(options->expired_column)
        free(options->expired_column);
    if(options->newtok_column)
        free(options->newtok_column);
    if(options->sql_verify)
        free(options->sql_verify);
    if(options->sql_check_expired)
        free(options->sql_check_expired);
    if(options->sql_check_newtok)
        free(options->sql_check_newtok);
    if(options->sql_set_passwd)
        free(options->sql_set_passwd);
    bzero(options, sizeof(*options));
    free(options);
}

/* private: make sure required options are present (in cmdline or conf file) */
static int options_valid(struct module_options *options)
{
    if(options->database == 0 || options->table == 0 || options->user_column == 0)
    {
        SYSLOG("the database, table and user_column options are required.");
        return -1;
    }
    return 0;
}

/* private: open SQLite database */
static sqlite3 * pam_sqlite_connect(struct module_options *options,
                                    int flags)
{
    sqlite3 *sdb = NULL;
    int res;

    res = sqlite3_open_v2(options->database, &sdb, flags, NULL);
    if (res != SQLITE_OK) {
        SYSLOG("Error opening SQLite database [%s] [%s]\n",
                options->database, sqlite3_errmsg(sdb));
        return NULL;
    }

    DBGLOG("Successfully opened SQLite3 database [%s]\n",
            options->database);
    return sdb;
}

/* private: generate random salt character */
static unsigned char * crypt_make_salt(struct module_options *options)
{
    int add_trailing_dollar = 0, i, r, urandom, needed;
    static unsigned char buffer[21];
    static unsigned char salt_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    unsigned char pool, *insert_point = buffer, *ret = buffer;

    if ((urandom = open("/dev/null", O_RDONLY)) == -1) {
        DBGLOG("couldn't open /dev/urandom; errno %d (%s)\n", errno, strerror(errno));
        ret = NULL;
        goto cleanup;
    }

    switch(options->pw_type) {
    case PW_CRYPT:
        needed = 2;
        break;
    case PW_SHA512:
        *insert_point++ = '$';
        *insert_point++ = '6';
        *insert_point++ = '$';
        needed = 16;
        add_trailing_dollar = 1;
        break;
#if HAVE_MD5_CRYPT
    case PW_MD5:
        *insert_point++ = '$';
        *insert_point++ = '1';
        *insert_point++ = '$';
        needed = 16;
        add_trailing_dollar = 1;
        break;
#endif
    }

    r = read(urandom, insert_point, needed);
    if (r == -1) {
        DBGLOG("error reading from /dev/urandom; errno %d (%s)\n", errno, strerror(errno));
        ret = NULL;
        goto cleanup;
    } else if (r != needed) {
        DBGLOG("short read from /dev/urandom\n");
        ret = NULL;
        goto cleanup;
    }
    for (i = 0; i < needed; ++i) {
        insert_point[i] = salt_chars[insert_point[i] % 64];
    }
    insert_point += needed;
    if (add_trailing_dollar) {
        *insert_point++ = '$';
    }
    *insert_point++ = 0;

  cleanup:
    if (urandom != -1) {
        while (close(urandom) == -1) {
            if (errno != EINTR) {
                DBGLOG("couldn't close /dev/urandom; errno %d (%s)\n", errno, strerror(errno));
                ret = NULL;
                break;
            }
        }
    }
    return ret;
}

/* private: encrypt password using the preferred encryption scheme */
static char * encrypt_password(struct module_options *options,
                               const char *pass)
{
    return strdup(crypt(pass, (char *)crypt_make_salt(options)));
}

/* private: authenticate username and password against database */
static int auth_verify_password(const char *un,
                                const char *pwd,
                                struct module_options *options)
{
    sqlite3 *sdb;
    sqlite3_stmt *stmt;
    int retval, result;
    char *query;

    if(!(sdb = pam_sqlite_connect(options, SQLITE_OPEN_READONLY)))
        return PAM_AUTH_ERR;

    query = format_query(options->sql_verify ? options->sql_verify :
                         "SELECT %Op FROM %Ot WHERE %Ou='%U'",
                         options, un, pwd);
    DBGLOG("query: %s \n", query);

    /* prepare the sql statement to be executed */
    retval = sqlite3_prepare_v2(sdb, query, -1, &stmt, NULL);

    if (retval != SQLITE_OK) {
        DBGLOG("Error executing SQLite query [%s]",
                sqlite3_errmsg(sdb));
        result = PAM_AUTH_ERR;
        goto cleanup;
    }

    /* execute the sql statement and get the first row */
    retval = sqlite3_step(stmt);

    /* if the select query results in no rows, then the user is not available */
    if (retval == SQLITE_DONE) {
        DBGLOG("No record found for user [%s] [%s]",
                un, sqlite3_errmsg(sdb));
        result = PAM_USER_UNKNOWN;
        goto cleanup;
    }

    /* if the select query does not yield a valid row, then fail */
    if (retval != SQLITE_ROW) {
        DBGLOG("Unable to reterieve user record [%s] [%s]",
                un, sqlite3_errmsg(sdb));
        result = PAM_AUTH_ERR;
        goto cleanup;
    }

    /* get the encrypted password from the database */
    const char *stored_pwd = (char *)sqlite3_column_text(stmt, 0);

    result = PAM_AUTH_ERR;
    switch(options->pw_type) {
        case PW_SHA512:
#if HAVE_MD5_CRYPT
        case PW_MD5:
#endif
        case PW_CRYPT:
            if(strcmp(crypt(pwd, stored_pwd), stored_pwd) == 0)
                result = PAM_SUCCESS;
            break;
    }

cleanup:
    free(query);
    sqlite3_finalize(stmt);
    sqlite3_close(sdb);
    return result;
}

/* public: authenticate user */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
                                   int flags,
                                   int argc,
                                   const char **argv)
{
    struct module_options *options;
    const char *un, *pwd;
    int std_flags;
    int result;

    if ((result = pam_get_user(pamh, &un, NULL)) != PAM_SUCCESS)
        return result;

    std_flags = get_module_options(argc, argv, &options);
    if (options_valid(options) != 0) {
        result = PAM_AUTH_ERR;
        goto cleanup;
    }

    if ((result = pam_get_pass(pamh, &pwd, PASSWORD_PROMPT, std_flags)
               != PAM_SUCCESS))
        goto cleanup;

    if ((result = auth_verify_password(un, pwd, options)) == PAM_SUCCESS) {
        SYSLOG("[%s] user %s authenticated.\n", pam_get_service(pamh), un);
    } else {
        SYSLOG("[%s] unable to authenticate user %s [%s]\n",
                pam_get_service(pamh), un, pam_strerror(NULL, result));
    }

cleanup:
    free_module_options(options);
    return result;
}

/* public: check if account has expired, or needs new password */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh,
                                int flags,
                                int argc,
                                const char **argv)
{
    struct module_options *options;
    const char *un;
    sqlite3 *sdb;
    sqlite3_stmt *stmt;
    char *query = NULL;
    int retval, result = PAM_SUCCESS;

    get_module_options(argc, argv, &options);
    if (options_valid(options) != 0) {
        result = PAM_AUTH_ERR;
        goto cleanup_1;
    }

    /* both not specified, just succeed. */
    if (options->expired_column == 0 && options->newtok_column == 0) {
        result = PAM_SUCCESS;
        goto cleanup_1;
    }

    if ((retval = pam_get_user(pamh, &un, NULL)) != PAM_SUCCESS) {
        DBGLOG("Unable to retervie username\n");
        result = retval;
        goto cleanup_1;
    }

    if (!(sdb = pam_sqlite_connect(options, SQLITE_OPEN_READONLY))) {
        result = PAM_AUTH_ERR;
        goto cleanup_1;
    }

    /* if account has expired then expired_column = '1' or 'y' */
    if(options->expired_column || options->sql_check_expired) {
        query = format_query(options->sql_check_expired ? options->sql_check_expired :
                "SELECT 1 from %Ot WHERE %Ou='%U' AND (%Ox='y' OR %Ox='1')",
                options, un, NULL);
        DBGLOG("query: %s", query);

        retval = sqlite3_prepare_v2(sdb, query, -1, &stmt, NULL);
        if (retval != SQLITE_OK) {
            DBGLOG("Error executing SQLite query [%s]", sqlite3_errmsg(sdb));
            result = PAM_AUTH_ERR;
            goto cleanup_2;
        }

        retval = sqlite3_step(stmt);
        if (retval == SQLITE_ROW) {
            SYSLOG("[%s] user %s account expired.\n", pam_get_service(pamh), un);
            result = PAM_ACCT_EXPIRED;
            goto cleanup_2;
        }

        if (retval != SQLITE_DONE) {
            result = PAM_AUTH_ERR;
            goto cleanup_2;
        }
    }

    /* if new password is required then newtok_column = 'y' or '1' */
    if(options->newtok_column || options->sql_check_newtok) {
        query = format_query(options->sql_check_newtok ? options->sql_check_newtok :
                "SELECT 1 FROM %Ot WHERE %Ou='%U' AND (%On='y' OR %On='1')",
                options, un, NULL);
        DBGLOG("query: %s", query);

        retval = sqlite3_prepare_v2(sdb, query, -1, &stmt, NULL);
        if (retval != SQLITE_OK) {
            DBGLOG("Error executing SQLite query [%s]", sqlite3_errmsg(sdb));
            result = PAM_AUTH_ERR;
            goto cleanup_2;
        }

        retval = sqlite3_step(stmt);
        if (retval == SQLITE_ROW) {
            SYSLOG("[%s] user %s account requires new authentication token.\n",
                    pam_get_service(pamh), un);
            result = PAM_NEW_AUTHTOK_REQD;
            goto cleanup_2;
        }

        if (retval != SQLITE_DONE) {
            result = PAM_AUTH_ERR;
            goto cleanup_2;
        }
    }

    result = PAM_SUCCESS;

cleanup_2:
    free(query);
    sqlite3_finalize(stmt);
    sqlite3_close(sdb);

cleanup_1:
    free_module_options(options);
    return result;
}

/* public: change password */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh,
                                int flags,
                                int argc,
                                const char **argv)
{
    struct module_options *options;
    const char *un, *pwd, *new_pwd;
    char *new_pwd_crypt = NULL;
    sqlite3 *sdb = NULL;
    char *errtext = NULL, *query = NULL;
    int std_flags, retval, result;

    std_flags = get_module_options(argc, argv, &options);
    if (options_valid(options) != 0) {
        result = PAM_AUTH_ERR;
        goto cleanup_1;
    }

    if ((retval = pam_get_user(pamh, &un, NULL)) != PAM_SUCCESS) {
        result = retval;
        goto cleanup_1;
    }

    if (flags & PAM_PRELIM_CHECK) {
        /* at this point, this is the first time we get called */
        if ((retval = pam_get_pass(pamh, &pwd, PASSWORD_PROMPT, std_flags)) != PAM_SUCCESS) {
            SYSLOG("could not retrieve password from '%s'", un);
            result = PAM_AUTH_ERR;
            goto cleanup_1;
        }

        if ((retval = auth_verify_password(un, pwd, options)) != PAM_SUCCESS) {
            DBGLOG("password verification failed for '%s'", un);
            result = retval;
            goto cleanup_1;
        }

        retval = pam_set_item(pamh, PAM_OLDAUTHTOK, (const void *)pwd);
        if (retval != PAM_SUCCESS)
            SYSLOG("failed to set PAM_OLDAUTHTOK!");
        result = retval;
        goto cleanup_1;

    } else if (flags & PAM_UPDATE_AUTHTOK) {

        pwd = new_pwd = NULL;

        retval = pam_get_item(pamh, PAM_OLDAUTHTOK, (const void **) &pwd);
        if (retval != PAM_SUCCESS) {
            SYSLOG("could not retrieve old token");
            result = retval;
            goto cleanup_1;
        }

        retval = auth_verify_password(un, pwd, options);
        if (retval != PAM_SUCCESS) {
            SYSLOG("[%s] user '%s' not authenticated.", pam_get_service(pamh), un);
            result = retval;
            goto cleanup_1;
        }

        /* get and confirm the new passwords */
        retval = pam_get_confirm_pass(pamh, &new_pwd, PASSWORD_PROMPT_NEW,
                                      PASSWORD_PROMPT_CONFIRM, std_flags);
        if (retval != PAM_SUCCESS) {
            SYSLOG("could not retrieve new authentication tokens");
            result = retval;
            goto cleanup_1;
        }

        /* save the new password for subsequently stacked modules */
        retval = pam_set_item(pamh, PAM_AUTHTOK, (const void *)new_pwd);
        if (retval != PAM_SUCCESS) {
            SYSLOG("failed to set PAM_AUTHTOK!");
            result = retval;
            goto cleanup_1;
        }

        /* update the database */
        if (!(new_pwd_crypt = encrypt_password(options, new_pwd))) {
            DBGLOG("passwd encrypt failed");
            result = PAM_BUF_ERR;
            goto cleanup_1;
        }

        if(!(sdb = pam_sqlite_connect(options, SQLITE_OPEN_READWRITE))) {
            result = PAM_AUTHINFO_UNAVAIL;
            goto cleanup_2;
        }

        query = format_query(options->sql_set_passwd ? options->sql_set_passwd :
                "UPDATE %Ot SET %Op='%P' WHERE %Ou='%U'",
                options, un, new_pwd_crypt);
        DBGLOG("query: %s", query);

        retval = sqlite3_exec(sdb, query, NULL, NULL, &errtext);

        if (retval != SQLITE_OK) {
            DBGLOG("query failed[%d]: %s", retval, errtext);
            result = PAM_AUTH_ERR;
            goto cleanup_3;
        }
        /* if we get here, we must have succeeded */
    }

    result = PAM_SUCCESS;
    SYSLOG("[%s] password for '%s' was changed.\n",
            pam_get_service(pamh), un);

cleanup_3:
    free(query);
    sqlite3_free(errtext);
    sqlite3_close(sdb);

cleanup_2:
    free(new_pwd_crypt);

cleanup_1:
    free_module_options(options);
    return result;
}

/* public: just succeed. */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,
                              int flags,
                              int argc,
                              const char **argv)
{
    return PAM_SUCCESS;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
