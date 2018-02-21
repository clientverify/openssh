/* $Id: auth-pam.h,v 1.11 2001/03/27 06:12:24 djm Exp $ */

#include "includes.h"
#ifdef USE_PAM

#include <pwd.h> /* For struct passwd */

void start_pam(const char *user);
void finish_pam(void);
int auth_pam_password(struct passwd *pw, const char *password);
char **fetch_pam_environment(void);
int do_pam_authenticate(int flags);
int do_pam_account(char *username, char *remote_user);
void do_pam_session(char *username, const char *ttyname);
void do_pam_setcred(int init);
void print_pam_messages(void);
int is_pam_password_change_required(void);
void do_pam_chauthtok(void);
#ifdef CLIVER
void do_pam_set_conv(char**);
#else
void do_pam_set_conv(struct pam_conv *);
#endif
void message_cat(char **p, const char *a);

#endif /* USE_PAM */
