#include "KTest_openssh.h"
#include <assert.h>
#include <unistd.h>
 
#include "log.h"
#include "readpass.h"
#include "monitor_shared_state.h"

#include <string.h>
#include <security/pam_appl.h>
 
# define PAM_STRERROR(a,b) pam_strerror((a),(b))
# define PAM_MSG_MEMBER(msg, n, member) ((msg)[(n)]->member)
static pam_handle_t *pamh = NULL;
static char *__pam_msg = NULL;
static const char *__pampasswd = NULL;



//TODO: go back and make this record and playback
void ktest_verify_set_password(char* password){
  __pampasswd = password;
}

//TODO: go back and make this record and playback
int ktest_verify_pamh_not_null(void){
  if(pamh == NULL) return 0; 
  return 1;
}

/*
 *  PAM conversation function.
 *  There are two states this can run in.
 *
 *  INITIAL_LOGIN mode simply feeds the password from the client into
 *  PAM in response to PAM_PROMPT_ECHO_OFF, and collects output
 *  messages with into __pam_msg.  This is used during initial
 *  authentication to bypass the normal PAM password prompt.
 *
 *  OTHER mode handles PAM_PROMPT_ECHO_OFF with read_passphrase()
 *  and outputs messages to stderr. This mode is used if pam_chauthtok()
 *  is called to update expired passwords.
 */
//TODO: change strdup back to xstrdup
enum PAMSTATE pamstate = INITIAL_LOGIN;
enum PAMSTATE get_pamstate(){
  return pamstate;
}
void set_pamstate(enum PAMSTATE to){
  pamstate = to;
}
    
/*
 * PAM conversation function.
 * There are two states this can run in.
 *
 * INITIAL_LOGIN mode simply feeds the password from the client into
 * PAM in response to PAM_PROMPT_ECHO_OFF, and collects output
 * messages with into __pam_msg.  This is used during initial
 * authentication to bypass the normal PAM password prompt.
 *
 * OTHER mode handles PAM_PROMPT_ECHO_OFF with read_passphrase()
 * and outputs messages to stderr. This mode is used if pam_chauthtok()
 * is called to update expired passwords.
 */
static int ktest_verify_do_pam_conversation(int num_msg, const struct pam_message **msg,
    struct pam_response **resp, void *appdata_ptr)
{
    struct pam_response *reply;
    int count;
    char buf[1024];

    /* PAM will free this later */
    reply = malloc(num_msg * sizeof(*reply));
    if (reply == NULL)
        return PAM_CONV_ERR;

    for (count = 0; count < num_msg; count++) {
        if (pamstate == INITIAL_LOGIN) {
          /*
           * We can't use stdio yet, queue messages for 
           * printing later
           */
            switch(PAM_MSG_MEMBER(msg, count, msg_style)) {
            case PAM_PROMPT_ECHO_ON:
                free(reply);
                return PAM_CONV_ERR;
            case PAM_PROMPT_ECHO_OFF:
                if (__pampasswd == NULL) {
                    free(reply);
                    return PAM_CONV_ERR;
                }
                reply[count].resp = xstrdup(__pampasswd);
                reply[count].resp_retcode = PAM_SUCCESS;
                break;
            case PAM_ERROR_MSG:
            case PAM_TEXT_INFO:
                if ((*msg)[count].msg != NULL) {
                    message_cat(&__pam_msg, 
                        PAM_MSG_MEMBER(msg, count, msg));
                }
                reply[count].resp = xstrdup("");
                reply[count].resp_retcode = PAM_SUCCESS;
                break;
            default:
                free(reply);
                return PAM_CONV_ERR;
            }
        } else {
            /*
             * stdio is connected, so interact directly
             */
            switch(PAM_MSG_MEMBER(msg, count, msg_style)) {
            case PAM_PROMPT_ECHO_ON:
                fputs(PAM_MSG_MEMBER(msg, count, msg), stderr);
                fgets(buf, sizeof(buf), stdin);
                reply[count].resp = xstrdup(buf);
                reply[count].resp_retcode = PAM_SUCCESS;
                break;
            case PAM_PROMPT_ECHO_OFF:
                reply[count].resp = 
                    read_passphrase(PAM_MSG_MEMBER(msg, count,
                    msg), RP_ALLOW_STDIN);
                reply[count].resp_retcode = PAM_SUCCESS;
                break;
            case PAM_ERROR_MSG:
            case PAM_TEXT_INFO:
                if ((*msg)[count].msg != NULL)
                    fprintf(stderr, "%s\n", 
                        PAM_MSG_MEMBER(msg, count, msg));
                reply[count].resp = xstrdup("");
                reply[count].resp_retcode = PAM_SUCCESS;
                break;
            default:
                free(reply);
                return PAM_CONV_ERR;
            }
        }
    }

    *resp = reply;

    return PAM_SUCCESS;
}


/* module-local variables */
static struct pam_conv conv = {
  ktest_verify_do_pam_conversation,
  NULL
};
 

//TODO: deal with this model recording and playing back.
char* ktest_verify_pam_strerror(int ret_val){
  return pam_strerror(pamh, ret_val);
}

//Todo: record the arguements to this function in order to verify them.
//For all item_types, other than PAM_CONV and PAM_FAIL_DELAY, item is a pointer
//to a <NUL> terminated character string.
//In the case of PAM_CONV, item points to an initialized pam_conv structure. In
//the case of PAM_FAIL_DELAY, item is a function pointer: void (*delay_fn)(int
//retval, unsigned usec_delay, void *appdata_ptr)
int ktest_verify_pam_set_item(int item_type, const void *item){
  printf("ktest_verify_pam_set_item entered\n");
  if(arg_ktest_mode == KTEST_NONE){
    return pam_set_item(pamh, item_type, item);
  }

  //For all item_types, other than PAM_CONV and PAM_FAIL_DELAY, item is a pointer
  //to a <NUL> terminated character string.
  if(item_type != PAM_CONV && item_type != PAM_FAIL_DELAY){
    const char* item_str = (const char*)item;
    if (arg_ktest_mode == KTEST_RECORD){
      printf("ktest_verify_pam_set_item calling writesocket with item %s\n", item_str);
      ktest_writesocket(verification_socket, item_str, strlen(item_str)+1);
      int ret = pam_set_item(pamh, item_type, item);
      printf("ktest_verify_pam_set_item calling record_readbuf with ret %d, &ret %p, sizeof(ret) %lu\n", ret, &ret, sizeof(ret));
      ktest_record_readbuf(verification_socket, (char*)&ret, sizeof(ret));
      return ret;
    } else if (arg_ktest_mode == KTEST_PLAYBACK){
      ktest_writesocket(verification_socket, item_str, strlen(item_str)+1);
      int ret = -1;
      ktest_readsocket(verification_socket, (char*)&ret, sizeof(ret));
      return ret;
    } else {
      assert(0);
    }
  } else if (item_type == PAM_CONV){
    const char* item_str = (const char*)item;
    if (arg_ktest_mode == KTEST_RECORD){
      printf("ktest_verify_pam_set_item calling writesocket with item %s\n", item_str);
      ktest_writesocket(verification_socket, item_str, strlen(item_str)+1);
      int ret;
      if (strcmp(item_str, "conv") == 0)
        ret = pam_set_item(pamh, item_type, &conv);
      else assert(0);
      printf("ktest_verify_pam_set_item calling record_readbuf with ret %d, &ret %p, sizeof(ret) %lu\n", ret, &ret, sizeof(ret));
      ktest_record_readbuf(verification_socket, (char*)&ret, sizeof(ret));
      return ret;
    } else if (arg_ktest_mode == KTEST_PLAYBACK){
      ktest_writesocket(verification_socket, item_str, strlen(item_str)+1);
      int ret = -1;
      ktest_readsocket(verification_socket, (char*)&ret, sizeof(ret));
      return ret;
    } else {
      assert(0);
    }
  } else if (item_type != PAM_FAIL_DELAY){
    assert(0);
  }
}

//TODO: record the arguements to this function in order to verify them.
//This one will be rather challenging
int ktest_verify_pam_start(const char *service_name, const char *user){
  printf("ktest_verify_pam_start entered\n");
  if(arg_ktest_mode == KTEST_NONE){
   return pam_start(service_name, user, &conv, &pamh);
  } else if (arg_ktest_mode == KTEST_RECORD){
    printf("ktest_verify_pam_start calling writesocket with service_name %s\n", service_name);
    ktest_writesocket(verification_socket, service_name, strlen(service_name));
    printf("ktest_verify_pam_start calling writesocket with user %s\n", user);
    ktest_writesocket(verification_socket, user, strlen(user));
    int ret = pam_start(service_name, user, &conv, &pamh);
    printf("ktest_verify_pam_start calling record_readbuf with ret %d, &ret %p, sizeof(ret) %lu\n", ret, &ret, sizeof(ret));
    ktest_record_readbuf(verification_socket, (char*)&ret, sizeof(ret));
    return ret;
  } else if (arg_ktest_mode == KTEST_PLAYBACK){
    printf("ktest_verify_pam_start calling writesocket with service_name %s\n", service_name);
    ktest_writesocket(verification_socket, service_name, strlen(service_name));
    printf("ktest_verify_pam_start calling writesocket with user %s\n", user);
    ktest_writesocket(verification_socket, user, strlen(user));
    int ret = -1;
    ktest_readsocket(verification_socket, (char*)&ret, sizeof(ret));
    return ret;
  } else assert(0);
}




int ktest_verify_pam_acct_mgmt(int flags){
  printf("ktest_verify_pam_acct_mgmt entered\n");
  if(arg_ktest_mode == KTEST_NONE){
    return pam_acct_mgmt(pamh, flags);
  } else if (arg_ktest_mode == KTEST_RECORD){
    printf("ktest_verify_pam_acct_mgmt calling writesocket with flags %d, &flags %p, sizeof(flags) %lu\n", flags, &flags, sizeof(flags));
    ktest_writesocket(verification_socket, (char*)&flags, sizeof(flags));
    int ret = pam_acct_mgmt(pamh, flags);
    printf("ktest_verify_pam_acct_mgmt calling record_readbuf with ret %d, &ret %p, sizeof(ret) %lu\n", ret, &ret, sizeof(ret));
    ktest_record_readbuf(verification_socket, (char*)&ret, sizeof(ret));
    return ret;
  } else if (arg_ktest_mode == KTEST_PLAYBACK){
    ktest_writesocket(verification_socket, (char*)&flags, sizeof(flags));
    int ret = -1;
    ktest_readsocket(verification_socket, (char*)&ret, sizeof(ret));
    return ret;
  } else assert(0);
}

int ktest_verify_pam_setcred(int flags){
  printf("ktest_verify_pam_setcred entered\n");
  if(arg_ktest_mode == KTEST_NONE){
    return pam_setcred(pamh, flags);
  } else if (arg_ktest_mode == KTEST_RECORD){
    printf("ktest_verify_pam_setcred calling writesocket with flags %d, &flags %p, sizeof(flags) %lu\n", flags, &flags, sizeof(flags));
    ktest_writesocket(verification_socket, (char*)&flags, sizeof(flags));
    int ret = pam_setcred(pamh, flags);
    printf("ktest_verify_pam_setcred calling record_readbuf with ret %d, &ret %p, sizeof(ret) %lu\n", ret, &ret, sizeof(ret));
    ktest_record_readbuf(verification_socket, (char*)&ret, sizeof(ret));
   return ret;
  } else if (arg_ktest_mode == KTEST_PLAYBACK){
    ktest_writesocket(verification_socket, (char*)&flags, sizeof(flags));
   int ret = -1;
    ktest_readsocket(verification_socket, (char*)&ret, sizeof(ret));
   return ret;
  } else assert(0);
}

int ktest_verify_pam_chauthtok(int flags){
  printf("ktest_verify_pam_chauthtok entered\n");
  if(arg_ktest_mode == KTEST_NONE){
    return pam_chauthtok(pamh, flags);
  } else if (arg_ktest_mode == KTEST_RECORD){
    printf("ktest_verify_pam_chauthtok calling writesocket with flags %d, &flags %p, sizeof(flags) %lu\n", flags, &flags, sizeof(flags));
    ktest_writesocket(verification_socket, (char*)&flags, sizeof(flags));
    int ret = pam_chauthtok(pamh, flags);
    printf("ktest_verify_pam_chauthtok calling record_readbuf with ret %d, &ret %p, sizeof(ret) %lu\n", ret, &ret, sizeof(ret));
    ktest_record_readbuf(verification_socket, (char*)&ret, sizeof(ret));
    return ret;
  } else if (arg_ktest_mode == KTEST_PLAYBACK){
    ktest_writesocket(verification_socket, (char*)&flags, sizeof(flags));
    int ret = -1;
    ktest_readsocket(verification_socket, (char*)&ret, sizeof(ret));
    return ret;
  } else assert(0);
}

int ktest_verify_pam_open_session(int flags){
  printf("ktest_verify_pam_open_session entered\n");
  if(arg_ktest_mode == KTEST_NONE){
    return pam_open_session(pamh, flags);
  } else if (arg_ktest_mode == KTEST_RECORD){
    printf("ktest_verify_pam_open_session calling writesocket with flags %d, &flags %p, sizeof(flags) %lu\n", flags, &flags, sizeof(flags));
    ktest_writesocket(verification_socket, (char*)&flags, sizeof(flags));
    int ret = pam_open_session(pamh, flags);
    printf("ktest_verify_pam_open_session calling record_readbuf with ret %d, &ret %p, sizeof(ret) %lu\n", ret, &ret, sizeof(ret));
    ktest_record_readbuf(verification_socket, (char*)&ret, sizeof(ret));
    return ret;
  } else if (arg_ktest_mode == KTEST_PLAYBACK){
    ktest_writesocket(verification_socket, (char*)&flags, sizeof(flags));
    int ret = -1;
    ktest_readsocket(verification_socket, (char*)&ret, sizeof(ret));
    return ret;
  } else assert(0);
}


int ktest_verify_pam_authenticate(int flags){
  printf("ktest_verify_pam_authenticate entered\n");
  if(arg_ktest_mode == KTEST_NONE){
    return pam_authenticate(pamh, flags);
  } else if (arg_ktest_mode == KTEST_RECORD){
    printf("ktest_verify_pam_authenticate calling writesocket with flags %d, &flags %p, sizeof(flags) %lu\n", flags, &flags, sizeof(flags));
    ktest_writesocket(verification_socket, (char*)&flags, sizeof(flags));
    int ret = pam_authenticate(pamh, flags);
    printf("ktest_verify_pam_authenticate calling record_readbuf with ret %d, &ret %p, sizeof(ret) %lu\n", ret, &ret, sizeof(ret));
    ktest_record_readbuf(verification_socket, (char*)&ret, sizeof(ret));
    return ret;
  } else if (arg_ktest_mode == KTEST_PLAYBACK){
    ktest_writesocket(verification_socket, (char*)&flags, sizeof(flags));
    int ret = -1;
    ktest_readsocket(verification_socket, (char*)&ret, sizeof(ret));
    return ret;
  } else assert(0);
}

int ktest_verify_pam_close_session(int flags){
  printf("ktest_verify_pam_close_session entered\n");
  if(arg_ktest_mode == KTEST_NONE){
    return pam_end(pamh, flags);
  } else if (arg_ktest_mode == KTEST_RECORD){
    printf("ktest_verify_pam_close_session calling writesocket with flags %d, &flags %p, sizeof(flags) %lu\n", flags, &flags, sizeof(flags));
    ktest_writesocket(verification_socket, (char*)&flags, sizeof(flags));
    int ret = pam_close_session(pamh, flags);
    printf("ktest_verify_pam_close_session calling record_readbuf with ret %d, &ret %p, sizeof(ret) %lu\n", ret, &ret, sizeof(ret));
    ktest_record_readbuf(verification_socket, (char*)&ret, sizeof(ret));
    return ret;
  } else if (arg_ktest_mode == KTEST_PLAYBACK){
    ktest_writesocket(verification_socket, (char*)&flags, sizeof(flags));
    int ret = -1;
    ktest_readsocket(verification_socket, (char*)&ret, sizeof(ret));
    return ret;
  } else assert(0);
}

int ktest_verify_pam_end(int flags){
  printf("ktest_verify_pam_end entered\n");
  if(arg_ktest_mode == KTEST_NONE){
    return pam_end(pamh, flags);
  } else if (arg_ktest_mode == KTEST_RECORD){
    printf("ktest_verify_pam_end calling writesocket with flags %d, &flags %p, sizeof(flags) %lu\n", flags, &flags, sizeof(flags));
    ktest_writesocket(verification_socket, (char*)&flags, sizeof(flags));
    int ret = pam_end(pamh, flags);
    printf("ktest_verify_pam_end calling record_readbuf with ret %d, &ret %p, sizeof(ret) %lu\n", ret, &ret, sizeof(ret));
    ktest_record_readbuf(verification_socket, (char*)&ret, sizeof(ret));
    return ret;
  } else if (arg_ktest_mode == KTEST_PLAYBACK){
    ktest_writesocket(verification_socket, &flags, sizeof(flags));
    int ret = -1;
    ktest_readsocket(verification_socket, &ret, sizeof(ret));
    return ret;
  } else assert(0);
}
