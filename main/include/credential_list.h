#include <stdint.h>


#define USR_TYPE_PEERS 0x00
#define USR_TYPE_USERS 0xff


typedef struct user_credential user_credential;

struct user_credential
{
    char user_name[8];
    uint8_t password[16];
    uint8_t usr_type;
    user_credential *next;
};

void credential_list_init();
void add_new_cred(char* usr_name, uint8_t *password,uint8_t usr_type);
user_credential* find_avaliable_cred();
void delete_cred(char *user_name);
bool find_cred(char *user_name, user_credential **prev, user_credential **this_node);
bool find_cred_s(char *user_name, user_credential **cred_ptr);
void free_all_creds();
void free_all_creds_r(user_credential* base_node);
uint8_t* cred_list_to_byte(size_t *len);
void byte_to_cred_list(uint8_t *data,size_t size_of_data);