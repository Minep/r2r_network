#include <stdint.h>

typedef struct user_credential user_credential;

struct user_credential
{
    char user_name[8];
    uint8_t password[16];
    user_credential *next;
};

void add_new_node(char* usr_name, uint8_t *password);
user_credential* find_avaliable();
void delete_node(char *user_name);
bool find_node(char *user_name, user_credential **prev, user_credential **this_node);
bool find_node_s(char *user_name);
void free_all_node(user_credential* base_node);
uint8_t* node_list_to_byte(size_t *len);
void byte_to_node_list(uint8_t *data,size_t size_of_data);