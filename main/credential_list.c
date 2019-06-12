#include <string.h>
#include "freertos/FreeRTOS.h"


#include "include/credential_list.h"


user_credential *credentials;

int current_node_count = 0;

void credential_list_init()
{
    credentials = malloc(sizeof(user_credential));
}

void add_new_cred(char* usr_name, uint8_t *password, uint8_t usr_type)
{
    user_credential* credential = malloc(sizeof(user_credential));
    memcpy(&(credential->password),password,16);
    memcpy(&(credential->user_name),usr_name,8);
    credential->next=NULL;
    if(current_node_count==0){
        memmove(credentials,credential,sizeof(user_credential));
        free(credential);
    }
    else
    {
        find_avaliable_cred()->next = credential;
    }
    current_node_count++;
}

user_credential* find_avaliable_cred()
{
    user_credential* ptr = credentials;
    while(ptr->next!=NULL){
        ptr = ptr->next;
    }
    return ptr;
}

void delete_cred(char *user_name)
{
    user_credential *this_node, *prev_node;
    if(find_cred(user_name, &prev_node, &this_node))
    {
        prev_node->next = this_node->next;
        free(this_node);
        current_node_count--;
    }
}

bool find_cred(char *user_name, user_credential **prev, user_credential **this_node)
{
    user_credential* ptr = credentials;
    user_credential* find = NULL;
    user_credential* previous = NULL;
    while(ptr->next!=NULL && find==NULL)
    {
        if(memcmp(&(ptr->user_name),user_name,8) == 0)
        {
            find = ptr;
        }
        if(find == NULL){
            previous = ptr;
        }
        ptr = ptr->next;
    }
    *this_node = ptr;
    *prev = previous;
    return find != NULL;
}

bool find_cred_s(char *user_name, user_credential **cred_ptr)
{
    user_credential* ptr = credentials;
    bool find = false;
    while(ptr->next!=NULL && !find)
    {
        find = memcmp(&(ptr->user_name),user_name,8) == 0;
        if(!find) ptr = ptr->next;
    }
    if(cred_ptr!=NULL)
    {
        *cred_ptr = ptr;
    }
    return find;
}

/*
 * 该方法将会释放 node_list 所占用的所有的空间。
 * 如果之后还想继续使用 node_list 的话，请重新调用 node_list_init 方法。
 */
void free_all_creds()
{
    free_all_creds_r(credentials);
    current_node_count=0;
}

void free_all_creds_r(user_credential* base_node)
{
    if(base_node == NULL)
    {
        return;
    }
    free_all_creds_r(base_node->next);
    free(base_node);
}

uint8_t* cred_list_to_byte(size_t *len)
{
    if(current_node_count==0){
        return NULL;
    }
    *len = sizeof(user_credential)*current_node_count;
    uint8_t* data = malloc(*len);
    int pointer_offset = 0;
    if(data == NULL)return NULL;
    user_credential *ptr = credentials;
    while(ptr->next!=NULL)
    {
        memcpy(data+pointer_offset,&(ptr->user_name),8);
        pointer_offset += 8;
        memcpy(data+pointer_offset,&(ptr->password),16);
        pointer_offset += 16;
        ptr = ptr->next;
    }
    return data;
}

void byte_to_cred_list(uint8_t *data,size_t size_of_data)
{
    if(data == NULL) return;
    char *user_name = malloc(8);
    uint8_t *password = malloc(16);
    uint8_t type = 0;
    size_t length = size_of_data;
    if(credentials==NULL){
        credential_list_init();
    }
    while(length>0)
    {
        memcpy(user_name, data + (size_of_data - length), 8);
        length -= 8;
        memcpy(password, data + (size_of_data - length), 16);
        length -= 16;
        memcpy(&type,data + (size_of_data - length), 1);
        length -= 1;
        add_new_cred(user_name,password,type);
    }
    free(user_name);
    free(password);
}