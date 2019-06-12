#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#include "freertos/FreeRTOS.h"
#include "lwip/api.h"
#include "lwip/sys.h"

#include "include/node_list.h"
#include "include/credential_list.h"
#include "include/watchdog.h"
#include "include/r2r.h"

header_auth *pending_auth_header;

/* 
 * 当凭据认证结果出来时的回调函数
 * 参数:
 *     bool arg1 : 是否通过认证
 */
void (*auth_result_updated)(bool);

/* 
 * 凭据认证状态更新回调函数
 * 参数: 
 *     uint8_t arg1 : 状态
 *     int arg2 : uncertain的值（hash不确定的节点数）
 *     int arg3 : counter的值（以通过认证的节点数）
 */
void (*auth_proccess_staus_updated)(uint8_t,int,int);

/* 指示是否需要等待hash不确定的节点返回数据 */
bool pending = false;

void call_watchdong()
{
    node_list_init();
    credential_list_init();
}

void replace_node_list(uint8_t* nodelist,size_t len)
{
    free_all_node();
    node_list_init();
    byte_to_node_list(nodelist,len);
}

void replace_cred_list(uint8_t* nodelist,size_t len)
{
    free_all_creds();
    credential_list_init();
    byte_to_node_list(nodelist,len);
}

void erase_cred_list()
{
    free_all_creds();
    credential_list_init();
}

void erase_node_list()
{
    free_all_node();
    node_list_init();
}


/* 
 * 设置当凭据认证结果出来时的回调函数
 * 回调函数参数:
 *     bool arg1 : 是否通过认证
 */
void set_auth_result_callback(void *_callback)
{
    auth_result_updated = _callback;
}

/* 
 * 设置凭据认证状态更新回调函数
 * 回调函数参数: 
 *     uint8_t arg1 : 状态
 *     int arg2 : uncertain的值（hash不确定的节点数）
 *     int arg3 : counter的值（以通过认证的节点数）
 */
void set_auth_update_callback(void *_callback)
{
    auth_proccess_staus_updated = _callback;
}

uint8_t* get_bytes(uint8_t list, size_t *len)
{
    if(list == CREDENTIAL_LIST)
    {
        return cred_list_to_byte(len);
    }
    else if(list == NODE_LIST)
    {
        return node_list_to_byte(len);
    }
    else
    {
        return NULL;
    }
    
}

void add_node(ip4_addr_t ipv4, uint8_t *mac_addr,uint32_t hash)
{
    r2r_node *found = NULL;
    if(find_node_s(mac_addr,&found))
    {
        found->ipv4_addr = ipv4;
        found->hash_record = hash;
    }
    else
    {
        add_new_node(ipv4, mac_addr, hash);
    }
}

void update_user_cred(char *user_name,char *new_usr_name,uint8_t *password, uint8_t type)
{
    user_credential *found = NULL;
    if(find_cred_s(user_name,&found))
    {
        if(password!=NULL){
            memcpy(&(found->password),password,16);
        }
        if(new_usr_name!=NULL){
            memcpy(&(found->user_name),new_usr_name,8);
        }
        if(type!=-1){
            found->usr_type = type;
        }
    }
}

void register_new_user(char *usr_name, uint8_t *password, uint8_t type)
{
    //Check whether name is existed
    if(!find_cred_s(usr_name,NULL))
    {
        add_new_cred(usr_name,password,type);
    }
}

void proceed_auth(header_auth *auth_header_, uint32_t hash_of_sender, uint64_t *access_marker)
{
    user_credential *found = NULL;
    r2r_node *found_node = NULL;
    if(find_cred_s(&(auth_header_->usr_id),&found))
    {
        if(memcmp(&(found->password),&(auth_header_->usr_pwd),16) == 0 &&
           found->usr_type == auth_header_->usr_type)
        {
            auth_header_->counter++;
        }
    }
    if(hash_of_sender != auth_header_->hash)
    {
        auth_header_->uncertain++;
        //TODO 发起群体hash认证
    }
}

/* 
 * 该方法的使用当且仅当在由该节点发出的包含header_auth的凭据认证包返回该节点时，并且access_marker里 0~N-1 位的所有字节都为1时。（N是node_list长度）
 */
void auth_completed(header_auth *auth_header_)
{
    int count = auth_header_->counter;
    int uncertain = auth_header_->uncertain;
    float ratio = count/get_node_count();
    if(uncertain==0 && ratio > 0.7)
    {
        (*auth_result_updated)(true);
    }
    else if(uncertain==0 && ratio < 0.1)
    {
        (*auth_result_updated)(false);
    }
    if(uncertain > 0)
    {
        pending = true;
        (*auth_proccess_staus_updated)(AUTH_STATUS_PENDING,count,uncertain);
    }
}

void hash_verif(header_verif *header_verif_, uint32_t hash_of_sender)
{
    if(header_verif_->hash == hash_of_sender)
    {
        header_verif_->counter++;
    }
}

void hash_verif_complete(header_verif *header_verif_)
{
    if(header_verif_->counter < get_node_count() / SELF_SHUTDOWN_THERSHOLD)
    {
        //TODO 汇报给发起认证的节点，并关闭此节点
    }
    else
    {
        //TODO 汇报给发起认证的节点。
    }
}

