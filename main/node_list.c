#include <string.h>
#include "lwip/api.h"
#include "lwip/sys.h"
#include "include/node_list.h"

r2r_node* nodes;

int current_node_count = 0;

void node_list_init()
{
    nodes = malloc(sizeof(r2r_node));
}

r2r_node* get_node_list()
{
    return nodes;
}

void add_new_node(ip_addr_t ip, uint8_t *mac_addr, uint32_t hash)
{
    r2r_node* node = malloc(sizeof(r2r_node));
    node->hash_record=hash;
    memcpy(&(node->mac_addr),mac_addr,6);
    node->ipv4_addr = ip;
    node->next=NULL;
    if(current_node_count==0){
        memmove(nodes,node,sizeof(r2r_node));
        free(node);
    }
    else
    {
        find_avaliable()->next = node;
    }
    current_node_count++;
}

r2r_node* find_avaliable()
{
    r2r_node* ptr = nodes;
    while(ptr->next!=NULL){
        ptr = ptr->next;
    }
    return ptr;
}

void delte_node(uint8_t *mac_addr)
{
    r2r_node *this_node, *prev_node;
    if(find_node(mac_addr, &prev_node, &this_node))
    {
        prev_node->next = this_node->next;
        free(this_node);
        current_node_count--;
    }
}

bool find_node(uint8_t *mac_addr, r2r_node **prev, r2r_node **this_node)
{
    r2r_node* ptr = nodes;
    r2r_node* find = NULL;
    r2r_node* previous = NULL;
    while(ptr->next!=NULL && find==NULL)
    {
        if(memcmp(&(ptr->mac_addr),mac_addr,6) == 0)
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

bool find_node_s(uint8_t *mac_addr)
{
    r2r_node* ptr = nodes;
    bool find = false;
    while(ptr->next!=NULL && !find)
    {
        find = memcmp(&(ptr->mac_addr),mac_addr,6) == 0;
        ptr = ptr->next;
    }
    return find;
}

/*
 * 该方法将会释放 node_list 所占用的所有的空间。
 * 如果之后还想继续使用 node_list 的话，请重新调用 node_list_init 方法。
 */
void free_all_node(r2r_node* base_node)
{
    if(base_node == NULL)
    {
        return;
    }
    free_all_node(base_node->next);
    free(base_node);
    current_node_count=0;
}

uint8_t* node_list_to_byte(size_t *len)
{
    if(current_node_count==0){
        return NULL;
    }
    *len = sizeof(r2r_node)*current_node_count;
    uint8_t* data = malloc(*len);
    int pointer_offset = 0;
    if(data == NULL)return NULL;
    r2r_node *ptr = nodes;
    while(ptr->next!=NULL)
    {
        memcpy(data+pointer_offset,&(ptr->mac_addr),6);
        pointer_offset += 6;
        memcpy(data+pointer_offset,&(ptr->hash_record),4);
        pointer_offset += 4;
        ptr = ptr->next;
    }
    return data;
}

void byte_to_node_list(uint8_t *data,size_t size_of_data)
{
    if(data == NULL) return;
    uint8_t *mac_addr = malloc(6);
    uint32_t *hash_record = malloc(4);
    size_t length = size_of_data;
    ip_addr_t *ip_padding = malloc(sizeof(ip_addr_t));
    memset(ip_padding,0,sizeof(ip_addr_t));
    if(nodes==NULL){
        node_list_init();
    }
    while(length>0)
    {
        memcpy(mac_addr, data + (size_of_data - length), 6);
        length -= 6;
        memcpy(hash_record, data + (size_of_data - length), 4);
        length -= 4;
        add_new_node(*ip_padding, mac_addr, *hash_record);
    }
    free(mac_addr);
    free(hash_record);
    free(ip_padding);
}