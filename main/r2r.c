#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"

#include "freertos/FreeRTOS.h"
#include "esp_system.h"

#include <lwip/netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>

#include "include/r2r.h"
#include "include/aes.h"
#include "include/utils.h"

const size_t h_trans_size = sizeof(header_transport);
const size_t h_enc_size = sizeof(header_encryption);
const size_t h_sess_size = sizeof(header_session);
const size_t h_body = sizeof(r2r_body);
const size_t h_auth_header_size = sizeof(header_auth);
const size_t h_verif_header_size = sizeof(header_verif);

uint8_t *expanded_key;
uint8_t *pkt_data = NULL;
size_t current_ptr = 0;
size_t size_allocated = 0;
bool prepared = false;

uint8_t *session_key = NULL;

void r2r_init()
{
    expanded_key = aes_init(SESSION_KEY_LEN);
}

void init_packet(uint8_t channel_type)
{
    deinit_packet();
    current_ptr = 0;
    size_t size_pkt= h_trans_size + h_enc_size + h_sess_size;
    if(channel_type == CHLTYPE_CONFIRM)
    {
        size_pkt = h_trans_size + sizeof(uint32_t);
    }
    else
    {
        switch (channel_type)
        {
            case CHLTYPE_AUTH:
                size_pkt += h_auth_header_size;
                break;
            case CHLTYPE_VERIF:
                size_pkt += h_verif_header_size;
                break;
            case CHLTYPE_KEY_SYNCING:
                break;
            default:
                size_pkt += h_body;
                break;
        }
    }
    pkt_data = malloc(size_pkt);
    memset(pkt_data,0,size_pkt);
    size_allocated = size_pkt;
}

int seek(size_t h_offset)
{
    if(h_offset>size_allocated) return -1;
    current_ptr = h_offset;
    return 1;
}

int write_content(void *content, size_t size_of_added_content)
{
    if(current_ptr + size_of_added_content >= size_allocated)
    {
        pkt_data = realloc(pkt_data,current_ptr+size_of_added_content);
        size_allocated = current_ptr + size_of_added_content;
    }
    memcpy(pkt_data+current_ptr,content,size_of_added_content);
    current_ptr += size_of_added_content;
    return 1;
}

void prepare_packet(bool encryption, uint8_t *replaced_key)
{
    header_transport *htr = malloc(h_trans_size);
    memcpy(htr,pkt_data,h_trans_size);
    htr->pkt_size = size_allocated;
    printf("size allocated : %i\r\n",htr->pkt_size);
    memcpy(pkt_data,htr,h_trans_size);
    free(htr);

    if(prepared) return;
    if((session_key == NULL || replaced_key == NULL) && encryption){
        prepared=true;
        return;
    }
    size_t plaintxt_size = size_allocated - (h_trans_size + h_enc_size);
    uint8_t *cipher = malloc(plaintxt_size);
    uint8_t *plain = malloc(plaintxt_size);
    header_encryption *henc = malloc(h_enc_size);
    memcpy(henc,pkt_data+h_trans_size,h_enc_size);
    memcpy(plain, pkt_data + size_allocated - plaintxt_size, plaintxt_size);

    if(GET_TAG(henc->enc_tag,ENCTAG_METHOD_MASK,1) == ENCTAG_METHOD_AES)
    {
        if(encryption)
        {
            aes_key_expansion(session_key,expanded_key);
            aes_cipher(plain,cipher,expanded_key);
            memcpy(pkt_data + size_allocated - plaintxt_size,cipher,plaintxt_size);
        }
        henc->fnv32_checksum = fnv1a_hash(cipher);
        prepared = true;
    }
    else if(GET_TAG(henc->enc_tag,ENCTAG_METHOD_MASK,1) == ENCTAG_METHOD_DES)
    {
        // TODO DES method

        /* 
         * memcpy(pkt_data + size_allocated - plaintxt_size,cipher,plaintxt_size);
         * henc->fnv32_checksum = fnv1a_hash(cipher);
         * prepared = true;
         */
    }
    memcpy(pkt_data + h_trans_size,henc,h_enc_size);
    free(plain);
    free(cipher); 
    free(henc);
    print_formated_hex(pkt_data,size_allocated,16);
}

uint8_t* get_packet()
{
    return pkt_data;
}

size_t get_packet_size()
{
    return size_allocated;
}
/* 创建完包之后必须调用 */
void deinit_packet()
{
    if(pkt_data !=NULL)
    {
        free(pkt_data);
        pkt_data=NULL;
        prepared=false;
        size_allocated = 0;
        current_ptr = 0;
    }
}

void set_session_key(uint8_t *key)
{
    session_key = key;
}

uint8_t* get_session_key()
{
    return session_key;
}

size_t get_size_allocated()
{
    return size_allocated;
}

uint8_t* get_packet_created()
{
    return pkt_data;
}

void get_transport_header(uint8_t *pkt_data ,header_transport **t_header)
{
    uint8_t *header = malloc(h_trans_size);
    memcpy(header,pkt_data,h_trans_size);
    *t_header = (header_transport*)header;
}

void get_enc_header(uint8_t *pkt_data ,header_encryption **e_header)
{
    uint8_t *header = malloc(h_enc_size);
    memcpy(header,pkt_data+h_trans_size,h_trans_size);
    *e_header = (header_encryption*)header;
}

void get_sealed(uint8_t *pkt_data, size_t pkt_size, uint8_t enc_method, 
                uint8_t *session_key, header_session **s_header, 
                uint8_t **rest_data, uint8_t *datalen)
{
    size_t sealed_size = pkt_size - (h_trans_size + h_enc_size);

    //rest_size 指的是 r2r_header/verif_header/auth_header和(或)annex_data的大小。
    size_t rest_size = sealed_size - h_sess_size;
    uint8_t *ciphertext = malloc(sealed_size);
    uint8_t *plaintext = malloc(sealed_size);
    memcpy(ciphertext,pkt_data + (h_trans_size + h_enc_size), sealed_size);
    if(enc_method == ENCTAG_METHOD_AES)
    {
        aes_key_expansion(session_key,expanded_key);
        aes_inv_cipher(ciphertext, plaintext, expanded_key);
    }
    else
    {
        // TODO DES method
    }
    free(ciphertext);
    uint8_t *session = malloc(h_sess_size);
    uint8_t *rest = malloc(rest_size);
    memcpy(session,plaintext,h_sess_size);
    memcpy(rest,plaintext + h_sess_size, rest_size);
    *s_header = (header_session*)session;
    *rest_data = rest;
    *datalen = rest_size;
}

void get_auth_header(uint8_t *data, header_auth **auth)
{
    header_auth *hauth = malloc(h_auth_header_size);
    memcpy(hauth,data,h_auth_header_size);
    *auth = hauth;
}

void get_verif_header(uint8_t *data, header_verif **verif)
{
    header_verif *hverif = malloc(h_verif_header_size);
    memcpy(hverif, data, h_verif_header_size);
    *verif = hverif;
}


header_transport* create_tr_header(uint8_t infotag, ip4_addr_t src_addr, ip4_addr_t dest_addr,
                        uint8_t *mac_src, uint8_t *mac_dest)
{
    header_transport* tr_header = calloc(h_trans_size,1);
    tr_header->info_tag = infotag;
    tr_header->ipv4_src = src_addr;
    tr_header->ipv4_dest = dest_addr;
    memcpy(&(tr_header->mac_src),mac_src,6);
    if(mac_dest == NULL)
    {
        memset(&(tr_header->mac_dest),0,6);
    }
    else
    {
        memcpy(&(tr_header->mac_dest),mac_dest,6);
    }  
    memset(&(tr_header->access_marker),0,16);
    return tr_header;
}

header_encryption* create_enc_header(uint8_t enc_method)
{
    uint8_t tag = SET_TAG(0x01,enc_method,ENCTAG_METHOD_MASK,1);
    if(session_key == NULL){
        tag = SET_TAG(tag,0x00,ENCTAG_KEYUSED_MASK,0);
    }
    header_encryption *henc = malloc(h_enc_size);
    henc->enc_tag = tag;
    return henc;
}

header_session* create_ses_header(bool need_negotiate_key)
{
    header_session *hses = malloc(h_sess_size);
    hses->need_negotiation = need_negotiate_key ? 0xff : 0x00;
    if(session_key==NULL)
    {
        memset(&(hses->r2r_session_key),0,SESSION_KEY_LEN);
    }
    else
    {
        memcpy(&(hses->r2r_session_key),session_key,SESSION_KEY_LEN);
    }
    return hses;
}

r2r_body* create_r2r_body(uint8_t opts, r2r_command *cmds, bool need_loop, int cmd_num)
{
    r2r_body *rbody = malloc(h_body);
    if(cmds!=NULL && cmd_num!=0)
    {
        //TODO Arrange the commands and their args in to ordered binary
    }
    rbody->operations = opts;
    rbody->loop = need_loop ? 0xff : 0x00;
    return rbody;
}

uint32_t retrive_hash(uint8_t* data)
{
    uint32_t hash=0;
    memcpy(&hash,data+h_trans_size,4);
    return hash;
}

