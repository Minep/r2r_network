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
const size_t INT8T_SIZE = sizeof(uint8_t);

uint8_t *expanded_key;
uint8_t *pkt_data = NULL;
size_t current_ptr = 0;
size_t size_allocated = 0;
void r2r_init()
{
    expanded_key = aes_init(SESSION_KEY_LEN);
}

void init_packet(uint8_t channel_type)
{
    deinit_packet();
    current_ptr = 0;
    size_t size_pkt= h_trans_size + h_enc_size + h_sess_size;
    switch (channel_type)
    {
    case CHLTYPE_AUTH:
        size_pkt += h_auth_header_size;
        break;
    case CHLTYPE_VERIF:
        size_pkt += h_verif_header_size;
    default:
        size_pkt += h_body;
        break;
    }
    pkt_data = malloc(size_pkt);
    size_allocated = size_pkt;
}

int add_to_packet(void *header_or_data, size_t size_of_added_content)
{
    if(current_ptr>=size_allocated)
    {
        return -1;
    }
    memcpy(pkt_data+current_ptr,header_or_data,size_of_added_content);
    current_ptr += size_of_added_content;
    return 1;
}

void deinit_packet()
{
    if(pkt_data !=NULL)
    {
        free(pkt_data);
        pkt_data=NULL;
        current_ptr = 0;
    }
}

/*
   // THIS METHOD IS FUCKED UP
   
uint8_t* create_packet(header_transport t_header,uint8_t encryption_method,
                    header_session s_header, r2r_body body, uint8_t *data, size_t data_size)
{
    uint8_t* buffer = malloc(h_trans_size + h_enc_size + h_sess_size + h_body + data_size);
    uint8_t* plain_text = malloc(h_sess_size + h_body + data_size);
    uint8_t* cipher_text = malloc(h_sess_size + h_body + data_size);
    uint8_t* session_key = s_header.r2r_session_key;

    header_encryption *e_header = malloc(h_enc_size);

    memcpy(plain_text, &s_header, h_sess_size);
    memcpy(plain_text + h_sess_size, &body, h_body);
    memcpy(plain_text + (h_sess_size + h_body), data, data_size);

    aes_key_expansion(session_key,expanded_key);
    aes_cipher(plain_text, cipher_text, expanded_key);

    e_header->fnv32_checksum = fnv1a_hash(cipher_text);
    e_header->enc_tag = e_header->enc_tag | encryption_method;

    memcpy(buffer,&t_header,h_trans_size);
    memcpy(buffer + h_trans_size, e_header, h_enc_size);
    memcpy(buffer + (h_trans_size + h_enc_size), cipher_text, h_sess_size + h_body + data_size);
    free(cipher_text);
    free(plain_text);
    return buffer;
}
 */

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
                        uint8_t *mac_src, uint8_t *mac_dest, uint64_t *access_marker)
{
    header_transport* tr_header = malloc(h_trans_size);
    tr_header->info_tag = infotag;
    tr_header->ipv4_src = src_addr;
    tr_header->ipv4_dest = dest_addr;
    memcpy(&(tr_header->mac_dest),mac_dest,6);
    memcpy(&(tr_header->mac_src),mac_src,6);
    memcpy(&(tr_header->access_marker),access_marker,16);
    return tr_header;
}

