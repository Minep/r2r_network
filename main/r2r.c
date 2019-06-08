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
const size_t INT8T_SIZE = sizeof(uint8_t);

uint8_t* expanded_key;
void r2r_init()
{
    expanded_key = aes_init(SESSION_KEY_LEN);
}

uint8_t* create_packet(header_transport t_header,header_encryption e_header,
                    header_session s_header, r2r_body body, uint8_t *data, size_t data_size)
{
    uint8_t* buffer = malloc(h_trans_size + h_enc_size + h_sess_size + h_body + data_size);
    uint8_t* plain_text = malloc(h_sess_size + h_body + data_size);
    uint8_t* cipher_text = malloc(h_sess_size + h_body + data_size);
    uint8_t* session_key = s_header.r2r_session_key;

    memcpy(plain_text, &s_header, h_sess_size);
    memcpy(plain_text + h_sess_size, &body, h_body);
    memcpy(plain_text + (h_sess_size + h_body), data, data_size);

    aes_key_expansion(session_key,expanded_key);
    aes_cipher(plain_text, cipher_text, expanded_key);

    e_header.fnv32_checksum = fnv1a_hash(cipher_text);

    memcpy(buffer,&t_header,h_trans_size);
    memcpy(buffer + h_trans_size, &e_header, h_enc_size);
    memcpy(buffer + (h_trans_size + h_enc_size), cipher_text, h_sess_size + h_body + data_size);
    free(cipher_text);
    free(plain_text);
    return buffer;
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
                uint8_t *session_key, header_session **s_header, r2r_body **r2rbody, 
                uint8_t **annex_data)
{
    size_t sealed_size = pkt_size - (h_trans_size + h_enc_size);
    size_t data_size = sealed_size - (h_sess_size + h_body);
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
    uint8_t *body = malloc(h_body);
    uint8_t *data = malloc(data_size);
    memcpy(session,plaintext,h_sess_size);
    memcpy(body,plaintext + h_sess_size,h_sess_size);
    memcpy(data,plaintext + (h_sess_size + h_body), data_size);
    *s_header = (header_session*)session;
    *r2rbody = (r2r_body*)body;
    *annex_data = data;
}