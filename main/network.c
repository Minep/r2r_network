#include "freertos/FreeRTOS.h"

#include "lwip/udp.h"
#include "lwip/api.h"
#include "lwip/sys.h"
#include "lwip/raw.h"
#include "lwip/netbuf.h"

#include <string.h>

#include "include/r2r.h"
#include "include/network.h"

#define PORT_R2R 8086

struct netconn *connection;



void (*pkt_local_forward_func)(pkt_b*) = NULL;
void (*pkt_incoming_func)(pkt_b*) = NULL;

void init_connection()
{
    connection = netconn_new(NETCONN_UDP);
    netconn_bind(connection,IPADDR_TYPE_ANY,8086);
}

void set_localforward_handler(void* func)
{
    pkt_local_forward_func=func;
}

void set_incoming_handler(void* func)
{
    pkt_incoming_func=func;
}

uint8_t* get_buffer_data(struct netbuf *buffer,size_t *len)
{
    size_t alloced = 2048;
    uint8_t* buf = malloc(alloced);
    uint8_t* inc_ptr = buf;
    size_t cur_size = 0;
    uint16_t size;
    do{
        if(cur_size>alloced)
        {
            realloc(buf,alloced+=1024);
        }
        inc_ptr+=cur_size;
        netbuf_data(buffer,&inc_ptr,&size);
        cur_size+=size;
    }
    while(netbuf_next(buffer)>=0);
    uint8_t* data = malloc(cur_size);
    memcpy(data,buf,cur_size);
    *len = cur_size;
    free(buf);
    return data;
}

TaskHandle_t r2r_net_listen_start()
{
    TaskHandle_t handler = NULL;
    xTaskCreate(&udp_loop,"UDP_LISTEN_LOOP_TASK",1000,NULL,1,&handler);
    return handler;
}

void udp_loop()
{
    struct netbuf *buffer;
    while(1)
    {
        if(netconn_recv(connection,&buffer) == ERR_OK)
        {
            size_t length=0;
            uint8_t* data = get_buffer_data(buffer,&length);
            header_transport *transport_h;
            get_transport_header(data,&transport_h);
            uint8_t pkt_type= GET_TAG(transport_h->info_tag,INFOTAG_PKTTYPE_MASK,PKTTYPE_BITS);
            
            pkt_b* packet = malloc(sizeof(pkt_b));
            packet->ip_address = buffer->addr;
            packet->port = buffer->port;
            packet->data = data;
            packet->transport = transport_h;
            packet->length_of_buff = length;
            switch (pkt_type)
            {
                case PKTTYPE_INCOMING:
                    if(pkt_incoming_func!=NULL){
                        (*pkt_incoming_func)(packet);
                    }
                    break;
                case PKTTYPE_FORWARD:
                    if(pkt_local_forward_func!=NULL){
                        (*pkt_local_forward_func)(packet);
                    }
                    break;
                default:
                    break;
            }            
        }
        else
        {
            continue;
        }
    }
}

err_t send_msg(void* data, size_t data_len, ip_addr_t destination)
{
    struct netbuf *buffer = netbuf_new();
    netbuf_alloc(buffer,data_len);
    memcpy(buffer->p->payload,data,data_len);
    err_t status;
    status=netconn_sendto(connection,buffer,&destination,PORT_R2R);
    netbuf_delete(buffer);
    return status;
}

