#include "freertos/FreeRTOS.h"

#include "lwip/udp.h"
#include "lwip/api.h"
#include "lwip/sys.h"
#include "lwip/raw.h"
#include "lwip/netbuf.h"

#include <string.h>

#include "include/r2r.h"
#include "include/network.h"
#include "include/packet_buffer.h"

#define ENTERPRISE_OPT 1

netconn *connection;



void (*pkt_local_forward_func)(pkt_b*) = NULL;
void (*pkt_incoming_func)(pkt_b*) = NULL;

void init_connection()
{
    connection = netconn_new(NETCONN_UDP);
    netconn_bind(connection,NULL,8086);
}

void set_localforward_handler(void* func)
{
    pkt_local_forward_func=func;
}

void set_incoming_handler(void* func)
{
    pkt_incoming_func=func;
}

uint8_t* get_buffer_data(netbuf *buffer,size_t *len)
{
    size_t alloced = 1048;
    uint8_t* buf = malloc(alloced);
    //uint8_t* inc_ptr = buf;
    size_t cur_size = 0;
    uint16_t size = 0;
    netbuf_first(buffer);
    do{
        char* data_buf;
        if(cur_size>alloced)
        {
            realloc(buf,alloced+=1024);
        }
        netbuf_data(buffer,(void*)&data_buf,&size);
        memcpy(buf+cur_size,data_buf,size);
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
    xTaskCreate(&udp_loop,"UDP_LISTEN_LOOP_TASK",5000,NULL,1,&handler);
    return handler;
}

void udp_loop()
{
    netbuf *buffer;
    while(1)
    {
        if(netconn_recv(connection,&buffer) == ERR_OK)
        {
            size_t length=0;
            uint8_t* data = get_buffer_data(buffer,&length);
            header_transport *transport_h;
            get_transport_header(data,&transport_h);
            
            pkt_b* packet = malloc(sizeof(pkt_b));
            packet->ip_address = buffer->addr;
            packet->port = buffer->port;
            packet->data = data;
            packet->transport = transport_h;
            packet->length_of_buff = length;
            netbuf_free(buffer);
            /*
                现在有一个问题，我们如何将密钥共享给新加入网络的节点？
                解决方法：
                    管理员登陆网络，对新加入的设备在credential_list中注册，注册完成后，
                    新的节点按照用户加入R2R网络中的那样的认证流程来认证，获取共享的密钥。
                当然，时间有限，所以上述问题暂不考虑，即忽略节点的认证。只考虑用户的认证。
             */
            //这里，以后可以搞收费的企业版，可以得到显著的速度提升。
#if ENTERPRISE_OPT == 0
            vTaskDelay(8000 / portTICK_PERIOD_MS);
#endif
            buffer_add(*packet);
            free(packet);
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

