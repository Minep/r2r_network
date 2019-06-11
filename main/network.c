#include "freertos/FreeRTOS.h"

#include "lwip/udp.h"
#include "lwip/api.h"
#include "lwip/sys.h"
#include "lwip/raw.h"
#include "lwip/netbuf.h"

#include <string.h>

#include "include/r2r.h"
#include "include/network.h"

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
            uint8_t pkt_type= GET_TAG(transport_h->info_tag,INFOTAG_PKTTYPE_MASK,PKTTYPE_BITS);
            uint8_t chl_type= GET_TAG(transport_h->info_tag,INFOTAG_CHLTYPE_MASK,CHLTYPE_BITS);
            
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
            //考虑使用消息列队建立缓冲区，使得监听能够继续进行，而不用等待包处理函数的返回。
            switch (pkt_type)
            {
                case PKTTYPE_INCOMING:
                    switch (chl_type)
                    {
                        // 开始Hash的群体校验
                        case CHLTYPE_VERIF:
                            break;
                        // 对一个用户凭据进行认证
                        case CHLTYPE_AUTH:
                            break;
                        default:
                            if(pkt_incoming_func!=NULL)
                                (*pkt_incoming_func)(packet);
                            break;
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

