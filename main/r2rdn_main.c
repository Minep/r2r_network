#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_log.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

#include "include/r2r.h"
#include "include/r2r_wifi.h"
#include "include/nvs_helper.h"
#include "include/network.h"
#include "include/utils.h"
#include "include/node_list.h"
#include "include/packet_buffer.h"


#define WIFI_SSID "Canterlot Beacon 2\0"
#define WIFI_PSWD "ZL2738--FF1725\0"
#define ESP_AP_SSID "ESP_WIFI_R2R\0"
#define ESP_AP_PSWD "ESP_WIFI_PWD\0"
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE

const int WIFI_CONNECTED_BIT = BIT0;
const int IPV6_GOTIP_BIT = BIT1;
const char* TAG = "R2R_MAIN";
const char* TAG_PKT = "R2R_PKT_PROC";

/*
static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch (event->event_id)
    {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_CONNECTED:
        printf("Connected");
        tcpip_adapter_create_ip6_linklocal(TCPIP_ADAPTER_IF_AP);
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        printf("ip: %s", ip4addr_ntoa(&event->event_info.got_ip.ip_info.ip));
        xEventGroupSetBits(wifi_evt_handler_get(), IPV4_GOTIP_BIT);
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        esp_wifi_connect();
        xEventGroupClearBits(wifi_evt_handler_get(), IPV4_GOTIP_BIT);
        xEventGroupClearBits(wifi_evt_handler_get(), IPV6_GOTIP_BIT);
        break;
    case SYSTEM_EVENT_AP_STACONNECTED:
        printf("Device connected");
        wifi_event_ap_staconnected_t* staevent = &event->event_info.sta_connected;
        printf("MAC:"MACSTR,MAC2STR(staevent->mac));
        break;
    case SYSTEM_EVENT_AP_STADISCONNECTED:
        printf("Device disconnected");
        break;
    default:
        break;
    }
    return ESP_OK;
}
*/

TaskHandle_t handler_udp_listen, handler_pkt_process;

static int s_retry_num = 0;
static void event_handler(void* arg, esp_event_base_t event_base, 
                                int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) 
    {
        esp_wifi_connect();
    } 
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) 
    {
        wifi_event_sta_disconnected_t * disconnected = (wifi_event_sta_disconnected_t*)event_data;
        if (s_retry_num < 50) 
        {
            esp_wifi_connect();
            xEventGroupClearBits(wifi_evt_handler_get(), WIFI_CONNECTED_BIT);
            s_retry_num++;
            printf("connected after %i retry\r\n",s_retry_num);
        }
        printf("Fail to connect; SSID: '%s' ; Error code: %i\r\n",disconnected->ssid,disconnected->reason);
    } 
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) 
    {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        printf("Got ip %s",ip4addr_ntoa(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(wifi_evt_handler_get(), WIFI_CONNECTED_BIT);
    }
    else if(event_base == WIFI_EVENT && event_id==WIFI_EVENT_AP_STACONNECTED)
    {
        wifi_event_ap_staconnected_t* connected = (wifi_event_ap_staconnected_t* ) event_data;
        printf("Device connected with MAC: "MACSTR" \r\n",MAC2STR(connected->mac));
    }
    else if(event_base == WIFI_EVENT && event_id==WIFI_EVENT_STA_CONNECTED)
    {
        wifi_event_sta_connected_t* connected = (wifi_event_sta_connected_t* ) event_data;
        ESP_LOGI(TAG,"Connected to %s\r\n",connected->ssid);
    }
}

void incoming_pkt_handler(pkt_b* packet)
{
    printf("\r\n");
    ESP_LOGI(TAG,"Packet recieved, from %s:%i",ipaddr_ntoa(&(packet->ip_address)),packet->port);
    ESP_LOGI(TAG,"Showing packet content, size %i bytes",packet->length_of_buff);
    print_formated_hex(packet->data,packet->length_of_buff,16);
    ESP_LOGI(TAG,"Showing transport header:");
    ESP_LOGI(TAG,"Tag info : "BYTE_TO_BINARY_PATTERN,BYTE_TO_BINARY(packet->transport->info_tag));
    ESP_LOGI(TAG,"destination ip : %s",ip4addr_ntoa(&(packet->transport->ipv4_dest)));
    ESP_LOGI(TAG,"source ip : %s",ip4addr_ntoa(&(packet->transport->ipv4_src)));
    ESP_LOGI(TAG,"source MAC : "MACSTR, MAC2STR(packet->transport->mac_src));
    ESP_LOGI(TAG,"destination MAC : "MACSTR, MAC2STR(packet->transport->mac_dest));
    //send_msg(packet->data,packet->length_of_buff,packet->ip_address);
}

void pkt_process_task()
{
    while (1)
    {
        if(get_items_count()>0)
        {
            pkt_b* packet = buffer_get();
            ESP_LOGI(TAG_PKT,"Packet fetched from buffer! remaining %i packet(s)",get_items_count());
            uint8_t chl_type= GET_TAG(packet->transport->info_tag,INFOTAG_CHLTYPE_MASK,CHLTYPE_BITS);
            switch (chl_type)
            {
                // 开始Hash的群体校验
                case CHLTYPE_VERIF:
                    break;
                // 对一个用户凭据进行认证
                case CHLTYPE_AUTH:
                    break;
                // 获取子节点发过来的身份信息
                case CHLTYPE_CONFIRM:
                
                    break;
                default:
                    incoming_pkt_handler(packet);
                    break;
            }
            free(packet->transport);
            free(packet->data);
            free(packet);
        }
        //ESP_LOGI(TAG_PKT,"Fetch the packet in buffer after 50 ms....");
        vTaskDelay(50/portTICK_PERIOD_MS);
    }
    
}

void initialize()
{
    r2r_wifi_init(WIFI_SSID,WIFI_PSWD,ESP_AP_SSID,ESP_AP_PSWD);
    wifi_begin(WIFI_MODE_STA,&event_handler);
    init_pkt_queue(10);
    r2r_init();
    init_connection();
    node_list_init();
    set_incoming_handler(&incoming_pkt_handler);

    handler_udp_listen = r2r_net_listen_start();
    xTaskCreate(&pkt_process_task,"PKT_PROCESS",5000,NULL,1,&handler_pkt_process);
}

void app_main()
{
    flash_init();
    initialize();
    ESP_LOGW(TAG,"The R2R protocol is running, port listening: %i",PORT_R2R);
}