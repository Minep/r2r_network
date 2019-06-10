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


#define WIFI_SSID "Canterlot Beacon 2\0"
#define WIFI_PSWD "ZL2738--FF1725\0"
#define ESP_AP_SSID "ESP_WIFI_R2R\0"
#define ESP_AP_PSWD "ESP_WIFI_PWD\0"
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE

const int WIFI_CONNECTED_BIT = BIT0;
const int IPV6_GOTIP_BIT = BIT1;
const char* TAG = "R2R_MAIN";
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
    send_msg(packet->data,packet->length_of_buff,packet->ip_address);
}

void initialize()
{
    TaskHandle_t handler;
    r2r_init();
    init_connection();
    set_incoming_handler(&incoming_pkt_handler);
    handler = r2r_net_listen_start();
}

void app_main()
{
    flash_init();
    r2r_wifi_init(WIFI_SSID,WIFI_PSWD,ESP_AP_SSID,ESP_AP_PSWD);
    wifi_begin(WIFI_MODE_STA,&event_handler);
    initialize();
    ESP_LOGW(TAG,"The R2R protocol is running, port listening: %i",PORT_R2R);
}