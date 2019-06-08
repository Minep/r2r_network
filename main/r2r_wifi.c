#include <stdio.h>
#include <string.h>
#include <sys/param.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_event_loop.h"
#include "esp_wifi.h"
#include "esp_system.h"

#include "include/r2r_wifi.h"

static EventGroupHandle_t wifi_event_group;

char* SSID_STA;
char* PSWD_STA;

char* SSID_AP;
char* PSWD_AP;

wifi_config_t wifi_config_ap;
wifi_config_t wifi_config_sta;

void r2r_wifi_init(char* ssid_sta,char* pswd_sta, char* ssid_ap,char* pswd_ap)
{
    SSID_STA = ssid_sta;
    PSWD_STA = pswd_sta;
    SSID_AP = ssid_ap;
    PSWD_AP = pswd_ap;
}

EventGroupHandle_t wifi_evt_handler_get(void)
{
    return wifi_event_group;
}

void wifi_begin(wifi_mode_t mode, void* event)
{
    wifi_event_group = xEventGroupCreate();

    tcpip_adapter_init();

    ESP_ERROR_CHECK(esp_event_loop_create_default());

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    //初始化Wifi驱动
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    //注册WiFi事件
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, event, NULL));
    //注册IP事件，当ESP32获取到IP时，此事件触发
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, event, NULL));
    //设置WiFi模式。
    //有以下模式可选：
    // WIFI_MODE_APSTA
    // WIFI_MODE_AP
    // WIFI_MODE_STA
    ESP_ERROR_CHECK(esp_wifi_set_mode(mode) );

    //分配内存空间
    bzero(&wifi_config_sta,sizeof(wifi_config_t));
    bzero(&wifi_config_ap,sizeof(wifi_config_t));
    switch(mode)
    {
        //WIFI_MODE_APSTA模式是基站模式以及SoftAP模式共存。
        //也就是说，ESP32可以同时连接wifi以及发射wifi。
        //换而言之，就是一个WiFi中继
        case WIFI_MODE_APSTA:
        //纯AP模式
        case WIFI_MODE_AP:
            memcpy(&wifi_config_ap.ap.password,PSWD_AP,strlen(PSWD_AP));
            memcpy(&wifi_config_ap.ap.ssid,SSID_AP,strlen(SSID_AP));
            wifi_config_ap.ap.ssid_len = strlen(SSID_AP);
            wifi_config_ap.ap.max_connection = 20;
            wifi_config_ap.ap.authmode = WIFI_AUTH_WPA_WPA2_PSK;
            printf("Creating ap of '%s' using password '%s'\r\n",wifi_config_ap.ap.ssid,wifi_config_ap.ap.password);
            ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config_ap) );
            if(mode!=WIFI_MODE_APSTA) break;
        //基站模式
        case WIFI_MODE_STA:
            memcpy(&wifi_config_sta.sta.password,PSWD_STA,strlen(PSWD_STA));
            memcpy(&wifi_config_sta.sta.ssid,SSID_STA,strlen(SSID_STA));
            wifi_config_sta.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
            printf("Connecting to '%s' using password '%s'\r\n",wifi_config_sta.sta.ssid,wifi_config_sta.sta.password);
            ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config_sta) );
            break;
        default:
            break;
    }
    //启动WiFi驱动
    ESP_ERROR_CHECK(esp_wifi_start() );
}

void wifi_try_connect(void)
{
    esp_wifi_connect();
}

void wifi_disconnect(void)
{
    esp_wifi_disconnect();
}

void wifi_end(void)
{
    esp_wifi_disconnect();
    free(&wifi_config_ap);
    free(&wifi_config_sta);
}