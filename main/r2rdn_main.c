#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "driver/gpio.h"

#include "lwip/err.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

#include "include/r2r.h"
#include "include/r2r_wifi.h"
#include "include/nvs_helper.h"
#include "include/network.h"
#include "include/utils.h"
#include "include/node_list.h"
#include "include/packet_buffer.h"
#include "include/watchdog.h"
#include "include/r2rdn.h"
#include "include/gpio_helper.h"

const int WIFI_CONNECTED_BIT = BIT0;
const int IPV6_GOTIP_BIT = BIT1;
const char* TAG = "R2R_MAIN";
const char* TAG_PKT = "R2R_PKT_PROC";

TaskHandle_t handler_udp_listen, handler_pkt_process;

static int s_retry_num = 0;

void app_main()
{
    flash_init();
    initialize();
    set_level(18,GPIO_HIGH);
    vTaskDelay(1000/portTICK_PERIOD_MS);
    set_level(18,GPIO_LOW);
    ESP_LOGW(TAG,"The R2R protocol is running, port listening: %i",PORT_R2R);
}

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
                    if(find_node_s(packet->transport->mac_src,NULL))
                    {
                        header_auth *ah = malloc(sizeof(header_auth));
                        memcpy(ah,packet->data+sizeof(header_transport),sizeof(header_auth));
                        ESP_LOGD(TAG,"Credential recieved from %s",ipaddr_ntoa(&(packet->ip_address)));
                        ESP_LOGD(TAG,"User Name: %s",ah->usr_id);
                        ESP_LOGD(TAG,"Password: %s",ah->usr_pwd);
                        ESP_LOGD(TAG,"User Type: 0x%02x",ah->usr_type);
                        if(verif_cred(&(ah->usr_id),&(ah->usr_pwd),ah->usr_type))
                        {
                            ESP_LOGI(TAG,"Verification sucessed");
                            ESP_LOGI(TAG,"Sharing session key");
                            ESP_LOGI(TAG,"Session Key : ");
                            print_formated_hex(get_session_key(),32,16);
                            //tcpip_adapter_ip_info_t *ipinfo = get_ip_info();
                            //sync_route_table(&send_msg,ipinfo->ip,get_mac(),true,packet->transport->ipv4_src);
                            tcpip_adapter_ip_info_t *ipinfo = get_ip_info();
                            sync_session_key(&send_msg,get_session_key(),ipinfo->ip,get_mac(),false,&(packet->transport->ipv4_src));
                        }
                        else
                        {
                            ESP_LOGI(TAG,"Verification fail");
                            //ESP_LOGI(TAG,"Sharing session key");
                        }
                    }
                    break;
                // 获取子节点发过来的身份信息
                case CHLTYPE_CONFIRM :
                    {
                        uint32_t hash = 0;
                        hash = retrive_hash(packet->data);
                        if(!find_node_s(packet->transport->mac_src,NULL))
                        {
                            add_node(packet->transport->ipv4_src,packet->transport->mac_src,hash);
                            // Notify other nodes
                            tcpip_adapter_ip_info_t *ipinfo = get_ip_info();
                            sync_route_table(&send_msg,ipinfo->ip,get_mac(),true,NULL);              
                        }
                    }
                    break;
                // 会话密钥同步
                case CHLTYPE_KEY_SYNCING:
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
    wifi_begin(WIFI_MODE_AP,&event_handler);
    
    init_gpio(NULL);
    set_mode(18, GPIO_MODE_OUTPUT,false,0);

    init_pkt_queue(10);
    r2r_init();
    set_session_key(generate_session_key());
    init_connection();
    call_watchdog();

    handler_udp_listen = r2r_net_listen_start();
    xTaskCreate(&pkt_process_task,"PKT_PROCESS",4096,NULL,1,&handler_pkt_process);
    
    register_new_user("rpby001","raspberry_pwd_+",USR_TYPE_PEERS);
    //register_new_user("minep","mypwd00000000",USR_TYPE_USERS);
    //register_new_user("shuozi","mypwd00000000",USR_TYPE_USERS);
    //if(!restore_cred_data())
    //{
        
        //save_cred_data();
    //}
}

void save_cred_data()
{
    size_t size = 0;
    uint8_t *cred_data = get_bytes(CREDENTIAL_LIST,&size);
    write_data(USR_CREDS_STORAGE,cred_data,size);
    free(cred_data);
}

bool restore_cred_data()
{
    uint8_t *data;
    size_t len = 0;
    if(read_data(USR_CREDS_STORAGE, &data, &len) == ERR_OK)
    {
        if(data!=NULL){
            set_bytes(CREDENTIAL_LIST,data,len);
            return true;
        }
    }
    return false;
}