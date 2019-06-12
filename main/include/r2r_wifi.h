
EventGroupHandle_t wifi_evt_handler_get(void);
void wifi_begin(wifi_mode_t mode, void* event);
void r2r_wifi_init(char* ssid_sta,char* pswd_sta, char* ssid_ap,char* pswd_ap);
wifi_mode_t get_mode();
uint8_t* get_mac();
tcpip_adapter_ip_info_t* get_ip_info();