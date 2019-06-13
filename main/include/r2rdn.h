
#define WIFI_SSID "Canterlot Beacon 2\0"
#define WIFI_PSWD "ZL2738--FF1725\0"
#define ESP_AP_SSID "ESP_WIFI_R2R\0"
#define ESP_AP_PSWD "ESP_WIFI_PWD\0"
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE

#define USR_CREDS_STORAGE "USR_CREDS"

void save_cred_data();
bool restore_cred_data();
void incoming_pkt_handler(pkt_b* packet);
void pkt_process_task();
void initialize();