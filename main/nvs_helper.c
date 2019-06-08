#include <string.h>
#include "esp_system.h"
#include "nvs_flash.h"
#include "nvs.h"


#include "freertos/FreeRTOS.h"
#define R2R_NAMESPACE "r2rdata"

/*
   Config secured boot
   set 1 if enable
 */ 
#define SECURED_BOOT 0

nvs_handle_t nvs_handler= NULL;
void flash_init()
{
    esp_err_t status;
    #if SECURED_BOOT
    uint8_t key[32] = {0x10,0x5e,0x3a,0xf7,0xb0,0x85,0xf0,0x3d,\
                    0xfd,0xd0,0x51,0x76,0xe3,0xce,0xb8,0x03,\
                    0xa0,0xf9,0xdc,0x1e,0x44,0xe7,0xaf,0x03,\
                    0xdf,0x61,0x34,0x00,0x4d,0x85,0xd4,0x2f};
    uint8_t tkey[32]= {0xd7,0xc0,0x7b,0x0b,0xde,0xfa,0x14,0x0d,\
                    0xbd,0x0f,0x70,0xc0,0xd3,0x5e,0x3b,0x00,\
                    0x0d,0xbd,0xd4,0x0d,0x83,0x08,0x3f,0x45,\
                    0x04,0x4d,0xbb,0x0b,0xde,0x42,0xeb,0x9e};
    nvs_sec_cfg_t* seccfg = malloc(sizeof(nvs_sec_cfg_t));
    memcpy(&(seccfg->eky),&key,sizeof(key));
    memcpy(&(seccfg->tky),&tkey,sizeof(key));
    free(&key);
    free(&tkey);
    status = nvs_flash_secure_init(seccfg);
    if(status == ESP_ERR_NVS_NOT_ENOUGH_SPACE || status == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        status = nvs_flash_secure_init(seccfg);
    }
    #else
    status = nvs_flash_init();
    if(status == ESP_ERR_NVS_NOT_ENOUGH_SPACE || status == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        status = nvs_flash_init();
    }
    #endif
    ESP_ERROR_CHECK(status);
    ESP_ERROR_CHECK_WITHOUT_ABORT(nvs_open(R2R_NAMESPACE,NVS_READWRITE,&nvs_handler));
}

//TODO Add read, write, close function

esp_err_t read_data(char* key, uint8_t **out_data, size_t **length)
{
    return nvs_get_blob(nvs_handler, key, *out_data, *length);
}

esp_err_t write_data(char *key, uint8_t *data, size_t length)
{
    return nvs_set_blob(nvs_handler, key, data, length);
}

void close_nvs()
{
    nvs_close(nvs_handler);
}