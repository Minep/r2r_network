
void flash_init();
esp_err_t read_data(char* key, uint8_t **out_data, size_t **length);
esp_err_t write_data(char *key, uint8_t *data, size_t length);
void close_nvs();