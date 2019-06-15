#define GPIO_LOW 0
#define GPIO_HIGH 1
#define ESP_INTR_FLAG_DEFAULT 0

void init_gpio(void *signal_callback);
bool set_mode(uint8_t pin_number,gpio_mode_t mode, bool bind_to_interrupt, uint8_t trig_intr_voltage);
bool set_level(uint8_t pin, uint8_t level);
uint8_t get_level(uint8_t pin);
void start_intr_handler();