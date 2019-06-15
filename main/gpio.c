#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

#include "include/gpio_helper.h"

gpio_config_t *gpio_cfg;

static xQueueHandle gpio_evt_queue = NULL;

void (*gpio_signal_receive)(uint8_t);

static void IRAM_ATTR gpio_isr_handler(void* arg)
{
    uint8_t gpio_num = (uint8_t) arg;
    xQueueSendFromISR(gpio_evt_queue, &gpio_num, NULL);
}

static void intr_handler()
{
    uint8_t io_num;
    while(1) {
        if(xQueueReceive(gpio_evt_queue, &io_num, portMAX_DELAY)) {
            if(gpio_signal_receive == NULL)
            {
                (*gpio_signal_receive)(io_num);
            }
        }
    }
}

void init_gpio(void *signal_callback)
{
    gpio_cfg = calloc(sizeof(gpio_config_t),1);
    gpio_install_isr_service(ESP_INTR_FLAG_DEFAULT);
    gpio_signal_receive = signal_callback;
}

void start_intr_handler()
{
    xTaskCreate(&intr_handler,"GPIO_INTR_HANDLER",4096,NULL,10,NULL);
}

bool set_mode(uint8_t pin_number,gpio_mode_t mode, bool bind_to_interrupt, uint8_t trig_intr_voltage)
{
    gpio_cfg->mode = mode;
    gpio_cfg->pin_bit_mask = (1ull << pin_number);
    if(mode == GPIO_MODE_INPUT)
    {
        gpio_cfg->intr_type = 1;
        gpio_cfg->pull_down_en = 1;
        gpio_cfg->pull_up_en = 0;
        if(bind_to_interrupt)
        {
            gpio_int_type_t type = trig_intr_voltage == -1 ? GPIO_INTR_ANYEDGE : (trig_intr_voltage == 0 ? GPIO_INTR_LOW_LEVEL : GPIO_INTR_HIGH_LEVEL);
            gpio_set_intr_type(pin_number,type);
            gpio_isr_handler_add(pin_number, gpio_isr_handler, (void*) pin_number);
        }
    }
    else
    {
        gpio_cfg->intr_type = 0;
        gpio_cfg->pull_down_en = 0;
        gpio_cfg->pull_up_en = 0;
    }
    return gpio_config(gpio_cfg) == ESP_OK;
}

bool set_level(uint8_t pin, uint8_t level)
{
    if(level !=0 && level != 1) return false;
    printf("Set pin %i output level to %i\r\n",pin,level);
    return gpio_set_level(pin,level) == ESP_OK;
}

uint8_t get_level(uint8_t pin)
{
    return gpio_get_level(pin);
}