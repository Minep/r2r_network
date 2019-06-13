#define SET_LOW_VOLTAGE 0x00
#define SET_HIGHT_VOLTAGE 0x01

typedef struct
{
    uint8_t cmd;
    uint8_t *arg;
}r2r_command;