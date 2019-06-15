#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0') 

uint32_t fnv1a_hash(const unsigned char* cp);
void print_formated_hex(uint8_t* data, size_t len, int max_col);
char *int2bin(uint8_t a, char *buffer, int buf_size);
//获取本设备的hash码
uint32_t get_local_hash();
uint8_t* generate_session_key();
uint8_t generate_rand();