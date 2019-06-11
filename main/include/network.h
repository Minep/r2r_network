#define PORT_R2R 8086

typedef struct netbuf netbuf;
typedef struct netconn netconn;

/* A packet block */
typedef struct pkt_b{
    ip_addr_t ip_address;
    uint16_t port;
    header_transport* transport;
    uint8_t* data;
    size_t length_of_buff;
}pkt_b;

void init_connection();
void set_localforward_handler(void* func);
void set_incoming_handler(void* func);
uint8_t* get_buffer_data(struct netbuf *buffer,size_t *len);
TaskHandle_t r2r_net_listen_start();
void udp_loop();
err_t send_msg(void* data, size_t data_len, ip_addr_t destination);
