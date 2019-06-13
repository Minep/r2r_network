
typedef struct r2r_node_record r2r_node;

struct r2r_node_record
{
    ip4_addr_t ipv4_addr;
    uint8_t mac_addr[6];
    uint32_t hash_record;
    r2r_node* next;
};
void node_list_init();
r2r_node* get_node_list();
void add_new_node(ip4_addr_t ip, uint8_t *mac_addr, uint32_t hash);
r2r_node* find_avaliable_node();
void delete_node(uint8_t *mac_addr);
bool find_node(uint8_t *mac_addr, r2r_node **prev, r2r_node **this_node);
bool find_node_s(uint8_t *mac_addr, r2r_node **node_ptr);
void free_all_node();
void tranverse_nodes(void (*task)(r2r_node*));
uint8_t* node_list_to_byte(size_t *len);
void byte_to_node_list(uint8_t *data,size_t size_of_data);
int get_node_count();
