
#define CREDENTIAL_LIST 0
#define NODE_LIST 1
/* 当小于1/SELF_SHUTDOWN_THERSHOLD的节点不认可该节点的hash时，该节点会自闭 */
#define SELF_SHUTDOWN_THERSHOLD 4

/*
 * 等待凭据认证包的返回
 */
#define AUTH_STATUS_PENDING 0x00
/*
 * 等待hash不确定的节点返回结果
 */
#define AUTH_STATUS_WAITING_FOR_UNCERTAIN 0X01
/*
 * 某个hash不确定的节点返回了结果
 */
#define AUTH_STATUS_UNCERTAIN_RESPONDED 0x02


void call_watchdog();
void replace_node_list(uint8_t* nodelist,size_t len);
void replace_cred_list(uint8_t* nodelist,size_t len);
void erase_cred_list();
void erase_node_list();
void set_auth_result_callback(void *_callback);
void set_auth_update_callback(void *_callback);
uint8_t* get_bytes(uint8_t list, size_t *len);
void set_bytes(uint8_t list, uint8_t* data, size_t len);
void add_node(ip4_addr_t ipv4, uint8_t *mac_addr,uint32_t hash);
void update_user_cred(char *user_name,char *new_usr_name,char *password, uint8_t type);
void register_new_user(char *usr_name, char *password, uint8_t type);
void proceed_auth(header_auth *auth_header_, uint32_t hash_of_sender, uint64_t *access_marker);
void auth_completed(header_auth *auth_header_);
void hash_verif(header_verif *header_verif_, uint32_t hash_of_sender);
void hash_verif_complete(header_verif *header_verif_);
void notify_all_nodes(err_t (*_msg_sender)(uint8_t*,size_t,ip4_addr_t),ip4_addr_t localIP, uint8_t *localmac);