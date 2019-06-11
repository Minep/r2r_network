#define INFOTAG_PKTTYPE_MASK 0x20
#define INFOTAG_PRORITY_MASK 0x18
#define INFOTAG_CHLTYPE_MASK 0x07

#define R2R_OPTS_ANNEXDATA 0x00
#define R2R_OPTS_CMDS 0x01
#define R2R_OPTS_RESET 0x02
#define R2R_OPTS_REPLACE 0x03
#define R2R_OPTS_ADDNEW 0x04

#define ENCTAG_METHOD_MASK 0x02
#define ENCTAG_KEYUSED_MASK 0x01

#define PKTTYPE_FORWARD 0x00
#define PKTTYPE_INCOMING 0X01

#define PRORITY_LOW 0x00
#define PRORITY_GENERAL 0x01
#define PRORITY_EMERGENCY 0x02

#define CHLTYPE_BOARDCAST 0x00
#define CHLTYPE_VERIF 0x01
#define CHLTYPE_AUTH 0x02
#define CHLTYPE_GENERAL 0x03
#define CHLTYPE_CONFIRM 0x04

#define ENCTAG_METHOD_AES 0x00
#define ENCTAG_METHOD_DES 0x01
#define ENCTAG_KEY_USED 0x00
#define ENCTAG_KEY_UNUSED 0x01

#define NEED_NEGOTIATION 0xff
#define NEGOTIATED 0x00

#define USR_TYPE_PEERS 0x00
#define USR_TYPE_USERS 0xff

#define SESSION_KEY_LEN 128

#define PKTTYPE_BITS 5
#define PRORITY_BITS 3
#define CHLTYPE_BITS 0

#define SET_TAG(tag,value,mask,shift_bits) (tag & (~mask)) | (value << shift_bits)
#define GET_TAG(tag,mask,shift_bits) (tag & mask) >> shift_bits

#define GET_OPT(opts,field) (opts >> field) & 0x01
#define SET_OPT(opts,field,value) (opts & (~(0x01 << field))) | (value << fields)

typedef struct r2r_header_transport header_transport;
typedef struct r2r_header_encryption header_encryption;
typedef struct r2r_header_session header_session;
typedef struct auth_header header_auth;
typedef struct verif_header header_verif;
typedef struct r2r_body r2r_body;

#pragma pack(push,1)
struct r2r_header_transport{
    uint8_t info_tag;
    ip4_addr_t ipv4_src;
    ip4_addr_t ipv4_dest;
    uint8_t mac_src[6];
    uint8_t mac_dest[6];
    // Store in big endian
    uint64_t access_marker[2];
};

struct r2r_header_encryption{
    /*
     * The info tag contain header info
     * bit 0: session key used (ALWAYS SET)
     * bit 1: Enctrption method:
     *          0 : AES
     *          1 : DES
     */
    uint8_t enc_tag;
    uint32_t fnv32_checksum;
};

struct r2r_header_session{
    /*
     * 0xff : Need negotiation
     * 0x00 : Already negotiated
     */
    uint8_t need_negotiation;
    /*
     * Key for encrypt r2r message
     */
    uint8_t r2r_session_key[16];
};

struct r2r_body{
    // TODO Add body definitions
    uint8_t operations;
    uint8_t cmds[10];
    uint8_t cmd_args_offsets[10];
    uint8_t loop;
};

struct auth_header
{
    char usr_id[8];
    uint8_t usr_pwd[16];
    uint8_t usr_type;
    uint32_t hash;
    int counter;
};

struct verif_header
{
    uint32_t hash;
    int counter;
};
#pragma pack(pop)

void r2r_init();
void init_packet(uint8_t channel_type);
int add_to_packet(void *header_or_data, size_t size_of_added_content);
void deinit_packet();

//uint8_t* create_packet(header_transport t_header,uint8_t encryption_method, header_session s_header, r2r_body body, uint8_t *data, size_t data_size);

size_t get_size_allocated();
uint8_t* get_packet_created();
void get_transport_header(uint8_t *pkt_data ,header_transport **t_header);
void get_enc_header(uint8_t *pkt_data ,header_encryption **e_header);
void get_verif_header(uint8_t *data, header_verif **verif);
void get_auth_header(uint8_t *data, header_auth **auth);
void get_sealed(uint8_t *pkt_data, size_t pkt_size, uint8_t enc_method, uint8_t *session_key, header_session **s_header, uint8_t **rest_data, uint8_t *datalen);
header_transport* create_tr_header(uint8_t infotag, ip4_addr_t src_addr, ip4_addr_t dest_addr, uint8_t *mac_src, uint8_t *mac_dest, uint64_t *access_marker);