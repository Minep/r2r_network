#define INFOTAG_PKTTYPE_MASK 0x20
#define INFOTAG_PRORITY_MASK 0x18
#define INFOTAG_CHLTYPE_MASK 0x07

#define ENCTAG_MASK 0x80

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

#define NEED_NEGOTIATION 0xff
#define NEGOTIATED 0x00

#define SESSION_KEY_LEN 128

#define PKTTYPE_BITS 5
#define PRORITY_BITS 3
#define CHLTYPE_BITS 0
/*
#define PKTTYPE(tag,pkt_type) (tag & (~INFOTAG_PKTTYPE_MASK)) | pkt_type << 5
#define PRORITY(tag,prority)  (tag & (~INFOTAG_PRORITY_MASK)) | prority << 3
#define CHLTYPE(tag,chl_type) (tag & (~INFOTAG_CHLTYPE_MASK)) | chl_type

#define PKTTYPE_GET(tag) (tag & INFOTAG_PKTTYPE_MASK) >> 5
#define PRORITY_GET(tag) (tag & INFOTAG_PRORITY_MASK) >> 3
#define CHLTYPE_GET(tag) (tag & INFOTAG_CHLTYPE_MASK)
*/

#define SET_TAG(tag,value,mask,shift_bits) (tag & (~mask)) | value << shift_bits
#define GET_TAG(tag,mask,shift_bits) (tag & mask) >> shift_bits

typedef struct r2r_header_transport header_transport;
typedef struct r2r_header_encryption header_encryption;
typedef struct r2r_header_session header_session;
typedef struct r2r_body r2r_body;

#pragma pack(push,1)
struct r2r_header_transport{
    uint8_t info_tag;
    ip_addr_t ipv4_src;
    ip_addr_t ipv4_dest;
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
};
#pragma pack(pop)

void r2r_init();
uint8_t* create_packet(header_transport t_header,header_encryption e_header, header_session s_header, r2r_body body, uint8_t *data, size_t data_size);
void get_transport_header(uint8_t *pkt_data ,header_transport **t_header);
void get_enc_header(uint8_t *pkt_data ,header_encryption **e_header);
void get_sealed(uint8_t *pkt_data, size_t pkt_size, uint8_t enc_method, uint8_t *session_key, header_session **s_header, r2r_body **r2rbody, uint8_t **annex_data);