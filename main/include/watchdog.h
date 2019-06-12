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