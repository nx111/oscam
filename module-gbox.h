#ifndef MODULE_GBOX_H_
#define MODULE_GBOX_H_

/*
 * WARNING! Enabling this will make gbox call external programs for OSD with parameters
 * received from the network. this means that a rogue server that sends you SMS messages
 * may execute code on your machine. do not enable this unless you know what you are
 * doing and accept the posssible *BAD* consequences
*/
//#define GBOX_ENABLE_UNSAFE_EXTENDED_OSD 1

#ifdef MODULE_GBOX

#define NO_GBOX_ID			0
#define GBOX_MAXHOPS			10
#define DEFAULT_GBOX_MAX_DIST		2
#define DEFAULT_GBOX_MAX_ECM_SEND	3
#define DEFAULT_GBOX_RESHARE		5
#define DEFAULT_GBOX_RECONNECT		300
#define CS_GBOX_MAX_LOCAL_CARDS		16
#define GBOX_REBROADCAST_TIMEOUT	1250
#define GBOX_MIN_REBROADCAST_TIME	100
#define GBOX_SID_CONFIRM_TIME		3600
#define GBOX_DEFAULT_CW_TIME		500

#define MSG_ECM		0x445C
#define MSG_CW		0x4844
#define MSG_HELLO	0xDDAB
#define MSG_HELLO1	0x4849
#define MSG_CHECKCODE	0x41C0
#define MSG_GOODBYE	0x9091
#define MSG_GSMS_ACK_1	0x9098
#define MSG_GSMS_ACK_2	0x9099
#define MSG_GSMS_1	0x0FF0
#define MSG_GSMS_2	0x0FFF
#define MSG_BOXINFO	0xA0A1
#define MSG_UNKNWN	0x48F9

#define GBOX_ECM_NOT_ASKED	0
#define GBOX_ECM_SENT		1
#define GBOX_ECM_SENT_ALL	2
#define GBOX_ECM_SENT_ALL_TWICE 3
#define GBOX_ECM_ANSWERED	4

#define GBOX_CARD_TYPE_GBOX	0
#define GBOX_CARD_TYPE_LOCAL	1
#define GBOX_CARD_TYPE_BETUN	2
#define GBOX_CARD_TYPE_CCCAM	3
#define GBOX_CARD_TYPE_PROXY	4

#define FILE_GBOX_VERSION       "gbox.ver"
#define FILE_SHARED_CARDS_INFO  "share.info"
#define FILE_BACKUP_CARDS_INFO  "expired.info"
#define FILE_ATTACK_INFO        "attack.txt"
#define FILE_GBOX_PEER_ONL      "share.onl"
#define FILE_STATS              "stats.info"
#define FILE_MSG_OSD            "msg.osd"
#define FILE_LOCAL_CARDS_INFO   "sc.info"

#define	MSGID_GOODNIGHT         0
#define	MSGID_GSMS              1
#define	MSGID_GONEOFFLINE       2
#define	MSGID_COMEONLINE        3
#define	MSGID_GOODBYE           4
#define	MSGID_LOSTCONNECT       5
#define	MSGID_ATTACK            6
#define	MSGID_IPMISSMATCH       7

#define GBOX_STAT_HELLOL        0
#define GBOX_STAT_HELLOS        1
#define GBOX_STAT_HELLOR        2
#define GBOX_STAT_HELLO3        3
#define GBOX_STAT_HELLO4        4

#define GBOX_DELETE_FROM_PEER	0
#define GBOX_DELETE_WITH_ID	1
#define GBOX_DELETE_WITH_TYPE	2

#define GBOX_PEER_OFFLINE	0
#define GBOX_PEER_ONLINE	1

struct gbox_rbc_thread_args 
{
    struct s_client *cli;
    ECM_REQUEST *er;
    uint32_t waittime;
};

struct gbox_srvid
{
    uint16_t sid;
    uint32_t provid_id;
};

struct gbox_good_srvid
{
    struct gbox_srvid srvid;
    time_t last_cw_received;
};

struct gbox_bad_srvid
{
    struct gbox_srvid srvid;
    uint8_t bad_strikes;
};

struct gbox_card_id
{
    uint16_t peer;
    uint8_t slot;
};

struct gbox_card_pending
{
    struct gbox_card_id id;
    uint32_t pending_time;
};

struct gbox_card
{
    struct gbox_card_id id;
    uint32_t caprovid;
    uint8_t dist;
    uint8_t lvl;
    uint8_t type;
    LLIST *badsids; // sids that have failed to decode (struct gbox_srvid)
    LLIST *goodsids; //sids that could be decoded (struct gbox_srvid)
    uint32_t no_cws_returned;
    uint32_t average_cw_time;
    struct gbox_peer *origin_peer;
};
                    
struct gbox_data
{
    uint16_t id;
    uint32_t password;
    uint8_t minor_version;
    uint8_t cpu_api;
};

struct gbox_peer
{
    struct gbox_data gbox;
    uchar *hostname;
    uchar checkcode[7];
    int8_t online;
    uint8_t onlinestat;
    uint8_t authstat;
    uint8_t next_hello;
    uchar ecm_idx;
    CS_MUTEX_LOCK lock;
    struct s_client *my_user;
    uint16_t filtered_cards;
    uint16_t total_cards;
};

struct gbox_ecm_request_ext
{
//    uint32_t        gbox_crc;       // rcrc for gbox, used to identify ECM
//    uint16_t        gbox_ecm_id;
//    uint8_t         gbox_ecm_ok;
    uint8_t	gbox_hops;
    uint16_t	gbox_peer;
    uint16_t	gbox_mypeer;
    uint8_t	gbox_slot;
    uint8_t	gbox_version;
    uint8_t	gbox_unknown;   //byte between version and cpu info of
    uint8_t	gbox_type;
    uchar	gbox_routing_info[GBOX_MAXHOPS];  //support max 10 hops
};

char *get_gbox_tmp_fname(char *fext);
uint16_t gbox_get_local_gbox_id(void);
uint32_t gbox_get_local_gbox_password(void);
void gbox_send(struct s_client *cli, uchar *buf, int32_t l);
int8_t gbox_message_header(uchar *buf, uint16_t cmd, uint32_t peer_password, uint32_t local_password);
void gbox_free_cards_pending(ECM_REQUEST *er);
void gbox_send_good_night(void);
void gbox_send_goodbye(struct s_client *cli);
#else
static inline void gbox_free_cards_pending(ECM_REQUEST *UNUSED(er)) { }
static inline void gbox_send_good_night(void) { }
#endif

#endif
