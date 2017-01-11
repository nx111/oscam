#define MODULE_LOG_PREFIX "gbox"

#include "globals.h"

#ifdef MODULE_GBOX
#include "module-gbox.h"
#include "module-gbox-cards.h"
#include "module-gbox-helper.h"
#include "oscam-lock.h"
#include "oscam-garbage.h"
#include "oscam-files.h"
#include "oscam-chk.h"
#include "oscam-string.h"
#include "oscam-time.h"

LLIST *gbox_cards;
LLIST *gbox_backup_cards; //NEEDFIX: this list has to be cleaned from time to time 
CS_MUTEX_LOCK gbox_cards_lock;
uchar checkcode[7];

GBOX_CARDS_ITER *gbox_cards_iter_create(void)
{
        GBOX_CARDS_ITER *gci;
        if(!cs_malloc(&gci, sizeof(GBOX_CARDS_ITER)))
                { return NULL; }
        cs_readlock(__func__, &gbox_cards_lock);
        gci->it = ll_iter_create(gbox_cards);
        return gci;
}

void gbox_cards_iter_destroy(GBOX_CARDS_ITER *gci)
{
        cs_readunlock(__func__, &gbox_cards_lock);
        if (gci) { add_garbage(gci); }
}

struct gbox_card *gbox_cards_iter_next(GBOX_CARDS_ITER *gci)
{
        if (gci) { return ll_iter_next(&gci->it); }
        else { return NULL; }
}

void gbox_write_share_cards_info(void)
{
        uint16_t card_count_shared = 0;
        uint16_t card_count_expired = 0;        
        char *fext = FILE_SHARED_CARDS_INFO;
        char *fname = get_gbox_tmp_fname(fext);
        FILE *fhandle_shared;
        fhandle_shared = fopen(fname, "w");
        if(!fhandle_shared)
        {
                cs_log("Couldn't open %s: %s", fname, strerror(errno));
                return;
        }

        struct gbox_card *card;
        cs_readlock(__func__, &gbox_cards_lock);
        LL_ITER it = ll_iter_create(gbox_cards);
        while((card = ll_iter_next(&it)))
        {
                if (card->type == GBOX_CARD_TYPE_GBOX)
                {
                        fprintf(fhandle_shared, "CardID %d at %s Card %08X Sl:%d Lev:%1d dist:%1d id:%04X\n",
                                card_count_shared, card->origin_peer->hostname, card->caprovid,
                                card->id.slot, card->lvl, card->dist, card->id.peer);
                        card_count_shared++;
                }
        }
        cs_readunlock(__func__, &gbox_cards_lock);
        fclose(fhandle_shared);

        fext = FILE_BACKUP_CARDS_INFO;
        fname = get_gbox_tmp_fname(fext);
        FILE *fhandle_expired;
        fhandle_expired = fopen(fname, "w");
        if(!fhandle_expired)
        {
                cs_log("Couldn't open %s: %s", fname, strerror(errno));
                return;
        }
        cs_readlock(__func__, &gbox_cards_lock);
        LL_ITER it2 = ll_iter_create(gbox_backup_cards);
        while((card = ll_iter_next(&it2)))
        {
                if (card->type == GBOX_CARD_TYPE_GBOX)
                {
                        fprintf(fhandle_expired, "CardID %2d at %s Card %08X Sl:%2d Lev:%1d dist:%1d id:%04X\n",
                                card_count_expired, card->origin_peer->hostname, card->caprovid,
                                card->id.slot, card->lvl, card->dist, card->id.peer);
                        card_count_expired++;
                }
        }
        cs_readunlock(__func__, &gbox_cards_lock);
        fclose(fhandle_expired);                
        return;
}

void gbox_write_local_cards_info(void)
{
        uint16_t card_count_local = 0;
        char *fext = FILE_LOCAL_CARDS_INFO;
        char *fname = get_gbox_tmp_fname(fext); 
        FILE *fhandle_local;
        fhandle_local = fopen(fname, "w");
        if(!fhandle_local)
        {
                cs_log("Couldn't open %s: %s", fname, strerror(errno));
                return;
        }

        struct gbox_card *card;
        cs_readlock(__func__, &gbox_cards_lock);
        LL_ITER it = ll_iter_create(gbox_cards);
        while((card = ll_iter_next(&it)))
        {
                switch (card->type)
                {
                case GBOX_CARD_TYPE_GBOX:
                        break;
                case GBOX_CARD_TYPE_LOCAL:
                        fprintf(fhandle_local, "CardID:%2d %s %08X Sl:%2d id:%04X\n",
                                card_count_local, "Local_Card", card->caprovid, card->id.slot, card->id.peer);
                        card_count_local++;
                        break;
                case GBOX_CARD_TYPE_BETUN:
                        fprintf(fhandle_local, "CardID:%2d %s %08X Sl:%2d id:%04X\n",
                                card_count_local, "Betun_Card", card->caprovid, card->id.slot, card->id.peer);
                        card_count_local++;
                        break;
                case GBOX_CARD_TYPE_CCCAM:
                        fprintf(fhandle_local, "CardID:%2d %s %08X Sl:%2d id:%04X\n",
                                card_count_local, "CCcam_Card", card->caprovid, card->id.slot, card->id.peer);
                        card_count_local++;
                        break;
                case GBOX_CARD_TYPE_PROXY:
                        fprintf(fhandle_local, "CardID:%2d %s %08X Sl:%2d id:%04X\n",
                                card_count_local, "Proxy_Card", card->caprovid, card->id.slot, card->id.peer);
                        card_count_local++;
                        break;
                default:
                        cs_log("Invalid card type: %d in gbox_write_cards_info", card->type);
                        break;
                }
        }
        cs_readunlock(__func__, &gbox_cards_lock);
        fclose(fhandle_local);
}

void gbox_write_stats(void)
{
        int32_t card_count = 0;
        struct gbox_good_srvid *srvid_good = NULL;
        struct gbox_bad_srvid *srvid_bad = NULL;
        char *fext = FILE_STATS;
        char *fname = get_gbox_tmp_fname(fext);
        FILE *fhandle;
        fhandle = fopen(fname, "w");
        if(!fhandle)
        {
                cs_log("Couldn't open %s: %s", fname, strerror(errno));
                return;
        }

        struct gbox_card *card;
        cs_readlock(__func__, &gbox_cards_lock);
        LL_ITER it = ll_iter_create(gbox_cards);
        while((card = ll_iter_next(&it)))
        {
                if (card->type == GBOX_CARD_TYPE_GBOX)
                {
                        fprintf(fhandle, "CardID %4d Card %08X id:%04X #CWs:%d AVGtime:%d ms\n",
                                        card_count, card->caprovid, card->id.peer, card->no_cws_returned, card->average_cw_time);
                        fprintf(fhandle, "Good SIDs:\n");
                        LL_ITER it2 = ll_iter_create(card->goodsids);
                        while((srvid_good = ll_iter_next(&it2)))
                                { fprintf(fhandle, "%04X\n", srvid_good->srvid.sid); }
                        fprintf(fhandle, "Bad SIDs:\n");
                        it2 = ll_iter_create(card->badsids);
                        while((srvid_bad = ll_iter_next(&it2)))
                                { fprintf(fhandle, "%04X #%d\n", srvid_bad->srvid.sid, srvid_bad->bad_strikes); }
                        card_count++;
                }
        } // end of while ll_iter_next
        cs_readunlock(__func__, &gbox_cards_lock);

        fclose(fhandle);
        return;
}

void init_gbox_cards(void)
{
        gbox_cards = ll_create("gbox.cards");
        gbox_backup_cards = ll_create("gbox.backup.cards");
        cs_lock_create(__func__, &gbox_cards_lock, "gbox_cards_lock", 5000);
        cs_writelock(__func__, &gbox_cards_lock);        
        checkcode[0] = 0x15;
        checkcode[1] = 0x30;
        checkcode[2] = 0x02;
        checkcode[3] = 0x04;
        checkcode[4] = 0x19;
        checkcode[5] = 0x19;
        checkcode[6] = 0x66;
        cs_writeunlock(__func__, &gbox_cards_lock);        
}

static void update_checkcode(struct gbox_card *card)
{
        checkcode[0] ^= (0xFF & (card->caprovid >> 24));
        checkcode[1] ^= (0xFF & (card->caprovid >> 16));
        checkcode[2] ^= (0xFF & (card->caprovid >> 8));
        checkcode[3] ^= (0xFF & (card->caprovid));
        checkcode[4] ^= (0xFF & (card->id.slot));
        checkcode[5] ^= (0xFF & (card->id.peer >> 8));
        checkcode[6] ^= (0xFF & (card->id.peer));
}

static void gbox_free_card(struct gbox_card *card)
{
        ll_destroy_data(&card->badsids);
        ll_destroy_data(&card->goodsids);
        add_garbage(card);
        return;
}

static uint8_t closer_path_known(uint32_t caprovid, uint16_t id_peer, uint8_t slot, uint8_t distance)
{
        uint8_t ret = 0;
        struct gbox_card *card;
        cs_readlock(__func__, &gbox_cards_lock);        
        LL_ITER it = ll_iter_create(gbox_cards);
        while((card = ll_iter_next(&it)))
        {
                if (card->caprovid == caprovid && card->id.peer == id_peer && card->id.slot == slot && card->dist <= distance)
                {
                        ret = 1;
                        break;
                }                
        }
        cs_readunlock(__func__, &gbox_cards_lock);        
        return ret;
}

static uint8_t got_from_backup(uint32_t caprovid, uint16_t id_peer, uint8_t slot, struct gbox_peer *origin_peer)
{
        uint8_t ret = 0;
        struct gbox_card *card;
        cs_writelock(__func__, &gbox_cards_lock);        
        LL_ITER it = ll_iter_create(gbox_backup_cards);
        while((card = ll_iter_next(&it)))
        {
                if (card->caprovid == caprovid && card->id.peer == id_peer && card->id.slot == slot)
                {
                        cs_log_dbg(D_READER, "backup card from peer: %04X %08X", card->id.peer, card->caprovid );
                        ll_remove(gbox_backup_cards, card);
                        card->origin_peer = origin_peer;
                        ll_append(gbox_cards, card);
                        update_checkcode(card);
                        ret = 1;
                        break;
                }                
        }
        cs_writeunlock(__func__, &gbox_cards_lock);                
        return ret;
}

void gbox_add_card(uint16_t id_peer, uint32_t caprovid, uint8_t slot, uint8_t level, uint8_t distance, uint8_t type, struct gbox_peer *origin_peer)
{
        uint16_t caid = gbox_get_caid(caprovid);
        uint32_t provid = gbox_get_provid(caprovid);

				if(!caprovid)	//skip caprov 00000000
					{ return; }
        //don't insert 0100:000000
        if(caid_is_seca(caid) && (!provid))
                { return; }
        //skip CAID 18XX providers
        if(caid_is_nagra(caid) && (provid))
                { return; }

        if (!closer_path_known(caprovid, id_peer, slot, distance) && !got_from_backup(caprovid, id_peer, slot, origin_peer))
        {        
                struct gbox_card *card;
                if(!cs_malloc(&card, sizeof(struct gbox_card)))
                {
                        cs_log("Card allocation failed");
                        return;
                }
                cs_log_dbg(D_READER, "new card from peer: %04X %08X", id_peer, caprovid);
                card->caprovid = caprovid;
                card->id.peer = id_peer;
                card->id.slot = slot;
                card->dist = distance;
                card->lvl = level;
                card->badsids = ll_create("badsids");
                card->goodsids = ll_create("goodsids");
                card->no_cws_returned = 0;
                card->average_cw_time = 0;
                card->type = type;
                card->origin_peer = origin_peer;
                cs_writelock(__func__, &gbox_cards_lock);
                ll_append(gbox_cards, card);
                update_checkcode(card);
                cs_writeunlock(__func__, &gbox_cards_lock);
        }

        return;
}

uchar *gbox_get_checkcode(void)
{
        return &checkcode[0];
}

uint16_t gbox_count_cards(void)
{
        return ll_count(gbox_cards);
}

uint16_t gbox_count_peer_cards(uint16_t peer_id)
{
        uint16_t counter = 0;
        struct gbox_card *card;

        cs_readlock(__func__, &gbox_cards_lock);
        LL_ITER it = ll_iter_create(gbox_cards);
        while((card = ll_iter_next(&it)))
        {
                if (card->origin_peer && card->origin_peer->gbox.id == peer_id)
                        { counter++; }
        }
        cs_readunlock(__func__, &gbox_cards_lock);

        return counter;
}

void gbox_delete_cards(uint8_t delete_type, uint16_t criteria)
{
        struct gbox_card *card;
        uint8_t found;

        cs_writelock(__func__, &gbox_cards_lock);
        LL_ITER it = ll_iter_create(gbox_cards);
        while((card = ll_iter_next(&it)))
        {
                found = 0;
                switch (delete_type)
                {
                case GBOX_DELETE_FROM_PEER:
                        if (card->origin_peer && card->origin_peer->gbox.id == criteria)
                                { found = 1; }
                        break;
                case GBOX_DELETE_WITH_ID:                
                        if (card->id.peer == criteria)
                                { found = 1; }
                        break;
                case GBOX_DELETE_WITH_TYPE:                
                        if (card->type == criteria)
                                { found = 1; }
                        break;        
                default:
                        cs_log("Invalid delete type: %d in gbox_delete_cards", delete_type);
                        break;        
                }
                if (found)
                {
                        cs_log_dbg(D_READER, "remove card from peer: %04X %08X", card->id.peer, card->caprovid);
                        ll_remove(gbox_cards, card);
                        ll_append(gbox_backup_cards, card);
                        update_checkcode(card);
                }
        }
        cs_writeunlock(__func__, &gbox_cards_lock);

        return;
}

static void gbox_free_list(LLIST *card_list)
{
    if(card_list)
    {
        cs_writelock(__func__, &gbox_cards_lock);
        LL_ITER it = ll_iter_create(card_list);
        struct gbox_card *card;
        while((card = ll_iter_next_remove(&it)))
            { gbox_free_card(card); }
        ll_destroy(&gbox_cards);        
        cs_writeunlock(__func__, &gbox_cards_lock);
    }
    return;
}

void gbox_free_cardlist(void)
{
        gbox_free_list(gbox_cards);
        gbox_free_list(gbox_backup_cards);
        return;
}

void gbox_add_good_sid(uint16_t id_card, uint16_t caid, uint8_t slot, uint16_t sid_ok, uint32_t cw_time)
{
        struct gbox_card *card = NULL;
        struct gbox_good_srvid *srvid = NULL;
        uint8_t factor = 0;
 
        cs_writelock(__func__, &gbox_cards_lock);
        LL_ITER it = ll_iter_create(gbox_cards);
        while((card = ll_iter_next(&it)))
        {
                if(card->id.peer == id_card && gbox_get_caid(card->caprovid) == caid && card->id.slot == slot)
                {
                        card->no_cws_returned++;
                        if (!card->no_cws_returned)
                                { card->no_cws_returned = 10; } //wrap around
                        if (card->no_cws_returned < 10)
                                { factor = card->no_cws_returned; }
                        else
                                { factor = 10; }
                                card->average_cw_time = ((card->average_cw_time * (factor-1)) + cw_time) / factor;
                        LL_ITER it2 = ll_iter_create(card->goodsids);
                        while((srvid = ll_iter_next(&it2)))
                        {
                                if(srvid->srvid.sid == sid_ok)
                                {
                                        srvid->last_cw_received = time(NULL);
                                        cs_writeunlock(__func__, &gbox_cards_lock);
                                        return; // sid_ok is already in the list of goodsids
                                }
                        }

                        if(!cs_malloc(&srvid, sizeof(struct gbox_good_srvid)))
                        { 
                                cs_writeunlock(__func__, &gbox_cards_lock);
                                cs_log("Good SID allocation failed");
                                return;
                        }
                        srvid->srvid.sid = sid_ok;
                        srvid->srvid.provid_id = gbox_get_provid(card->caprovid);
                        srvid->last_cw_received = time(NULL);
                        cs_log_dbg(D_READER, "Adding good SID: %04X for CAID: %04X Provider: %04X on CardID: %04X", sid_ok, caid, gbox_get_provid(card->caprovid), id_card);
                        ll_append(card->goodsids, srvid);
                        break;
                }
        }//end of ll_iter_next
        //return dist_c;
        cs_writeunlock(__func__, &gbox_cards_lock);
        return;        
}

void gbox_remove_bad_sid(uint16_t id_peer, uint8_t id_slot, uint16_t sid)
{
        struct gbox_card *card = NULL;
        struct gbox_bad_srvid *srvid = NULL;
                
        cs_writelock(__func__, &gbox_cards_lock);
        LL_ITER it2 = ll_iter_create(gbox_cards);
        while((card = ll_iter_next(&it2)))
        {
                if(card->id.peer == id_peer && card->id.slot == id_slot)
                {
                        LL_ITER it3 = ll_iter_create(card->badsids);
                        while((srvid = ll_iter_next(&it3)))
                        {
                                if(srvid->srvid.sid == sid)
                                {
                                        ll_iter_remove_data(&it3); // remove sid_ok from badsids
                                        break;
                                }
                        }
                }
        }
        cs_writeunlock(__func__, &gbox_cards_lock);        
}        

uint8_t gbox_next_free_slot(uint16_t id)
{
        struct gbox_card *c;
        uint8_t lastslot = 0;
                        
        cs_readlock(__func__, &gbox_cards_lock);        
        LL_ITER it = ll_iter_create(gbox_cards);
        while((c = ll_iter_next(&it)))
        {
                if(id == c->id.peer && c->id.slot > lastslot)
                        { lastslot = c->id.slot; }
        }
        cs_readunlock(__func__, &gbox_cards_lock);        
        return ++lastslot;
} 

static int8_t is_already_pending(LLIST *pending_cards, uint16_t peer_id, uint8_t slot)
{
        if (!pending_cards)
                { return -1; }
                
        int8_t ret = 0;
        struct gbox_card_id *current_id;
        LL_LOCKITER *li = ll_li_create(pending_cards, 0);
        while ((current_id = ll_li_next(li)))
        {
                if (current_id->peer == peer_id && current_id->slot == slot)
                {
                        ret = 1;
                        break;
                }
        }
        ll_li_destroy(li);
        return ret;
}

uint8_t gbox_get_cards_for_ecm(uchar *send_buf_1, int32_t cont_1, uint8_t max_cards, ECM_REQUEST *er, uint32_t *current_avg_card_time, uint16_t peer_id)
{
        if (!send_buf_1 || !er)
                { return 0; }
                
        uint8_t cont_card_1 = 0;
        struct gbox_good_srvid *srvid_good = NULL;
        struct gbox_bad_srvid *srvid_bad = NULL;
        uint8_t enough = 0;              
        uint8_t sid_verified = 0;
        time_t time_since_lastcw;

        //loop over good only
        cs_readlock(__func__, &gbox_cards_lock);        
        LL_ITER it = ll_iter_create(gbox_cards);
        LL_ITER it2;
        struct gbox_card *card;
                                
        while((card = ll_iter_next(&it)))
        {
                if(card->origin_peer && card->origin_peer->gbox.id == peer_id && card->type == GBOX_CARD_TYPE_GBOX &&
                        gbox_get_caid(card->caprovid) == er->caid && gbox_get_provid(card->caprovid) == er->prid && !is_already_pending(er->gbox_cards_pending, card->id.peer, card->id.slot))
                {
                        sid_verified = 0;

                        //check if sid is good
                        it2 = ll_iter_create(card->goodsids);
                        while((srvid_good = ll_iter_next(&it2)))
                        {
                                if(srvid_good->srvid.provid_id == er->prid && srvid_good->srvid.sid == er->srvid)
                                {
                                        if (!enough || *current_avg_card_time > card->average_cw_time)
                                        {
                                                time_since_lastcw = llabs(srvid_good->last_cw_received - time(NULL));
                                                *current_avg_card_time = card->average_cw_time;
                                                if (enough)
                                                        { cont_1 = cont_1 - 3; }
                                                else
                                                {
                                                        cont_card_1++;
                                                        if (time_since_lastcw < GBOX_SID_CONFIRM_TIME && er->gbox_ecm_status == GBOX_ECM_NOT_ASKED)
                                                                { enough = 1; }
                                                }
                                                i2b_buf(2, card->id.peer, send_buf_1 + cont_1);
                                                send_buf_1[cont_1 + 2] = card->id.slot;
                                                cont_1 = cont_1 + 3;
                                                sid_verified = 1;
                                                break;
                                        }
                                }
                        }

                        if(cont_card_1 == max_cards)
                                { break; }
                }
        }
        cs_readunlock(__func__, &gbox_cards_lock);        
                                                                                              
        //loop over bad and unknown cards
        cs_writelock(__func__, &gbox_cards_lock);        
        it = ll_iter_create(gbox_cards);
        while((card = ll_iter_next(&it)))
        {
                if(card->origin_peer && card->origin_peer->gbox.id == peer_id && card->type == GBOX_CARD_TYPE_GBOX &&
                        gbox_get_caid(card->caprovid) == er->caid && gbox_get_provid(card->caprovid) == er->prid && !is_already_pending(er->gbox_cards_pending, card->id.peer, card->id.slot) && !enough)
                {
                        sid_verified = 0;

                        //check if sid is good
                        it2 = ll_iter_create(card->goodsids);
                        while((srvid_good = ll_iter_next(&it2)))
                        {
                                if(srvid_good->srvid.provid_id == er->prid && srvid_good->srvid.sid == er->srvid)
                                {
                                        sid_verified = 1;
                                        cs_log_dbg(D_READER, "ID: %04X SL: %02X SID: %04X is good", card->id.peer, card->id.slot, srvid_good->srvid.sid);
                                }
                        }
                        if(!sid_verified)
                        {
                                //check if sid is bad
                                LL_ITER itt = ll_iter_create(card->badsids);
                                while((srvid_bad = ll_iter_next(&itt)))
                                {
                                        if(srvid_bad->srvid.provid_id == er->prid && srvid_bad->srvid.sid == er->srvid)
                                        {
                                                if (srvid_bad->bad_strikes < 3)
                                                {
                                                        sid_verified = 2;
                                                        srvid_bad->bad_strikes++;
                                                }
                                                else
                                                        { sid_verified = 1; }
                                                cs_log_dbg(D_READER, "ID: %04X SL: %02X SID: %04X is bad %d", card->id.peer, card->id.slot, srvid_bad->srvid.sid, srvid_bad->bad_strikes);
                                                break;
                                        }
                                }

                                //sid is neither good nor bad
                                if(sid_verified != 1)
                                {
                                        i2b_buf(2, card->id.peer, send_buf_1 + cont_1);
                                        send_buf_1[cont_1 + 2] = card->id.slot;
                                        cont_1 = cont_1 + 3;
                                        cont_card_1++;

                                        if (!sid_verified)
                                        {
                                                if(!cs_malloc(&srvid_bad, sizeof(struct gbox_bad_srvid)))
                                                { 
                                                        cs_log("ServID allocation failed");
                                                        cs_writeunlock(__func__, &gbox_cards_lock);                                                
                                                        return 0;                                                
                                                }

                                                srvid_bad->srvid.sid = er->srvid;
                                                srvid_bad->srvid.provid_id = gbox_get_provid(card->caprovid);
                                                srvid_bad->bad_strikes = 1;
                                                ll_append(card->badsids, srvid_bad);
                                                cs_log_dbg(D_READER, "ID: %04X SL: %02X SID: %04X is not checked", card->id.peer, card->id.slot, srvid_bad->srvid.sid);
                                        }
                                }
                        }

                        if(cont_card_1 == max_cards)
                                { break; }
                }
        }
        cs_writeunlock(__func__, &gbox_cards_lock);        
        return cont_card_1;
}

#endif

