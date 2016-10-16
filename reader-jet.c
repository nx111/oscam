#include "globals.h"
#ifdef READER_JET
#include "reader-common.h"
#include "cscrypt/des.h"
#include "cscrypt/twofish.h"
#include <time.h>


static int32_t jet_card_init(struct s_reader *reader, ATR *newatr)
{
	def_resp;
	get_atr;

	if((atr_size != 20) || atr[0] != 0x3B || atr[1] != 0x7F) { return ERROR; }
	if(atr[17] > 0x34 && atr[18] > 0x32)
		cas_version=5;
	else
		cas_version=1;

	reader->caid = 0x4A30;
	reader->nprov = 1;
	memset(reader->prid, 0x00, sizeof(reader->prid));



	rdr_log_sensitive(reader, "type: jet, caid: %04X, serial: %llu, hex serial: %02x%02x%02x%02x,"\
			"BoxID: %02X%02X%02X%02X",
			reader->caid, (unsigned long long) b2ll(6, reader->hexserial), reader->hexserial[2],
			reader->hexserial[3], reader->hexserial[4], reader->hexserial[5], 
			boxID[0], boxID[1], boxID[2], boxID[3]);

	return OK;
}


static int32_t jet_do_ecm(struct s_reader *reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{


	return OK;
}

static int32_t jet_get_emm_type(EMM_PACKET *ep, struct s_reader *UNUSED(reader))
{
	ep->type = UNKNOWN;
	return 1;
}

static int32_t jet_do_emm(struct s_reader *reader, EMM_PACKET *ep)
{

	return OK;
}

static int32_t jet_card_info(struct s_reader *reader)
{

	return OK;
}

const struct s_cardsystem reader_jet =
{
	.desc         = "jet",
	.caids        = (uint16_t[]){ 0x4A, 0 },
	.do_emm       = jet_do_emm,
	.do_ecm       = jet_do_ecm,
	.card_info    = jet_card_info,
	.card_init    = jet_card_init,
	.get_emm_type = jet_get_emm_type,
};

#endif
