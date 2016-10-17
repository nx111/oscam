#include "globals.h"
#ifdef READER_JET
#include "reader-common.h"
#include "cscrypt/des.h"
#include "cscrypt/twofish.h"
#include <time.h>

#define CRC16 0x8005

uint16_t calc_crc16(const uint8_t *data, uint16_t size)
{
    uint16_t out = 0;
    int bits_read = 0, bit_flag;

    /* Sanity check: */
    if(data == NULL)
        return 0;

    while(size > 0)
    {
        bit_flag = out >> 15;

        /* Get next bit: */
        out <<= 1;
        out |= (*data >> (7 - bits_read)) & 1;

        /* Increment bit counter: */
        bits_read++;
        if(bits_read > 7)
        {
            bits_read = 0;
            data++;
            size--;
        }

        /* Cycle check: */
        if(bit_flag)
            out ^= CRC16;

    }
    return out;
}

static size_t encrypt(uint8_t tag, char * data, size_t len, char *output, size_t maxlen)
{
	uint8_t buf[256];
	size_t aligned_len = (len + 15) / 16 * 16;
	if((aligned_len + 7) > maxlen || (aligned_len + 7) > 256)
		return 0;
	memset(buf, 0, aligned_len + 7);

	buf[0] = 0x84;
	buf[1] = tag;
	buf[2] = 0;
	buf[3] = 0;
	buf[4] = aligned_len & 0xFF;
	memcpy(buf + 5, data, len);
	if(tag == 0x15)
		aes_twofish_encrypt(buf + 5, aligned_len);
	else if(tag == 0x16)
		des_ecb_encrypt(buf + 5, aligned_len);
	buf[aligned_len + 5] = 0x90;
	buf[aligned_len + 6] = 0x00;
	memcpy(output, buf, aligned_len + 7);
	return (aligned_len + 7);
}

/*================================================================*/

static int32_t jet_card_init(struct s_reader *reader, ATR *newatr)
{
	uint8_t begin_cmd01[]={0x21, 0x21, 0x00, 0x00, 0x00}

	def_resp;
	get_atr;
	uint8_t cmd[256];
	uint8_t cmd_buf[256];
	size_t cmdLen;

	if((atr_size != 20) || atr[0] != 0x3B || atr[1] != 0x7F) { return ERROR; }
	if(atr[17] > 0x34 && atr[18] > 0x32)
		cas_version=5;
	else
		cas_version=1;

	reader->caid = 0x4A30;
	reader->nprov = 1;
	memset(reader->prid, 0x00, sizeof(reader->prid));

	// begin_cmd_01
	memset(cmd_buf, 0, sizeof(cmd_buf));
	memcpy(cmd_buf, begin_cmd01, sizeof(begin_cmd01);
	uint16_t crc=calc_crc16(0, cmd_buf, 37);
	cmd_buf[37] = crc >> 8;
	cmd_buf[38] = crc & 0xFF;
	cmdLen = encrypt(cmd_buf, 39, cmd, sizeof(cmd));
	if(cmdLen == 0)
		return ERROR;
	write_cmd(cmd, cmd + 5);
	if(cta_res[cta_lr - 2] != 0x90 || cta_res[cta_lr - 1] != 0x00){
		rdr_log(reader, "error: exec begin cmd 01 failed!");
		return ERROR;
	}
	memcpy(reader->hexserial, cta_res + 9, 8);

	rdr_log_sensitive(reader, "type: jet, caid: %04X, serial: %llu, hex serial: %08llX,"\
			"BoxID: %02X%02X%02X%02X",
			reader->caid, (uint64_t) b2ll(8, reader->hexserial), (uint64_t) b2ll(8, reader->hexserial),
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
