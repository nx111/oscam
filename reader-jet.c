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

	memset(output, 0, maxlen);
	memcpy(output, buf, aligned_len + 7);
	return (aligned_len + 7);
}

/*================================================================*/
static int generate_derivekey(struct s_reader *reader, uint8_t * out, int len)
{
	uint8_t mask_key[32] = {0x16,0x23,0x6A,0x8A,0xF5,0xC2,0x8E,0x6,0x14,0x53,0xCF,0x6E,0x12,0xA1,0x2E,0xC5,
				0xE4,0xF8,0x94,0x10,0x03,0x0A,0xD8,0xC6,0xD4,0x55,0xE8,0x4A,0xB6,0x22,0x09,0xAD};
	uint8_t temp[128];
	uint8_t derivekey[56]={0x59, 0x32, 0x00, 0x00};
	int i;

	if(len < sizeof(derivekey))
		return 0;
	memset(temp, 0 , sizeof(temp));
	memcpy(temp + 56, mask_key, sizeof(mask_key));
	memcpy(temp + 56 + sizeof(mask_key), reader->hexserial, 8);
	memcpy(temp + 56 + sizeof(mask_key) + 8, reader->jet_root_key, 8);
	temp[12] = temp[100] ^ temp[92];
	temp[16] = temp[102] ^ temp[94];
	temp[20] = temp[97];
	temp[32] = temp[96] ^ temp[88];
	temp[36] = temp[97] ^ temp[89];
	temp[40] = temp[98] ^ temp[90];
	temp[44] = temp[99] ^ temp[91];
	temp[48] = temp[101] ^ temp[93];
	temp[52] = temp[103];

	memcpy(derivekey + 4, reader->jet_root_key, 8);
	derivekey[12] = temp[32];
	derivekey[13] = temp[36];
	derivekey[14] = temp[40];
	derivekey[15] = temp[44];
	derivekey[16] = temp[12];
	derivekey[17] = temp[48];
	derivekey[18] = temp[16];
	derivekey[19] = temp[52] ^ temp[95];

	for(i = 0; i < 36; i++)
		derivekey[20 + i] = temp[54 + i] ^ temp[ (i % 8) + 96];
	uint16_t crc = calc_crc16(derivekey, 54);
	derivekey[54] = crc >> 8;
	derivekey[55] = crc & 0xFF;
	memcpy(out, derivekey, sizeof(derivekey));
	return sizeof(derivekey);
}

static int32_t jet_card_init(struct s_reader *reader, ATR *newatr)
{
	uint8_t get_serial_cmd01[37] = {0x21, 0x21, 0x00, 0x00, 0x00};
	uint8_t get_rootkey_cmd[6] = {0x58, 0x02, 0x00, 0x00, 0x00, 0x00};
	uint8_t get_authkey_cmd[6] = {0x58, 0x02, 0x00, 0x00, 0x00, 0x00};
	def_resp;
	get_atr;
	uint8_t cmd[256];
	uint8_t cmd_buf[256];
	uint8_t temp[256];
	size_t cmdLen;
	uint16_t crc = 0;

	if((atr_size != 20) || atr[0] != 0x3B || atr[1] != 0x7F) { return ERROR; }
	if(atr[17] > 0x34 && atr[18] > 0x32)
		cas_version=5;
	else
		cas_version=1;

	reader->caid = 0x4A30;
	reader->nprov = 1;
	memset(reader->prid, 0x00, sizeof(reader->prid));

	// get serial step1
	memset(cmd_buf, 0, sizeof(cmd_buf));
	memcpy(cmd_buf, get_serial_cmd01, sizeof(get_serial_cmd01));
	crc=calc_crc16(0, cmd_buf, sizeof(get_serial_cmd01));
	cmd_buf[sizeof(get_serial_cmd01)] = crc >> 8;
	cmd_buf[sizeof(get_serial_cmd01) + 1] = crc & 0xFF;
	if(!encrypt(0xAA, cmd_buf, sizeof(get_serial_cmd01) + 2, cmd, sizeof(cmd))){
		rdr_log(reader, "error: encrypt get_serial_cmd01 failed.");
		return ERROR;
	}
	cmd[4] += 2;
	write_cmd(cmd, cmd + 5);
	if(cta_res[cta_lr - 2] != 0x90 || cta_res[cta_lr - 1] != 0x00){
		rdr_log(reader, "error: get serial step 1 failed!");
		return ERROR;
	}
	memcpy(reader->hexserial, cta_res + 9, 8);

	//get root key
	memset(cmd_buf, 0, sizeof(cmd_buf));
	memcpy(cmd_buf, get_rootkey_cmd, sizeof(get_rootkey_cmd);
	crc=calc_crc16(0, cmd_buf, sizeof(get_rootkey_cmd));
	cmd_buf[sizeof(get_rootkey_cmd)] = crc >> 8;
	cmd_buf[sizeof(get_rootkey_cmd) + 1] = crc & 0xFF;
	if (!encrypt(0xAA, cmd_buf, sizeof(get_rootkey_cmd) + 2, cmd, sizeof(cmd))){
		rdr_log(reader, "error: encrypt get_rootkey_cmd failed.");
		return ERROR;
	}
	cmd[4] += 2;
	write_cmd(cmd, cmd + 5);
	if(cta_res[cta_lr - 2] != 0x90 || cta_res[cta_lr - 1] != 0x00){
		rdr_log(reader, "error: get root key failed!");
		return ERROR;
	}
	memcpy(temp, cta_res + 5, cta_res[4]);
	aes_twofish_decrypt(temp, cta_res[4]);
	memset(reader->jet_root_key, 0 ,sizeof(reader->jet_root_key));
	memcpy(reader->jet_root_key, temp + 4, (cta_res[4] < sizeof(reader->jet_root_key)) ? cta_res[4] : sizeof(reader->jet_root_key));

	//get derive key
	memset(cmd_buf, 0, sizeof(cmd_buf));
	if(!generate_derivekey(reader, cmd_buf, sizeof(cmd_buf))){
		rdr_log(reader, "error: generate derivekey faild, buffer overflow!");
		return ERROR;
	}
	if(!encrypt(0xAA, cmd_buf, sizeof(reader->jet_derive_key), cmd, sizeof(cmd))){
		rdr_log(reader, "error: encrypt for getting derive key failed.");
		return ERROR;
	}
	cmd[4] += 2;
	write(cmd, cmd + 5);
	if(cta_res[cta_lr - 2] != 0x90 || cta_res[cta_lr - 1] != 0x00){
		rdr_log(reader, "error: confirm derive key failed!");
		return ERROR;
	}
	memcpy(reader->jet_derive_key, cmd_buf, sizeof(reader->jet_derive_key));

	//get auth key
	memset(cmd_buf, 0, sizeof(cmd_buf));
	memcpy(cmd_buf, get_authkey_cmd, sizeof(get_authkey_cmd);
	memcpy(cmd_buf + 4, reader->jet_root_key, 2));
	crc=calc_crc16(0, cmd_buf, sizeof(get_authkey_cmd));
	cmd_buf[sizeof(get_authkey_cmd)] = crc >> 8;
	cmd_buf[sizeof(get_authkey_cmd) + 1] = crc & 0xFF;
	if (!encrypt(0xAA, cmd_buf, sizeof(get_rootkey_cmd) + 2, cmd, sizeof(cmd))){
		rdr_log(reader, "error: encrypt get_authkey_cmd failed.");
		return ERROR;
	}
	cmd[4] += 2;
	write_cmd(cmd, cmd + 5);
	if(cta_res[cta_lr - 2] != 0x90 || cta_res[cta_lr - 1] != 0x00){
		rdr_log(reader, "error: get auth key failed!");
		return ERROR;
	}
	memset(temp, 0, sizeof(temp));
	memcpy(temp, cta_res, cta_res[4]);
	des_twofish_decrypt(temp, cta_res[4]);
	memcpy(reader->jet_auth_key, temp, 10);

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
