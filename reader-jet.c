#include "globals.h"
#ifdef READER_JET
#include "reader-common.h"
#include "cscrypt/des.h"
#include "cscrypt/twofish.h"
#include <time.h>

#define CRC16 0x8005
static const uint8_t vendor_key[32] = {0x54, 0xF5, 0x53, 0x12, 0xEA, 0xD4, 0xEC, 0x03, 0x28, 0x60, 0x80, 0x94, 0xD6, 0xC4, 0x3A, 0x48, 
                                   0x43, 0x71, 0x28, 0x94, 0xF4, 0xE3, 0xAB, 0xC7, 0x36, 0x59, 0x17, 0x8E, 0xCC, 0x6D, 0xA0, 0x9B};

#define jet_write_cmd(reader, cmd, len, encrypt_tag, title) \
 do { \
	uint8_t cmd_buf[256];\
	uint8_t cmd_tmp[256];\
	memset(cmd_buf, 0, sizeof(cmd_buf));\
	memcpy(cmd_buf, cmd, len);\
	uint16_t crc=calc_crc16(cmd_buf, len);\
	cmd_buf[len] = crc >> 8;\
	cmd_buf[len + 1] = crc & 0xFF;\
	if(!jet_encrypt(reader, encrypt_tag, cmd_buf, len + 2, cmd_tmp, sizeof(cmd_tmp))){\
		rdr_log(reader, "error: encrypt %s failed.", title);\
		return ERROR;\
	}\
	cmd_tmp[4] += 2;\
	write_cmd(cmd_tmp, cmd_tmp + 5);\
	if(cta_res[cta_lr - 2] != 0x90 || cta_res[cta_lr - 1] != 0x00){\
		rdr_log(reader, "error: exec %s failed!", title);\
		return ERROR;\
	}\
  } while (0)

#define jet_write_cmd_hold(reader, cmd, len, encrypt_tag, title) \
 do { \
	uint8_t cmd_buf[256];\
	uint8_t cmd_tmp[256];\
	memset(cmd_buf, 0, sizeof(cmd_buf));\
	memcpy(cmd_buf, cmd, len);\
	uint16_t crc=calc_crc16(cmd_buf, len);\
	cmd_buf[len] = crc >> 8;\
	cmd_buf[len + 1] = crc & 0xFF;\
	if(jet_encrypt(reader, encrypt_tag, cmd_buf, len + 2, cmd_tmp, sizeof(cmd_tmp))){\
		cmd_tmp[4] += 2;\
		write_cmd(cmd_tmp, cmd_tmp + 5);\
		if(cta_res[cta_lr - 2] != 0x90 || cta_res[cta_lr - 1] != 0x00){\
			rdr_log(reader, "error: exec %s failed!", title);\
		}\
	}\
	else \
		rdr_log(reader, "error: encrypt %s failed.", title);\
  } while (0)

static uint16_t calc_crc16( const uint8_t *data, size_t size)
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

static size_t jet_encrypt(struct s_reader * reader, uint8_t tag, uint8_t *data, size_t len, uint8_t *out, size_t maxlen)
{
	uint8_t buf[256];
	size_t i;
	size_t aligned_len = (len + 15) / 16 * 16;
	if((aligned_len + 7) > maxlen || (aligned_len + 7) > 256)
		return 0;
	memset(buf, 0, aligned_len + 7);

	out[0] = 0x84;
	out[1] = tag;
	out[2] = 0;
	out[3] = 0;
	out[4] = aligned_len & 0xFF;
	memcpy(buf, data, len);
	if(tag == 0x15){
		struct TWOFISH ctx;
		twofish_init(&ctx, reader->jet_vendor_key, 256);
		twofish_crypt(&ctx, out + 5, buf, aligned_len / 16, NULL, 0);
	}
	else if(tag == 0x16){
		for(i = 0; i < (aligned_len / 8); i++)
			des_ecb_encrypt(buf + 8 * i, reader->jet_vendor_key + (i % 4) * 8, 8);
		memcpy(out + 5, buf, aligned_len);
	}
	out[aligned_len + 5] = 0x90;
	out[aligned_len + 6] = 0x00;

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

	if(len < (int)sizeof(derivekey))
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
	uint8_t confirm_auth_cmd[48] = {0x15, 0x2C, 0x00, 0x00};
	uint8_t change_vendorkey_cmd[12] = {0x12, 0x08, 0x00, 0x00};
	uint8_t pairing_cmd01[38] = {0x20, 0x22, 0x00, 0x00};
	uint8_t pairing_cmd02[53] = {0x37, 0x31, 0x00, 0x00};

	get_atr;
	def_resp;
	uint8_t cmd_buf[256];
	uint8_t temp[256];
	uint8_t buf[256];
	struct TWOFISH ctx;
	int i;

	if((atr_size != 20) || atr[0] != 0x3B || atr[1] != 0x7F) { return ERROR; }
	if(atr[17] > 0x34 && atr[18] > 0x32)
		reader->cas_version=5;
	else
		reader->cas_version=1;

	reader->caid = 0x4A30;
	reader->nprov = 1;
	memset(reader->prid, 0x00, sizeof(reader->prid));
	memcpy(reader->jet_vendor_key, vendor_key, sizeof(vendor_key));

	// get serial step1
	jet_write_cmd(reader, get_serial_cmd01, sizeof(get_serial_cmd01), 0xAA, "get_serial_cmd01");
	memcpy(reader->hexserial, cta_res + 9, 8);

	//get root key
	jet_write_cmd(reader, get_rootkey_cmd, sizeof(get_rootkey_cmd), 0xAA, "get_rootkey_cmd");
	memcpy(temp, cta_res + 5, cta_res[4]);
	memset(temp + cta_res[4], 0, sizeof(temp) - cta_res[4]);
	twofish_init(&ctx, reader->jet_vendor_key, 256);
	twofish_crypt(&ctx, buf, temp, (cta_res[4] + 15)/ 16, NULL, 1);		//twfish decrypt
	memset(reader->jet_root_key, 0 ,sizeof(reader->jet_root_key));
	memcpy(reader->jet_root_key, buf + 4, (cta_res[4] < sizeof(reader->jet_root_key)) ? cta_res[4] : sizeof(reader->jet_root_key));

	//get derive key
	memset(cmd_buf, 0, sizeof(cmd_buf));
	if(!generate_derivekey(reader, cmd_buf, sizeof(cmd_buf))){
		rdr_log(reader, "error: generate derivekey faild, buffer overflow!");
		return ERROR;
	}
	//generate_derivekey has filled crc16. so call jet_write_cmd with len - 2.
	jet_write_cmd(reader, cmd_buf, sizeof(reader->jet_derive_key) - 2, 0xAA, "get derivekey cmd");
	memcpy(reader->jet_derive_key, cmd_buf, sizeof(reader->jet_derive_key));

	//get auth key
	memset(cmd_buf, 0, sizeof(cmd_buf));
	memcpy(cmd_buf, get_authkey_cmd, sizeof(get_authkey_cmd));
	memcpy(cmd_buf + 4, reader->jet_root_key, 2);
	jet_write_cmd(reader, cmd_buf, sizeof(get_authkey_cmd), 0xAA, "get_auth_cmd");
	memset(temp, 0, sizeof(temp));
	memcpy(temp, cta_res, cta_res[4]);
	twofish_init(&ctx, reader->jet_vendor_key, 256);
	twofish_crypt(&ctx, buf, temp, (cta_res[4] + 15)/ 16, NULL, 1);		//twfish decrypt
	memcpy(reader->jet_auth_key, buf, 10);

	//confirm auth key
	memcpy(confirm_auth_cmd + 36, reader->jet_auth_key, 8);
	memcpy(confirm_auth_cmd + 44, reader->jet_derive_key, 4); 
	jet_write_cmd(reader, confirm_auth_cmd, sizeof(confirm_auth_cmd), 0x15, "confirm_auth_cmd");

	//change vendor key
	jet_write_cmd(reader, change_vendorkey_cmd, sizeof(change_vendorkey_cmd), 0x15, "change_vendorkey_cmd");
	memset(temp, 0, sizeof(temp));
	memcpy(temp, cta_res + 5, cta_res[4]);
	twofish_init(&ctx, reader->jet_vendor_key, 256);
	twofish_crypt(&ctx, buf, temp, (cta_res[4] + 15)/ 16, NULL, 1);		//twfish decrypt
	if(((cta_res[4] + 15)/ 16 * 16) == 48 && buf[0] == 0x42 && buf[1] == 0x20)
		memcpy(reader->jet_vendor_key, buf + 4, 32);

	//pairing step1
	if(reader->boxkey_length)
		memcpy(pairing_cmd01 + 4, reader->boxkey, 32);
	pairing_cmd01[37] = 0x01;
	jet_write_cmd_hold(reader, pairing_cmd01, sizeof(pairing_cmd01), 0x15, "pairing_cmd01");
	memset(temp, 0, sizeof(temp));
	memcpy(temp, cta_res + 5, cta_res[4]);
	twofish_init(&ctx, reader->jet_vendor_key, 256);
	twofish_crypt(&ctx, buf, temp, (cta_res[4] + 15)/ 16, NULL, 1);		//twfish decrypt
	if(buf[0] != 0x41)
		rdr_log(reader, "error: pairing step 1 failed! continue ...");

	//pairing step 2
	if(reader->boxkey_length)
		memcpy(pairing_cmd02 + 4, reader->boxkey, 32);
	pairing_cmd02[36] = 0x01;
	for(i = 37;i < 45; i++)
		pairing_cmd02[i] = 0x30;
	memcpy(pairing_cmd02 + 45, reader->jet_derive_key + 45, 8);
	jet_write_cmd_hold(reader, pairing_cmd02, sizeof(pairing_cmd02), 0x15, "pairing_cmd02");

	rdr_log_sensitive(reader, "type: jet, caid: %04X, serial: %llu, hex serial: %08llX",
			reader->caid, (uint64_t) b2ll(8, reader->hexserial), (uint64_t) b2ll(8, reader->hexserial));

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
