#include "globals.h"
#ifdef READER_TONGFANG
#include "reader-common.h"
#include "cscrypt/des.h"
#include <time.h>

static const uint32_t  tongfang3_calibsn=2991124752UL;	//B248F110<=;

#if 0
static uchar tongfang3_keyblock[96] =
{
	0xed,0x44,0x1d,0x92,0xef,0x17,0x2f,0xee,
	0xc5,0x76,0x71,0xbd,0xe2,0x7b,0x4a,0xbb,
	0x3a,0xa5,0xc8,0xc7,0x46,0xe4,0xb2,0x11,
	0x23,0xb2,0x8f,0x49,0xd9,0x88,0x93,0x0e,
	0x96,0xf7,0x64,0x23,0xf7,0x62,0xb8,0x5e,
	0x89,0x6c,0xbd,0xb8,0x76,0xcb,0x24,0x9d,
	0x92,0xca,0x2a,0x26,0x64,0xd3,0x4c,0x2a,
	0x53,0x69,0x94,0xce,0xa5,0xa4,0x9d,0x95,
	0x54,0x3a,0xa5,0x52,0x33,0x29,0xa9,0x99,
	0xa6,0xe5,0xa8,0xf4,0x27,0x15,0x4a,0x49,
	0xe9,0xa9,0x2b,0x1d,0x52,0xb2,0x4f,0x4a,
	0x54,0x4c,0x74,0x54,0xcb,0x27,0xd2,0x52,
};

void tongfang3_keygenerate_ex(uchar* KeyBlock, uchar* lpKeySub, int nCount)
{
	int i = 0;

	for (i=0; i<48; i++)
	{
		lpKeySub[i] = (KeyBlock[i*2+nCount/8]>>(nCount%8))&1;
	}
}


void tongfang3_KeyBlockToKey(uchar* keyBlock, uchar* key)
{
		int i = 0;
		int j = 0;
		uchar SubKey[ 48 ];
		uchar PC0[64] =
		{
		   7, 17, 18, 03, 36, 45, 39, 255,
		   4, 255,01, 255,33, 27, 46, 255,
		  23, 11, 255,16, 42, 255,30, 255,
		  06, 02, 13, 20, 28, 38, 26, 255,
		  15, 14, 21, 25, 35, 31, 47, 255,
		   5, 22, 10, 41, 37, 24, 34, 255,
		   9,  0, 255,255,44, 43, 40, 255,
		  19,  8, 12, 29, 32, 255,255,255
		};
		uchar PC1[64] =
		{
		 20, 19,  8, 12,255,255, 29, 255,
		  7, 17, 18,  3, 36, 45, 39, 255,
		  4,255, 01,255, 33, 27, 46, 255,
		 23, 11,255, 16, 42, 255,30, 255,
		 06, 02, 13, 20, 28, 38, 26, 255,
		 15, 14, 21, 25, 35, 31, 47, 255,
		  5, 22, 10, 41, 37, 24, 34, 255,
		  9,  0,255,255, 44, 43, 40, 255
		};

		tongfang3_keygenerate_ex(keyBlock, SubKey, 0);
		for(i=0; i<8; i++)
		{
		  key[7-i] = 0;
		  for (j=0; j<8; j++)
		  {
			  if (PC0[8*i+j]<255)
			  {
				  key[7-i] |= (SubKey[PC0[8*i+j]]<<(7-j));
			  }
		  }
		}

		tongfang3_keygenerate_ex(keyBlock, SubKey, 1);
		for(i=0; i<8; i++)
		{
		  for (j=0; j<8; j++)
		  {

			  if (PC1[8*i+j]<255)
			  {
				  key[7-i] |= (SubKey[PC1[8*i+j]]<<(7-j));
			  }
		  }
		}
}
#endif

//=======main functions===========

uint32_t tongfang3_get_true_calibsn(uint32_t value)
{
	size_t i;
	uint32_t result=0;

	for(i=0; i < 8; i++)
		result |= ((value >> (4 * i)) % 0x10) <<(28-4*i);
	return result;
}

static int32_t cw_is_valid(unsigned char *cw) //returns 1 if cw_is_valid, returns 0 if cw is all zeros
{
	int32_t i;

	for(i = 0; i < 8; i++)
	{
		if(cw[i] != 0)  //test if cw = 00
		{
			return OK;
		}
	}
	return ERROR;
}

static int32_t tongfang_read_data(struct s_reader *reader, uchar size, uchar *cta_res, uint16_t *status)
{
	uchar read_data_cmd[] = {0x00, 0xc0, 0x00, 0x00, 0xff};
	uint16_t cta_lr;

	read_data_cmd[4] = size;
	write_cmd(read_data_cmd, NULL);

	*status = (cta_res[cta_lr - 2] << 8) | cta_res[cta_lr - 1];

	return (cta_lr - 2);
}

static int32_t tongfang_card_init(struct s_reader *reader, ATR *newatr)
{
	const uchar get_ppua_cmdv1[] = {0x00, 0xa4, 0x04, 0x00, 0x05, 0xf9, 0x5a, 0x54, 0x00, 0x06};
	const uchar get_ppua_cmdv3[] = {0x80, 0x46, 0x00, 0x00, 0x04, 0x07, 0x00, 0x00, 0x08};
	uchar get_serial_cmdv1[] = {0x80, 0x32, 0x00, 0x00, 0x58};
	uchar get_serial_cmdv2[] = {0x80, 0x46, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x04};
	uchar get_serial_cmdv3[] = {0x80, 0x46, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x14};
	uchar get_commkey_cmd[17] = {0x80, 0x56, 0x00, 0x00, 0x0c};
	uchar confirm_commkey_cmd[21] = {0x80, 0x4c, 0x00, 0x00, 0x10};
	uchar pairing_cmd[200] = {0x80, 0x4c, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF};

	const uchar des_key[8] = {0x24,0x76,0x92,0xec,0x7c,0x02,0xba,0x30};

	uchar data[257];
	uchar card_id[20];
	uint16_t status = 0;
	uchar boxID[] = {0xFF, 0xFF, 0xFF, 0xFF};
	uchar stbid[8] = {0x01,0x00,0x12,0x34,0x00,0x00,0x00,0x00};
	uchar zero[8] =  {0};
	int32_t i;
	uint32_t calibsn=0;
	int8_t readsize=0;

	get_atr;
	def_resp;

	if(atr_size == 8 && atr[0] == 0x3B && atr[1] == 0x64)
		reader->cas_version = 1;
	else if (atr_size > 9 && atr[0] == 0x3B && (atr[1] & 0xF0) == 0x60 && 0 == memcmp(atr + 4, "NTIC", 4))
		reader->cas_version = atr[8] - 0x30 + 1;
	else if((atr_size == ((uint32_t)(atr[1] & 0x0F) + 4)) && (atr[0] == 0x3B) && ((atr[1] & 0xF0) == 0x60) && (atr[2] == 0x00) && ((atr[3] & 0xF0) == 0x00))
		reader->cas_version = 2;
	else
		return ERROR;	//not yxsb/yxtf

	reader->caid = 0x4A02;
	reader->nprov = 1;
	memset(reader->prid, 0x00, sizeof(reader->prid));
	memset(card_id, 0, sizeof(card_id));
	memset(reader->hexserial, 0, 8);

	if (reader->boxid > 0 ){
		for(i = 0; (size_t)i < sizeof(boxID); i++){
			boxID[i] = (reader->boxid >> (8 * (3 - i))) % 0x100;
		}
	}

	if(reader->cas_version <= 2){	//tongfang 1-2
		write_cmd(get_ppua_cmdv1, get_ppua_cmdv1 + 5);
		if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00)) { return ERROR; }
		rdr_log(reader, "Tongfang %d card detected", reader->cas_version);

		//get card serial
		if(atr[8] == 0x31){	//degrade card from version 3
			write_cmd(get_serial_cmdv2, get_serial_cmdv2 + 5);
			if((cta_res[cta_lr - 2] & 0xf0) != 0x60) {
				rdr_log(reader, "error: get card serial failed.");
				return ERROR;
			}
			readsize=cta_res[cta_lr -1];
			if(readsize != tongfang_read_data(reader, readsize,data,&status) || status != 0x9000){
				rdr_log(reader, "error: card get serial data failed.");
				return ERROR;
			}
			memcpy(reader->hexserial + 2, data, 4);
		}
		else{
			write_cmd(get_serial_cmdv1, get_serial_cmdv1 + 5);
			if((cta_res[cta_lr - 2] & 0xf0) != 0x60) {
				rdr_log(reader, "error: get card serial failed.");
				return ERROR;
			}
			memcpy(reader->hexserial + 2, cta_res, 4);
		}

		// check pairing
		write_cmd(pairing_cmd, pairing_cmd + 5);
		if((cta_res[cta_lr - 2] == 0x94) && (cta_res[cta_lr - 1] == 0xB1) ) {
			rdr_log_dbg(reader, D_IFD, "the card needlessly pairing with any box.");
		}
		else if((cta_res[cta_lr - 2] == 0x94) && (cta_res[cta_lr - 1] == 0xB2))
		{
			if(reader->boxid > 0){
				memcpy(pairing_cmd + 5, boxID, 4);
				write_cmd(pairing_cmd, pairing_cmd + 5);

				if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00) ) {
					rdr_log(reader, "error: this card pairing failed with the box,please check your boxid setting.");
					//return ERROR;
				}
			}
			else{
				rdr_log(reader, "warning: the card pairing with some box.");
				//return ERROR;
			}
		}
		else{
			rdr_log(reader, "error: this card pairing failed with the box(return code:0x%02X%02X).",cta_res[cta_lr -2],cta_res[cta_lr - 1]);
		}

	}
	else if(reader->cas_version == 3){	//tongfang 3
		write_cmd(get_ppua_cmdv3, get_ppua_cmdv3 + 5);
		if((cta_res[cta_lr - 2] & 0xf0) != 0x60) { return ERROR; }
		rdr_log(reader, "Tongfang3 card detected");

		// get commkey
		/* tongfang3_KeyBlockToKey(tongfang3_keyblock,des_key); */
		memcpy(data, zero, sizeof(zero));
		des_ecb_encrypt(data, des_key, 8);
		memcpy(get_commkey_cmd+5, data, 8);
		if(reader->tongfang3_calibsn)
			calibsn=reader->tongfang3_calibsn;
		else
			calibsn=tongfang3_get_true_calibsn(tongfang3_calibsn);
		get_commkey_cmd[5+8] = (calibsn>>24) & 0xFF;
		get_commkey_cmd[5+8+1] = (calibsn>>16) & 0xFF;
		get_commkey_cmd[5+8+2] = (calibsn>>8) & 0xFF;
		get_commkey_cmd[5+8+3] = (calibsn) & 0xFF;
		write_cmd(get_commkey_cmd, get_commkey_cmd + 5);
		if((cta_res[cta_lr - 2] & 0xf0) != 0x60) {
			rdr_log(reader,"error: get card commkey failed.");
			return ERROR;
		}
		readsize=cta_res[cta_lr -1];
		if(readsize != tongfang_read_data(reader, readsize,data,&status)){
			rdr_log(reader, "error: get card seed failed.");
			return ERROR;
		}
		//rdr_log(reader, "card seed got.");
		memcpy(reader->tongfang3_commkey, data, 8);
		des_ecb_encrypt(reader->tongfang3_commkey,des_key,8);

		rdr_log_dbg(reader, D_IFD, "card commkey got(%llX)",(unsigned long long)b2ll(8,reader->tongfang3_commkey));

		//get card serial
		write_cmd(get_serial_cmdv3, get_serial_cmdv3 + 5);
		if((cta_res[cta_lr - 2] & 0xf0) != 0x60) {
			rdr_log(reader, "error: get card serial failed.");
			return ERROR;
		}
		readsize=cta_res[cta_lr -1];
		if(readsize != tongfang_read_data(reader, readsize,data,&status) || status != 0x9000){
			rdr_log(reader, "error: card get serial failed.");
			return ERROR;
		}
		//rdr_log(reader, "card serial got.");

		memset(reader->hexserial, 0, 8);
		memcpy(reader->hexserial + 2, data, 4); // might be incorrect offset

		memcpy(card_id, data + 4, (readsize - 4) > ((int32_t)sizeof(card_id) - 1) ? (int32_t)sizeof(card_id) - 1 : readsize - 5);
		card_id[sizeof(card_id) - 1] = '\0';

		//confirm commkey and pairing
		memcpy(data, stbid, sizeof(stbid));
		des_ecb_encrypt(data, reader->tongfang3_commkey, 8);

		if (reader->boxid > 0 )
			memcpy(zero + 2, boxID, 4);
		memcpy(data + 8, zero, 8);
		des_ecb_encrypt(data + 8, reader->tongfang3_commkey, 8);

		memcpy(confirm_commkey_cmd + 5, data, 16);
		write_cmd(confirm_commkey_cmd, confirm_commkey_cmd + 5);

		if(cta_res[cta_lr - 2] == 0x90 && cta_res[cta_lr - 2] == 0x00){
			rdr_log_dbg(reader, D_IFD, "the card is not pairing with any box,continue...");
		}
		else{
			readsize=cta_res[cta_lr -1];
			if(readsize != tongfang_read_data(reader, readsize, data, &status) || status != 0x9000){
				rdr_log(reader, "error: confirm commkey failed(read response data failed).");
				//return ERROR;
			}
			if(data[0] == 0x90 && data[1] == 0x00)
				rdr_log_dbg(reader, D_IFD, "the card pairing with any box succeed.");
			else if(data[0] == 0x94 && data[1] == 0xB1)
				rdr_log_dbg(reader, D_IFD, "the card needlessly pairing with any box");
			else if(data[0] == 0x94 && data[1] == 0xB2){
				write_cmd(pairing_cmd, pairing_cmd + 5);
				if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00) ) {
					rdr_log(reader, "warning: the card pairing with some box.");
					//return ERROR;
				}
			}
		}

	}
	else {
		rdr_log(reader, "error: NTIC%c card not support yet!",atr[8]);
		return ERROR;
	}

	rdr_log_sensitive(reader, "type: Tongfang, caid: %04X, serial: {%llu}, hex serial: {%llX}, Card ID: {%s}, BoxID: {%08X}",
			reader->caid, 
			(unsigned long long) b2ll(6, reader->hexserial),
			(unsigned long long) b2ll(4, reader->hexserial+2),
			card_id, b2i(4, boxID));
	return OK;
}

/* example ecm
81 70 76 22 91 14 96 01 0C 17 C4 00 12 09 5A 00
98 80 B0 D8 65 32 1B 26 03 F0 21 3B 8C 07 15 12
58 80 3A 14 96 53 22 91 C0 04 17 C5 61 C0 FF 3A
D9 3C EE 51 CD 6E 70 A2 EC 71 FF 0F D6 E8 52 D6
69 C2 7F 07 0F 83 02 09 00 01 00 01 B5 AC C0 8D
7A B0 65
*/

static int32_t tongfang_do_ecm(struct s_reader *reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
	uchar ecm_buf[512];	//{0x80,0x3a,0x00,0x01,0x53};
	uchar *ecm_cmd=ecm_buf;
	int32_t ecm_len=0;
	uchar data[256]={0};

	char *tmp;
	int32_t i = 0;
	size_t write_len = 0;
	size_t read_size = 0;
	size_t data_len = 0;
	uint16_t status = 0;

	def_resp;
	if(cs_malloc(&tmp, er->ecmlen * 3 + 1))
	{
		rdr_log_dbg(reader, D_IFD, "ECM: %s", cs_hexdump(1, er->ecm, er->ecmlen, tmp, er->ecmlen * 3 + 1));
		NULLFREE(tmp);
	}
	if((ecm_len = check_sct_len(er->ecm, 3, sizeof(er->ecm))) < 0) {
		rdr_log(reader, "error: check_sct_len failed, smartcard section too long %d > %zd", SCT_LEN(er->ecm), sizeof(er->ecm) - 3);
		return ERROR;
	}

	for(i = 0; i < ecm_len; i++)
	{
		if((i < ecm_len-1) && (er->ecm[i] == 0x80) && (er->ecm[i+1] == 0x3a)
		     && (er->ecm[i+2] == er->ecm[5]) && (er->ecm[i+3]==er->ecm[6]))
			break;
	}
	if(i == ecm_len){
		rdr_log(reader, "error: invalid ecm data...");
		return ERROR;
	}

	write_len = er->ecm[i + 4] + 5;
	if(write_len > (sizeof(ecm_buf))){
		if(write_len > MAX_ECM_SIZE || !cs_malloc(&ecm_cmd,write_len)){
			rdr_log(reader,"error: ecm data too long,longer than sizeof ecm_buf(%zd > %zd).",write_len,sizeof(ecm_cmd));
			return ERROR;
		}
	}

	memcpy(ecm_cmd, er->ecm + i, write_len);
	write_cmd(ecm_cmd, ecm_cmd + 5);
	if((cta_lr - 2) >= 2)
	{
		read_size = cta_res[1];
	}
	else
	{
		if((cta_res[cta_lr - 2] & 0xf0) == 0x60)
		{
			read_size = cta_res[cta_lr - 1];
		}
		else
		{
			char ecm_cmd_string[150];
			rdr_log(reader, "error: card send parsing ecm command failed!(%s)",cs_hexdump(1,ecm_cmd,write_len,ecm_cmd_string, sizeof(ecm_cmd_string)));
			if(ecm_cmd != ecm_buf)
				NULLFREE(ecm_cmd);
			return ERROR;
		}
	}

	if(ecm_cmd != ecm_buf)
		NULLFREE(ecm_cmd);

	if(read_size > sizeof(data)){
		rdr_log(reader, "error: read_size is bigger than sizeof data.(%zd>%zd)",read_size,sizeof(data));
		return ERROR;
	}

	data_len = tongfang_read_data(reader, read_size, data, &status);
	if(data_len < 23) {
		char ecm_string[256*3+1];
		rdr_log(reader, "error: card return cw data failed,return data len=%zd(ECM:%s).",data_len,
				cs_hexdump(1,er->ecm,er->ecmlen,ecm_string, sizeof(ecm_string)));
		return ERROR;
	}

	if(!(er->ecm[0] & 0x01))
	{
		memcpy(ea->cw, data + 8, 16);
	}
	else
	{
		memcpy(ea->cw, data + 16, 8);
		memcpy(ea->cw + 8, data + 8, 8);
	}

	// All zeroes is no valid CW, can be a result of wrong boxid
	if(!cw_is_valid(ea->cw) || !cw_is_valid(ea->cw + 8)) {
		rdr_log(reader,"error: cw is invalid.");
		return ERROR;
	}

	if(reader->cas_version >=3 ){
		des_ecb_encrypt(ea->cw, reader->tongfang3_commkey, 8);
		des_ecb_encrypt(ea->cw + 8, reader->tongfang3_commkey, 8);
	}

	return OK;
}

static int32_t tongfang_get_emm_type(EMM_PACKET *ep, struct s_reader *UNUSED(reader))
{
	ep->type = UNKNOWN;
	return 1;
}

static int32_t tongfang_do_emm(struct s_reader *reader, EMM_PACKET *ep)
{
	uchar emm_cmd[200];
	def_resp;
	int32_t write_len;

	if(SCT_LEN(ep->emm) < 8) { return ERROR; }

	write_len = ep->emm[15] + 5;
	memcpy(emm_cmd, ep->emm + 11, write_len);

	write_cmd(emm_cmd, emm_cmd + 5);

	return OK;
}

static int32_t tongfang_card_info(struct s_reader *reader)
{
	static const uchar get_provider_cmd[] = {0x80, 0x44, 0x00, 0x00, 0x08};
	uchar get_subscription_cmd[] = {0x80,0x48,0x00,0x01,0x04,0x01,0x00,0x00,0x13};
	static const uchar get_agegrade_cmd[] = {0x80, 0x46, 0x00, 0x00, 0x04, 0x03, 0x00, 0x00, 0x09};

	def_resp;
	int32_t i;
	uchar data[256];
	uint16_t status = 0;

	write_cmd(get_provider_cmd, NULL);
	if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00)) { return ERROR; }

	reader->nprov = 0;
	memset(reader->prid, 0x00, sizeof(reader->prid));
	for(i = 0; i < 4; i++)
	{
		if((cta_res[i*2] != 0xFF) || (cta_res[i*2 + 1] != 0xFF)){
			int j;
			int found = 0;
			for(j=0; j < reader->nprov; j++){
				if(reader->nprov > 0 && reader->prid[j][2] == cta_res[i * 2] && reader->prid[j][3] == cta_res[i *2 + 1]){
					found = 1;
					break;
				}
			}

			if(found == 1)
				continue;
			memcpy(&reader->prid[reader->nprov][2],cta_res + i * 2, 2);
			rdr_log(reader, "Provider:%06X", b2i(2,cta_res + i * 2));
			reader->nprov ++;

		}
	}

	cs_clear_entitlement(reader);
	for(i = 0; i < reader->nprov; i++)
	{
			get_subscription_cmd[2] = reader->prid[i][2] ;
			get_subscription_cmd[3] = reader->prid[i][3];
			write_cmd(get_subscription_cmd, get_subscription_cmd + 5);
			if((cta_res[cta_lr - 2] & 0xF0) != 0x60)
				continue;
			if((3 > tongfang_read_data(reader, cta_res[cta_lr - 1], data, &status)) || (status != 0x9000))
				continue;

			uint16_t count = data[2];
			int j;
			for(j = 0; j < count; j++){
				//if(!data[j * 13 + 4]) continue;

				time_t start_t,end_t;
				//946656000L = 2000-01-01 00:00:00
				start_t = 946656000L + (b2i(2, data + j * 13 + 8) - 1) * 24 * 3600L;
				end_t = 946656000L + (b2i(2, data + j * 13 + 12) - 1) * 24 * 3600L;
				uint64_t product_id=b2i(2, data + j * 13 + 5);

				struct tm  tm_start, tm_end;
				char start_day[11], end_day[11];

				localtime_r(&start_t, &tm_start);
				localtime_r(&end_t, &tm_end);
				strftime(start_day, sizeof(start_day), "%Y/%m/%d", &tm_start);
				strftime(end_day, sizeof(end_day), "%Y/%m/%d", &tm_end);

				if (!j)
					rdr_log(reader, "entitlements for provider: %d (%04X:%06X)", i, reader->caid, b2i(2, &reader->prid[i][2]));
				rdr_log(reader, "    chid: %04"PRIX64"  date: %s - %s", product_id, start_day, end_day);
				
				cs_add_entitlement(reader, reader->caid, b2i(2, &reader->prid[i][2]), product_id, 0, start_t, end_t, 0, 1);
			}

	}
	write_cmd(get_agegrade_cmd, get_agegrade_cmd + 5);
	if((cta_res[cta_lr - 2] & 0xF0) != 0x60) { return OK; }

	tongfang_read_data(reader, cta_res[cta_lr - 1], data, &status);
	if(status != 0x9000) { return OK; }

	rdr_log(reader, "AgeGrade:%d", (data[0] + 3));

	return OK;
}

const struct s_cardsystem reader_tongfang =
{
	.desc         = "tongfang",
	.caids        = (uint16_t[]){ 0x4A02, 0 },
	.do_emm       = tongfang_do_emm,
	.do_ecm       = tongfang_do_ecm,
	.card_info    = tongfang_card_info,
	.card_init    = tongfang_card_init,
	.get_emm_type = tongfang_get_emm_type,
};

#endif
