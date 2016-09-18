#include "globals.h"
#ifdef READER_STREAMGUARD
#include "reader-common.h"
//#include "cscrypt/md5.h"
#include "cscrypt/des.h"

static int32_t is_valid(uchar *buf, size_t len)
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		if(buf[i] != 0)
		{
			return OK;
		}
	}
	return ERROR;
}

static int32_t streamguard_read_data(struct s_reader *reader, uchar size, uchar *cta_res, uint16_t *status)
{
	static uchar read_data_cmd[]={0x00,0xc0,0x00,0x00,0xff};
	uint16_t cta_lr;

	read_data_cmd[4] = size;
	write_cmd(read_data_cmd, NULL);

	*status = (cta_res[cta_lr - 2] << 8) | cta_res[cta_lr - 1];

	return(cta_lr - 2);
}

static int32_t streamguard_card_init(struct s_reader *reader, ATR* newatr)
{
	uchar get_ppua_cmd[7] = {0x00,0xa4,0x04,0x00,0x02,0x3f,0x00};
	uchar get_serial_cmd[11] = {0x00,0xb2,0x00,0x05,0x06,0x00,0x01,0xff,0x00,0x01,0xff};
	uchar unknown_cmd1[5] = {0x00,0x84,0x00,0x00,0x08};
	uchar unknown_cmd2[11] = {0x00,0x20,0x04,0x02,0x06,0x12,0x34,0x56,0x78,0x00,0x00};
	uchar unknown_cmd3[12] = {0x00,0xb2,0x00,0x06,0x07,0x00,0x05,0xff,0x00,0x02,0xff,0xff};
	uchar unknown_cmd4[12] = {0x00,0xb2,0x00,0x0d,0x07,0x00,0x01,0x28,0x00,0x02,0x05,0xd2};
	uchar pairing_cmd[25] = {0x80,0x5A,0x00,0x00,0x10,0x36,0x9A,0xEE,0x31,0xB2,0xDA,0x94,
				 0x3D,0xEF,0xBA,0x10,0x22,0x67,0xA5,0x1F,0xFB,0x3B,0x9E,0x1F,0xCB};
	uchar confirm_pairing_cmd[9] = {0x80,0x5A,0x00,0x01,0x04,0x3B,0x9E,0x1F,0xCB};

	//uchar seed[] = {0x00,0x00,0x00,0x00,0x24,0x30,0x28,0x73,0x40,0x33,0x46,0x2C,0x6D,0x2E,0x7E,0x3B,0x3D,0x6E,0x3C,0x37};
	uchar randkey[16] = { 0x36,0x9A,0xEE,0x31,0xB2,0xDA,0x94,0x3D,0xEF,0xBA,0x10,0x22,0x67,0xA5, 0x1F,0xFB };
	uchar key1[8], key2[8];
	uchar data[257];
	uchar boxID[4] = {0xff, 0xff, 0xff, 0xff};
	uchar md5_key[16] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};

	int32_t data_len = 0;
	uint16_t status = 0;

	def_resp;
	get_atr;

	rdr_log(reader, "[reader-streamguard] StreamGuard atr_size:%d, atr[0]:%02x, atr[1]:%02x", atr_size, atr[0], atr[1]);

	if ((atr_size != 4) || (atr[0] != 0x3b) || (atr[1] != 0x02)) return ERROR;

	reader->caid = 0x4AD2;
	reader->cas_version=2;	//new version

	memset(reader->des_key, 0, sizeof(reader->des_key));

	// For now, only one provider, 0000
	reader->nprov = 1;
	memset(reader->prid, 0x00, sizeof(reader->prid));

	rdr_log(reader, "[reader-streamguard] StreamGuard card detected");

	write_cmd(get_ppua_cmd, get_ppua_cmd + 5);
	if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00)){
		rdr_log(reader, "error: init get ppua 1 failed.");
		return ERROR;
	}
	get_ppua_cmd[5] = 0x4A;
	write_cmd(get_ppua_cmd, get_ppua_cmd + 5);
	if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00)){
		rdr_log(reader, "error: init get ppua 2 failed.");
		return ERROR;
	}

	if(reader->cas_version > 1){
		write_cmd(unknown_cmd1, unknown_cmd1 + 5);
		if((cta_res[cta_lr - 2] & 0xf0) == 0x60) {
			data_len = streamguard_read_data(reader,cta_res[cta_lr - 1], data, &status);
			if(data_len < 0){
				rdr_log(reader, "error: init read data failed 1.");
				return ERROR;
			}
		}
		else{
			rdr_log(reader, "error: init unknown_cmd1 failed 1.");
			return ERROR;
		}
	}

	write_cmd(get_serial_cmd, get_serial_cmd + 5);
	if((cta_res[cta_lr - 2] & 0xf0) != 0x60) {
		rdr_log(reader, "error: init run get serial cmd failed.");
		return ERROR;
	}

	data_len = streamguard_read_data(reader, cta_res[cta_lr - 1], data, &status);
	if(status != 0x9000 || data_len < 0){
		rdr_log(reader, "error: init read data failed for get serial.");
		return ERROR;
	}
	memset(reader->hexserial, 0, 8);
	memcpy(reader->hexserial + 2, data + 3, 4);

	if(reader->cas_version > 1){
		//memcpy(seed,data + 3, 4);
		//MD5(seed,sizeof(seed),md5_key);

		write_cmd(unknown_cmd1, unknown_cmd1 + 5);

		if((cta_res[cta_lr - 2] & 0xf0) != 0x60) {
			rdr_log(reader, "error: init unknown_cmd1 failed.");
			return ERROR;
		}

		data_len = streamguard_read_data(reader,cta_res[cta_lr - 1], data, &status);
		if(data_len < 0){
			rdr_log(reader, "error: init read data failed 2.");
			return ERROR;
		}

		write_cmd(unknown_cmd2, unknown_cmd2 + 5);
		if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00)){
			rdr_log(reader, "error: init unknown_cmd2 failed.");
			return ERROR;
		}

		write_cmd(unknown_cmd3, unknown_cmd3 + 5);
		if((cta_res[cta_lr - 2] & 0xf0) != 0x60) {
			rdr_log(reader, "error: init unknown_cmd3 failed.");
			return ERROR;
		}
		data_len = streamguard_read_data(reader,cta_res[cta_lr - 1], data, &status);
		if(data_len < 0){
			rdr_log(reader, "error: init read data failed for unknow_cmd3.");
			return ERROR;
		}
		//unkown_id[0] = data[3];
		//unkown_id[1] = data[4];

		unknown_cmd4[10] = data[3];
		unknown_cmd4[11] = data[4];
		write_cmd(unknown_cmd4, unknown_cmd4 + 5);
		if((cta_res[cta_lr - 2] & 0xf0) != 0x60) {
			rdr_log(reader, "error: init unknown_cmd4 failed.");
			return ERROR;
		}
		data_len = streamguard_read_data(reader,cta_res[cta_lr - 1], data, &status);
		if(data_len < 0){
			rdr_log(reader, "error: init read data failed for unknow_cmd4.");
			return ERROR;
		}

		if(reader->boxid){
			pairing_cmd[4]=0x14;
			boxID[0] = (reader->boxid>>24) & 0xFF;
			boxID[1] = (reader->boxid>>16) & 0xFF;
			boxID[2] = (reader->boxid>>8) & 0xFF;
			boxID[3] = (reader->boxid) & 0xFF;
			memcpy(pairing_cmd + 21, boxID,4);
		}
		write_cmd(pairing_cmd, pairing_cmd + 5);
		if((cta_res[cta_lr - 2] & 0xf0) != 0x60) {
			rdr_log(reader, "error: init pairing failed.");
			return ERROR;
		}
		data_len = streamguard_read_data(reader,cta_res[cta_lr - 1], data, &status);
		if(data_len < 0){
			rdr_log(reader, "error: init read data failed for pairing.");
			return ERROR;
		}

		//3des decrypt
		memcpy(key1, md5_key, 8);
		memcpy(key2, md5_key + 8, 8);
		des_ecb_decrypt(randkey, key1, sizeof(randkey));  //decrypt
		des_ecb_encrypt(randkey, key2, sizeof(randkey));  //crypt
		des_ecb_decrypt(randkey, key1, sizeof(randkey));  //decrypt

		memcpy(reader->des_key,randkey,sizeof(reader->des_key));

		if(reader->boxid){
			memcpy(confirm_pairing_cmd + 5, boxID, 4);
			write_cmd(confirm_pairing_cmd, confirm_pairing_cmd + 5);
			if((cta_res[cta_lr - 2] & 0xf0) != 0x60) {
				rdr_log(reader, "error: init confirm_pairing_cmd failed.");
				return ERROR;
			}
			data_len = streamguard_read_data(reader,cta_res[cta_lr - 1], data, &status);
			if(data_len < 0){
				rdr_log(reader, "error: init read data failed for confirm_pairing_cmd.");
				return ERROR;
			}
		}
	}

	rdr_log(reader, "type: StreamGuard, caid: %04X, serial: %llu, hex serial: %02x%02x%02x%02x",
			reader->caid, (unsigned long long)b2ll(6, reader->hexserial), reader->hexserial[2],
			reader->hexserial[3], reader->hexserial[4], reader->hexserial[5]);

	return OK;
}

/*
Example ecm:
80 30 79 00 0C 76 66 BC 57 C4 4F 33 0B 7D B2 90
95 9D 6F 0B 6D 40 4E 9A F1 13 03 40 12 7C B7 9D
E1 70 71 20 C7 FB 35 B1 EC 32 02 5C 0C 7E 04 CC
79 3D 84 4A AD DF DA DD 9E 4F E7 54 CF C0 17 2F
84 A5 4E 75 B1 6D E9 95 BE 8B 17 4A 07 96 03 B6
0E B7 7D 06 14 3A 2D 23 7F F8 BF 47 C4 70 F7 29
62 8E 02 CB B0 4C 51 93 FB AD 41 25 52 3A 54 4A
7B 58 FD 16 72 93 E9 A8 9B DA 23 25
*/
static int32_t streamguard_do_ecm(struct s_reader *reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
	uchar ecm_cmd[200] = {0x80,0x32,0x00,0x00,0x3C};
	uchar data[100];
	int32_t ecm_len;
	uchar* pbuf = data;
	int32_t i = 0;
	int32_t write_len = 0;
	def_resp;
	int32_t read_size = 0;
	int32_t data_len = 0;
	uint16_t status = 0;
	char *tmp;

	if((ecm_len = check_sct_len(er->ecm, 3, sizeof(er->ecm))) < 0) return ERROR;
	if(cs_malloc(&tmp, ecm_len * 3 + 1)){
		cs_debug_mask(D_IFD, "ECM: %s", cs_hexdump(1, er->ecm, ecm_len, tmp, ecm_len * 3 + 1));
		//rdr_log_dump(reader, er->ecm, ecm_len,"ECM:");
		free(tmp);
	}

	write_len = er->ecm[2] + 3;
	ecm_cmd[4] = write_len;
	memcpy(ecm_cmd + 5, er->ecm, write_len);
	write_cmd(ecm_cmd, ecm_cmd + 5);
	//rdr_log(reader, "result for send ecm_cmd,cta_lr=%d,status=0x%02X%02X",cta_lr,cta_res[cta_lr-2],cta_res[cta_lr-1]);

	if ((cta_lr - 2) >= 2)
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
			rdr_log(reader, "error: write ecm cmd failed.");
			return ERROR;
		}
	}

	data_len = streamguard_read_data(reader, read_size, data, &status);

	if(data_len <= 18){
		rdr_log(reader, "error: card return cw data failed,request data len=%d, return data len=%d.",read_size, data_len);
		return ERROR;
	}

	for(i = 0; i < (data_len - 1); i++)
	{
		if ((pbuf[0] == 0x83)&&(pbuf[1] == 0x16))
		{
			break;
		}
		pbuf++;
	}

	if (i >= data_len || (!is_valid(pbuf, 8)) || (!is_valid(pbuf + 8, 8))  )
	{
		rdr_log(reader, "error: not valid cw data...");
		return ERROR;
	}

	if((er->ecm[0] == 0x80))
	{
		memcpy(ea->cw +  0, pbuf + 6, 4);
		memcpy(ea->cw +  4, pbuf + 6 + 4 + 1, 4);
		memcpy(ea->cw +  8, pbuf + 6 + 8 + 1, 4);
		memcpy(ea->cw + 12, pbuf + 6 + 8 + 4 + 1 + 1, 4);
	}
	else
	{
		memcpy(ea->cw +  0, pbuf + 6 + 8 + 1, 4);
		memcpy(ea->cw +  4, pbuf + 6 + 8 + 4 + 1 + 1, 4);
		memcpy(ea->cw +  8, pbuf + 6, 4);
		memcpy(ea->cw + 12, pbuf + 6 + 4 + 1, 4);
	}

	if(is_valid(reader->des_key,sizeof(reader->des_key))){
		//3des decrypt
		uchar key1[8], key2[8];
		memcpy(key1, reader->des_key, 8);
		memcpy(key2, reader->des_key + 8, 8);
		des_ecb_decrypt(ea->cw, key1, sizeof(ea->cw));  //decrypt
		des_ecb_encrypt(ea->cw, key2, sizeof(ea->cw));  //crypt
		des_ecb_decrypt(ea->cw, key1, sizeof(ea->cw));  //decrypt
	}
	return OK;
}

static int32_t streamguard_get_emm_type(EMM_PACKET *ep, struct s_reader *UNUSED(reader))
{
	ep->type = UNKNOWN;
	return 1;
}

void streamguard_get_emm_filter(struct s_reader *UNUSED(reader), uchar *UNUSED(filter))
{
}

static int32_t streamguard_do_emm(struct s_reader *reader, EMM_PACKET *ep)
{
	uchar emm_cmd[200] = {0x80,0x30,0x00,0x00,0x4c};
	def_resp;
	int32_t len;
	uint16_t status;
	uchar data[100];

	if(SCT_LEN(ep->emm) < 8) {
		rdr_log(reader, "error: emm data too short !");
		return ERROR;
	}

	len = SCT_LEN(ep->emm);
	emm_cmd[4] = len;
	memcpy(emm_cmd + 5, ep->emm, len);

	write_cmd(emm_cmd, emm_cmd + 5);
	if((cta_res[cta_lr - 2] & 0xf0) != 0x60){
		rdr_log(reader,"error: send emm cmd failed!");
		return ERROR;
	}
	len = cta_res[1];
	if((len != streamguard_read_data(reader, len, data, &status)) ||
	    (cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00)){
		rdr_log(reader, "error: read data failed for emm cmd returned.");
		return ERROR;
	}

	return OK;
}

static int32_t streamguard_card_info(struct s_reader * UNUSED(reader))
{
	return OK;
}

const struct s_cardsystem reader_streamguard =
{
	.desc         = "streamguard",
	.caids        = (uint16_t[]){ 0x4A, 0 },
	.do_emm       = streamguard_do_emm,
	.do_ecm       = streamguard_do_ecm,
	.card_info    = streamguard_card_info,
	.card_init    = streamguard_card_init,
	.get_emm_type = streamguard_get_emm_type,
};

#endif
