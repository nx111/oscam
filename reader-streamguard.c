#include "globals.h"
#ifdef READER_STREAMGUARD
#include "reader-common.h"
#include "cscrypt/des.h"
#include "cscrypt/md5.h"
#include "oscam-time.h"
#include <time.h>

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

static void  decrypt_cw_ex(int32_t tag, int32_t a, int32_t b, int32_t c, uint8_t *data)
{
    uint8_t key1[16] = {0xB5, 0xD5, 0xE8, 0x8A, 0x09, 0x98, 0x5E, 0xD0, 0xDA, 0xEE, 0x3E, 0xC3, 0x30, 0xB9, 0xCA, 0x35};
    uint8_t key2[16] = {0x5F, 0xE2, 0x76, 0xF8, 0x04, 0xCB, 0x5A, 0x24, 0x79, 0xF9, 0xC9, 0x7F, 0x23, 0x21, 0x45, 0x84};
    uint8_t key3[16] = {0xE3, 0x78, 0xB9, 0x8C, 0x74, 0x55, 0xBC, 0xEE, 0x03, 0x85, 0xFD, 0xA0, 0x2A, 0x86, 0xEF, 0xAF};
	uint8_t keybuf[22] = {0xCC,0x65,0xE0, 0xCB,0x60,0x62,0x06,0x33,0x87,0xE3,0xB5,0x2D,0x4B,0x12,0x90,0xD9,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t md5key[16];
	uint8_t md5tmp[20];
	uint8_t deskey1[8], deskey2[8];

	if(tag != 0x120 && tag != 0x100 && tag != 0x10A && tag != 0x101 && tag != 0x47 && tag != 0x92 && tag == 0xDE)
		return;

	if(tag == 0x100 || tag == 0x92){
		key1[15] = 0x37;
		memcpy(keybuf,key1,sizeof(key1));
	}
	else if(tag == 0x101){
		key2[15] = 0x87;
		memcpy(keybuf,key2,sizeof(key2));
	}
	else if(tag == 0x47){
		key3[15] = 0xB3;
		memcpy(keybuf,key3,sizeof(key3));
	}
	keybuf[16] = (c >> 24) & 0xFF;
	keybuf[17] = (a >> 8) & 0xFF;
	keybuf[18] = (c >> 16) & 0xFF;
	keybuf[19] = (c >> 8) & 0xFF;
	keybuf[20] = c & 0xFF;
	keybuf[21] = a & 0xFF;
	MD5(keybuf,22,md5tmp);

	md5tmp[16] = (b >> 8)& 0xFF;
	md5tmp[17] = b & 0xFF;
	md5tmp[18] = (a >> 8) & 0xFF;
	md5tmp[19] = a & 0xff;
	MD5(md5tmp,20,md5key);

	//3des decrypt
	memcpy(deskey1, md5key, 8);
	memcpy(deskey2, md5key + 8, 8);
	des_ecb_decrypt(data, deskey1, 16);  //decrypt
	des_ecb_encrypt(data, deskey2, 16);  //crypt
	des_ecb_decrypt(data, deskey1, 16);  //decrypt
}

static int32_t streamguard_read_data(struct s_reader *reader, uint8_t size, uint8_t *cta_res, uint16_t *status)
{
	static uint8_t read_data_cmd[]={0x00,0xc0,0x00,0x00,0xff};
	uint16_t cta_lr;

	read_data_cmd[4] = size;
	write_cmd(read_data_cmd, NULL);

	*status = (cta_res[cta_lr - 2] << 8) | cta_res[cta_lr - 1];

	return(cta_lr - 2);
}

static int32_t streamguard_card_init(struct s_reader *reader, ATR* newatr)
{
	uint8_t get_ppua_cmd[7] = {0x00,0xa4,0x04,0x00,0x02,0x3f,0x00};
	uint8_t get_serial_cmd[11] = {0x00,0xb2,0x00,0x05,0x06,0x00,0x01,0xff,0x00,0x01,0xff};
	uint8_t begin_cmd2[5] = {0x00,0x84,0x00,0x00,0x08};
	uint8_t begin_cmd3[11] = {0x00,0x20,0x04,0x02,0x06,0x12,0x34,0x56,0x78,0x00,0x00};
	uint8_t begin_cmd4[5] = {0x00,0xFC,0x00,0x00,0x00};
	uint8_t pairing_cmd[25] = {0x80,0x5A,0x00,0x00,0x10,0x36,0x9A,0xEE,0x31,0xB2,0xDA,0x94,
				 0x3D,0xEF,0xBA,0x10,0x22,0x67,0xA5,0x1F,0xFB,0x3B,0x9E,0x1F,0xCB};
	uint8_t confirm_pairing_cmd[9] = {0x80,0x5A,0x00,0x01,0x04,0x3B,0x9E,0x1F,0xCB};

	uint8_t seed[] = {0x00,0x00,0x00,0x00,0x24,0x30,0x28,0x73,0x40,0x33,0x46,0x2C,0x6D,0x2E,0x7E,0x3B,0x3D,0x6E,0x3C,0x37};
	uint8_t randkey[16]={0};
	uint8_t key1[8], key2[8];
	uint8_t data[257];
	uint8_t boxID[4] = {0xff, 0xff, 0xff, 0xff};
	uint8_t md5_key[16] = {0};

	int32_t data_len = 0;
	uint16_t status = 0;

	def_resp;
	get_atr;

	//rdr_log(reader, "[reader-streamguard] StreamGuard atr_size:%d, atr[0]:%02x, atr[1]:%02x", atr_size, atr[0], atr[1]);

	if ((atr_size != 4) || (atr[0] != 0x3b) || (atr[1] != 0x02)) return ERROR;

	reader->caid = 0x4AD2;
	if(reader->cas_version < 10){
        if (atr[2] < 0x20) {
            reader->cas_version = 10;
        } else if (atr[2] > 0x20) {
            reader->cas_version = 30;
        } else {
            reader->cas_version = 20;
        }
	}
	memset(reader->des_key, 0, sizeof(reader->des_key));

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

	if(reader->cas_version >= 20){
		write_cmd(begin_cmd2, begin_cmd2 + 5);
		if((cta_res[cta_lr - 2] & 0xf0) == 0x60) {
			data_len = streamguard_read_data(reader,cta_res[cta_lr - 1], data, &status);
			if(data_len < 0){
				rdr_log(reader, "error: init read data failed 1.");
				return ERROR;
			}
		}
		else{
			rdr_log(reader, "error: init begin_cmd2 failed 1.");
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

	if(reader->cas_version >= 20){
		memcpy(seed,data + 3, 4);
		MD5(seed,sizeof(seed),md5_key);

		write_cmd(begin_cmd2, begin_cmd2 + 5);

		if((cta_res[cta_lr - 2] & 0xf0) != 0x60) {
			rdr_log(reader, "error: init begin cmd2 failed.");
			return ERROR;
		}

		data_len = streamguard_read_data(reader,cta_res[cta_lr - 1], data, &status);
		if(data_len < 0){
			rdr_log(reader, "error: init read data failed for begin cmd2.");
			return ERROR;
		}

		write_cmd(begin_cmd3, begin_cmd3 + 5);
		if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00)){
			rdr_log(reader, "error: init begin cmd3 failed.");
			return ERROR;
		}

		write_cmd(begin_cmd4, NULL);
		if((cta_res[cta_lr - 2] & 0xF0) != 0x60){
			rdr_log(reader, "error: init begin cmd4 failed.");
			return ERROR;
		}
		data_len = streamguard_read_data(reader,cta_res[cta_lr - 1], data, &status);
		if(data_len < 0){
			rdr_log(reader, "error: init read data failed for begin cmd4.");
			return ERROR;
		}


		memcpy(key1, md5_key, 8);
		memcpy(key2, md5_key + 8, 8);
		memcpy(reader->des_key,randkey,sizeof(reader->des_key));
		if(reader->cas_version >= 30){
			des_ecb_encrypt(randkey, key1, 16);  //encrypt
			des_ecb_decrypt(randkey, key2, 16);  //decrypt
			des_ecb_encrypt(randkey, key1, 16);  //encrypt
			memcpy(pairing_cmd + 5, randkey, 16);
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

	rdr_log(reader, "type: StreamGuard, caid: %04X, serial: {%llu}, hex serial: {%02x%02x%02x%02x}，  BoxID: {%08X}",
			reader->caid, (unsigned long long)b2ll(6, reader->hexserial), reader->hexserial[2],
			reader->hexserial[3], reader->hexserial[4], reader->hexserial[5], b2i(4, boxID));

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
	uint8_t ecm_cmd[256] = {0x80,0x32,0x00,0x00,0x3C};
	uint8_t data[256];
	int32_t ecm_len;
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
		rdr_log(reader, "error: card return cw data failed,request data len must > 18, return data len=%d.", data_len);
		return ERROR;
	}
	uint16_t tag=0;
	for(i = 0; i < (data_len - 1); i++)
	{
		if (reader->cas_version >= 30 && data[i] == 0xB4 && data[i + 1] == 0x04)
			tag = b2i(2, data + i + 4);
;
		if (data[i] == 0x83 && data[i + 1] == 0x16)
		{
			if(reader->cas_version <= 20 || data[i + 2] != 0 || data[i + 3] != 1)
				break;
		}
	}

	if (i >= data_len || (!is_valid(data + i, 8)) || (!is_valid(data + i + 8, 8))  )
	{
		rdr_log(reader, "error: not valid cw data...");
		return ERROR;
	}

	if((er->ecm[0] == 0x80))
	{
		memcpy(ea->cw +  0, data + i + 6, 4);
		memcpy(ea->cw +  4, data + i + 6 + 4 + 1, 4);
		memcpy(ea->cw +  8, data + i + 6 + 8 + 1, 4);
		memcpy(ea->cw + 12, data + i + 6 + 8 + 4 + 1 + 1, 4);
	}
	else
	{
		memcpy(ea->cw +  0, data + i + 6 + 8 + 1, 4);
		memcpy(ea->cw +  4, data + i + 6 + 8 + 4 + 1 + 1, 4);
		memcpy(ea->cw +  8, data + i + 6, 4);
		memcpy(ea->cw + 12, data + i + 6 + 4 + 1, 4);
	}

	if(reader->cas_version < 20)
		return OK;

	if(((uint16_t)(ea->cw[0]) + (uint16_t)(ea->cw[1]) + (uint16_t)(ea->cw[2])) == (uint16_t)(ea->cw[3])
	   && ((uint16_t)(ea->cw[4]) + (uint16_t)(ea->cw[5]) + (uint16_t)(ea->cw[6])) == (uint16_t)(ea->cw[7])
	   && ((uint16_t)(ea->cw[8]) + (uint16_t)(ea->cw[9]) + (uint16_t)(ea->cw[10])) == (uint16_t)(ea->cw[11])
	   && ((uint16_t)(ea->cw[12]) + (uint16_t)(ea->cw[13]) + (uint16_t)(ea->cw[14])) == (uint16_t)(ea->cw[15]))
		return OK;

	if((data[i + 5] & 0x10) != 0){
		//3des decrypt
		uint8_t key1[8], key2[8];
		memcpy(key1, reader->des_key, 8);
		memcpy(key2, reader->des_key + 8, 8);
		des_ecb_decrypt(ea->cw, key1, sizeof(ea->cw));  //decrypt
		des_ecb_encrypt(ea->cw, key2, sizeof(ea->cw));  //crypt
		des_ecb_decrypt(ea->cw, key1, sizeof(ea->cw));  //decrypt
	}

	if(tag == 0x120 || tag == 0x100 || tag == 0x10A || tag == 0x101 || tag == 0x47 || tag == 0x92 || tag == 0xDE){
		int32_t a=b2i(2, data);
		int32_t b=b2i(2, data + i + 2);
		decrypt_cw_ex(tag, a, b, tag, ea->cw);
	}
	return OK;
}


static int32_t streamguard_get_emm_type(EMM_PACKET *ep, struct s_reader *UNUSED(reader))
{
	ep->type = EMM_UNKNOWN;		// need more working.
	return OK;
}

static int32_t streamguard_get_emm_filter(struct s_reader *rdr, struct s_csystem_emm_filter **emm_filters, uint32_t *filter_count)
{
	struct s_csystem_emm_filter *filters = *emm_filters;

	if ((emm_filters == NULL) || (emm_filters[0] == NULL) || filter_count == NULL) {
		return ERROR;
	}

	if (rdr->hexserial[2] + rdr->hexserial[3] + rdr->hexserial[4] + rdr->hexserial[5] == 0) {
		rdr_log(rdr, "error: get emm filter failed (card serial is empty)!");
		return ERROR;
	}

	memset(filters[0].filter, 0, sizeof(filters[0].filter));
	memset(filters[0].mask, 0, sizeof(filters[0].mask));

	filters[0].type = EMM_UNKNOWN;		// need more working.
	filters[0].enabled = 1;
	filters[0].filter[0] = 0x82;
	filters[0].mask[0] = 0xFF;
	
	memset(filters[0].filter + 1, 0xFF, 4);
	memcpy(filters[0].mask + 1, rdr->hexserial + 2, 4);
	*filter_count = 1;

	return OK;
}

static int32_t streamguard_do_emm(struct s_reader *reader, EMM_PACKET *ep)
{
	uint8_t emm_cmd[200] = {0x80,0x30,0x00,0x00,0x4c};
	def_resp;
	int32_t len;
	uint16_t status;
	uint8_t data[256];
    
	struct timeb now;
	cs_ftime(&now);
	int64_t gone = comp_timeb(&now, &reader->emm_last);
	if(gone < 19*1000) {
		return ERROR;
	}

	if(SCT_LEN(ep->emm) < 8) {
		rdr_log(reader, "error: emm data too short (%d < 8)!", SCT_LEN(ep->emm));
		return ERROR;
	}

	if(reader->cas_version >= 30 && ep->emm[0] == 0x83){
		rdr_log(reader, "Receive refresh cmd");
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

	// do_emm 2
	len = SCT_LEN(ep->emm) - 3;
	emm_cmd[4] = len;
	memcpy(emm_cmd + 5, ep->emm + 3, len);
	if (len < 5) {
		rdr_log(reader, "error: emm cmd len to small(%d < 5)", len);
		return ERROR;
	}
	memcpy(emm_cmd + 5 + 1, reader->hexserial + 2, 4);
	write_cmd(emm_cmd, emm_cmd + 5);
	
	if((cta_res[cta_lr - 2] & 0xf0) != 0x60){
		rdr_log(reader,"error: send emm cmd 2 failed!");
		return ERROR;
	}
	len = cta_res[1];
	if((len != streamguard_read_data(reader, len, data, &status)) ||
	    (cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00)){
		rdr_log(reader, "error: read data failed for emm cmd 2 returned.");
		return ERROR;
	}

	return OK;
}

static int32_t streamguard_card_info(struct s_reader *reader)
{
	uint8_t get_provid_cmd[12] = {0x00,0xb2,0x00,0x06,0x07,0x00,0x05,0xff,0x00,0x02,0xff,0xff};
	uint8_t get_subscription_cmd[12] = {0x00,0xb2,0x00,0x07,0x07,0x00,0xfa,0xff,0x00,0x02,0x03,0xd4};
	uint8_t data[256];
	uint16_t status = 0;

	def_resp;

	write_cmd(get_provid_cmd, get_provid_cmd + 5);
	if((cta_res[cta_lr - 2] & 0xf0) != 0x60) {
		rdr_log(reader, "error: get provid  failed.");
		return ERROR;
	}
	int nextReadSize= cta_res[cta_lr - 1];
	int data_len = streamguard_read_data(reader,nextReadSize, data, &status);
	if(data_len < 0){
		rdr_log(reader, "error: read data failed for get provid.");
		return ERROR;
	}

	reader->nprov = 0;
	int count = ((nextReadSize - 3) / 46) < 4 ? (nextReadSize - 3) / 46 : 4;
	int i;
	for(i = 0; i < count; i++){
		if(data[i * 46 + 3] != 0xFF || data[i * 46 + 4] != 0xFF ){
			int j;
			int found = 0;
			for(j = 0; j < reader->nprov; j++){
				if(reader->nprov > 0 && reader->prid[j][2] == data[i * 46 + 3] && reader->prid[j][3] == data[i * 46 + 4]){
					found = 1;
					break;
				}
			}
			if(found == 1) continue;

			memcpy(&reader->prid[reader->nprov][2], data + i * 46 + 3, 2);
			rdr_log(reader, "Provider:%06X", b2i(2, data + i * 46 + 3));
			reader->nprov ++;
			if(data[i * 46 + 3] == 0x09 && data[i * 46 + 4] == 0x88){
				reader->caid = 0x4AD3;
				break;
			}
		}
	}
	int bankid=0;
	for(i = 0; i < reader->nprov; i++){
		int j=0;
		get_subscription_cmd[10] = reader->prid[i][2];
		get_subscription_cmd[11] = reader->prid[i][3];
                for(;;){
			get_subscription_cmd[5] = bankid;
			write_cmd(get_subscription_cmd, get_subscription_cmd + 5);
			if((cta_res[cta_lr - 2] & 0xf0) != 0x60) {
				rdr_log(reader, "error:  get subscription failed.");
				break;
			}

			data_len = streamguard_read_data(reader,cta_res[cta_lr - 1], data, &status);
			if(data_len < 0){
				rdr_log(reader, "error: read data failed for get subscription.");
				break;
			}

			count = data[1];
			int k;
			for(k = 0; k < count; j++,k++){
				//if(data[j * 19 + 2 + 3] == 0 && data[j * 19 + 3 + 3] == 0) continue;

				time_t start_t,end_t,subscription_t;
				subscription_t = b2i(4, data + 3 + j * 19 + 4);
				start_t = b2i(4, data + j * 19 + 9 + 3);
				if((uint32_t)start_t == 0xFFFFFFFFLU)
					start_t = subscription_t;
				end_t = b2i(4, data + 3 + j * 19 + 13);
				uint64_t product_id=b2i(2, data + 3 + j * 19 + 2);

				struct tm  tm_start, tm_end, tm_subscription;
				char start_day[20], end_day[20], subscription_day[20];

				localtime_r(&start_t, &tm_start);
				localtime_r(&end_t, &tm_end);
				localtime_r(&subscription_t, &tm_subscription);
				if(tm_subscription.tm_year >= 117){
					tm_end.tm_year += 1;
					end_t = cs_timegm(&tm_end);
				}

				strftime(subscription_day, sizeof(subscription_day), "%Y-%m-%d %H:%M:%S", &tm_subscription);
				strftime(start_day, sizeof(start_day), "%Y-%m-%d %H:%M:%S", &tm_start);
				strftime(end_day, sizeof(end_day), "%Y-%m-%d %H:%M:%S", &tm_end);

				if(!j)
					rdr_log(reader, "entitlements for provider: %d (%04X:%06X)", i, reader->caid, b2i(2, &reader->prid[i][2]));
				rdr_log(reader, "    chid: %04"PRIX64" auth:%s  valid:%s - %s", product_id,  subscription_day, start_day, end_day);

				cs_add_entitlement(reader, reader->caid, b2i(2, &reader->prid[i][2]), product_id, 0, start_t, end_t, 0, 1);
			}
			if(data[0] == 0)
				break;
			bankid = data[0];
		}
	}

	return OK;
}

const struct s_cardsystem reader_streamguard =
{
	.desc         = "streamguard",
	.caids        = (uint16_t[]){ 0x4AD2, 0x4AD3, 0 },
	.do_emm       = streamguard_do_emm,
	.do_ecm       = streamguard_do_ecm,
	.card_info    = streamguard_card_info,
	.card_init    = streamguard_card_init,
	.get_emm_type = streamguard_get_emm_type,
	.get_emm_filter = streamguard_get_emm_filter,
};

#endif
