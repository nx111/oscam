#include "globals.h"
#ifdef READER_JET
#include "reader-common.h"
#include "cscrypt/des.h"
#include "cscrypt/jet_twofish.h"
#include <time.h>

#define CRC16 0x8005
static const uint8_t vendor_key[32] = {0x54, 0xF5, 0x53, 0x12, 0xEA, 0xD4, 0xEC, 0x03, 0x28, 0x60, 0x80, 0x94, 0xD6, 0xC4, 0x3A, 0x48, 
                                         0x43, 0x71, 0x28, 0x94, 0xF4, 0xE3, 0xAB, 0xC7, 0x36, 0x59, 0x17, 0x8E, 0xCC, 0x6D, 0xA0, 0x9B};

#define jet_write_cmd(reader, cmd, len, encrypt_tag, title) \
 do { \
	uint8_t __cmd_buf[256];\
	uint8_t __cmd_tmp[256];\
	memset(__cmd_buf, 0, sizeof(__cmd_buf));\
	memcpy(__cmd_buf, cmd, len);\
	uint16_t crc=calc_crc16(__cmd_buf, len);\
	__cmd_buf[len] = crc >> 8;\
	__cmd_buf[len + 1] = crc & 0xFF;\
	if(!jet_encrypt(reader, encrypt_tag, __cmd_buf, len + 2, __cmd_tmp, sizeof(__cmd_tmp))){\
		rdr_log(reader, "error: %s failed... (encrypt cmd failed.)", title);\
		return ERROR;\
	}\
	write_cmd(__cmd_tmp, __cmd_tmp + 5);\
	if(cta_res[cta_lr - 2] != 0x90 || cta_res[cta_lr - 1] != 0x00){\
		rdr_log(reader, "error: %s failed... ", title);\
		return ERROR;\
	}\
  } while (0)

#define jet_write_cmd_hold(reader, cmd, len, encrypt_tag, title) \
 do { \
	uint8_t __cmd_buf[256];\
	uint8_t __cmd_tmp[256];\
	memset(__cmd_buf, 0, sizeof(__cmd_buf));\
	memcpy(__cmd_buf, cmd, len);\
	uint16_t crc=calc_crc16(__cmd_buf, len);\
	__cmd_buf[len] = crc >> 8;\
	__cmd_buf[len + 1] = crc & 0xFF;\
	if(jet_encrypt(reader, encrypt_tag, __cmd_buf, len + 2, __cmd_tmp, sizeof(__cmd_tmp))){\
		write_cmd(__cmd_tmp, __cmd_tmp + 5);\
		if(cta_res[cta_lr - 2] != 0x90 || cta_res[cta_lr - 1] != 0x00){\
			rdr_log(reader, "error: %s failed... ", title);\
		}\
	}\
	else \
		rdr_log(reader, "error: %s failed... (encrypt cmd failed.)", title);\
  } while (0)

static const uint16_t crc16_table[256]={
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
};


static uint16_t calc_crc16(uint8_t* in, int len) {
        int i = 0;
	uint16_t crc_value = 0;
        while(len >= 0) {
            int j = len - 1;
            if(len <= 0) {
                return crc_value;
            }

            crc_value = ((uint16_t)(((crc_value & 0xFFFF) >> 8) ^ crc16_table[((0xFFFF & crc_value) ^ (in[i] & 0xFF)) & 0xFF]));
            ++i;
            len = j;
        }

        return crc_value;
    }

static size_t jet_encrypt(struct s_reader* reader,uint8_t tag, uint8_t *data, size_t len, uint8_t *out, size_t maxlen)
{
	uint8_t buf[256];
	size_t i;
	size_t aligned_len = (len + 15) / 16 * 16;
	if((aligned_len + 7) > maxlen || (aligned_len + 7) > 256)
		return 0;
	memset(buf, 0xFF, aligned_len + 7);

	out[0] = 0x84;
	out[1] = tag;
	out[2] = 0;
	out[3] = 0;
	out[4] = aligned_len & 0xFF;
	memcpy(buf, data, len);
	if(tag == 0x15){
		twofish(buf,len, out + 5,maxlen,reader->jet_vendor_key,sizeof(vendor_key),0);
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
#if 0
static size_t jet_decrypt(struct s_reader* reader, uint8_t *data,  uint8_t *out, size_t maxlen)
{
	uint8_t buf[256];
	size_t i;
	uint8_t tag;
	int len = data[4];

	memset(buf, 0, sizeof(buf));
	memset(out, 0, maxlen);
	tag = data[1];

	memcpy(buf, data + 5, len);
	if(tag == 0x15){
		twofish(buf,len, out,maxlen,reader->jet_vendor_key,sizeof(vendor_key),1);
	}
	else if(tag == 0x16){
		for(i = 0; i < (len / 8); i++)
			des_ecb_encrypt(buf + 8 * i, reader->vendor_key + (i % 4) * 8, 8);
		memcpy(out, buf, len);
	}
	else
		memcpy(out, buf, len);
	return (len);
}
#endif

/*================================================================*/

static int32_t cw_is_valid(unsigned char *cw) //returns 1 if cw_is_valid, returns 0 if cw is all zeros
{
	int32_t i;

	for(i = 0; i < 16; i++)
	{
		if(cw[i] != 0)  //test if cw = 00
		{
			return OK;
		}
	}
	return ERROR;
}

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
	uint8_t get_serial_cmd[37] = {0x21, 0x21, 0x00, 0x00, 0x00};
	uint8_t get_key_cmd[6] = {0x58, 0x02, 0x00, 0x00, 0x00, 0x00};
	uint8_t register_key_cmd[48] = {0x15, 0x2C, 0x00, 0x00};
	uint8_t change_vendorkey_cmd[12] = {0x12, 0x08, 0x00, 0x00};
	uint8_t pairing_cmd01[38] = {0x20, 0x22, 0x00, 0x00};
	uint8_t pairing_cmd02[53] = {0x37, 0x31, 0x00, 0x00};
	uint8_t confirm_box_cmd[55] = {0x93, 0x33, 0x00, 0x00, 0x00, 0x00};
	uint8_t unknow_cmd1[39] = {0x71, 0x23, 0x00, 0x00, 0x04, 0x00};

	get_atr;
	def_resp;
	uint8_t cmd_buf[256];
	uint8_t temp[256];
	uint8_t buf[256];
	int i;
	struct twofish_ctx ctx;

	if((atr_size != 20) || atr[0] != 0x3B || atr[1] != 0x7F || memcmp(atr + 5, "DVN TECH", 8) != 0) { return ERROR; }
	if(atr[17] > 0x34 && atr[18] > 0x32)
		reader->cas_version=5;
	else
		reader->cas_version=1;

	rdr_log(reader, "Jet card detect");
	reader->caid = 0x4A30;
	reader->nprov = 1;


	memset(reader->prid, 0x00, sizeof(reader->prid));
	if(reader->cas_version < 5){
		for(i = 0; i < 32; i++)
			reader->jet_vendor_key[i] = i;
	}
	else
		memcpy(reader->jet_vendor_key, vendor_key, sizeof(vendor_key));

	// get serial step1
	jet_write_cmd(reader, get_serial_cmd, sizeof(get_serial_cmd), 0xAA, "get serial step1");
	memcpy(reader->hexserial, cta_res + 9, 8);

	if(reader->cas_version >= 5){
		//get root key
		jet_write_cmd(reader, get_key_cmd, sizeof(get_key_cmd), 0xAA, "get rootkey");
		memcpy(temp, cta_res + 5, cta_res[4]);
		memset(temp + cta_res[4], 0, sizeof(temp) - cta_res[4]);
		twofish_setkey(&ctx, reader->jet_vendor_key, sizeof(reader->jet_vendor_key));
		twofish_decrypt(&ctx, temp, cta_res[4], buf, sizeof(buf));
		memset(reader->jet_root_key, 0 ,sizeof(reader->jet_root_key));
		memcpy(reader->jet_root_key, buf + 4, (cta_res[4] < sizeof(reader->jet_root_key)) ? cta_res[4] : sizeof(reader->jet_root_key));

		//get derive key
		memset(temp, 0, sizeof(temp));
		if(!generate_derivekey(reader, temp, sizeof(temp))){
			rdr_log(reader, "error: generate derivekey faild, buffer overflow!");
			return ERROR;
		}
		//generate_derivekey has filled crc16. so call jet_write_cmd with len - 2.
		jet_write_cmd(reader, temp, sizeof(reader->jet_derive_key) - 2, 0xAA, "get derivekey");
		memcpy(reader->jet_derive_key, temp, sizeof(reader->jet_derive_key));

		//get auth key
		memset(cmd_buf, 0, sizeof(cmd_buf));
		memcpy(cmd_buf, get_key_cmd, sizeof(get_key_cmd));
		memcpy(cmd_buf + 4, reader->jet_root_key, 2);
		jet_write_cmd(reader, cmd_buf, sizeof(get_key_cmd), 0xAA, "get authkey");
		memset(temp, 0, sizeof(temp));
		memcpy(temp, cta_res, cta_res[4]);
		twofish_decrypt(&ctx, temp, cta_res[4], buf, sizeof(buf));
		memcpy(reader->jet_auth_key, buf + 4, 10);

		//register auth key
		memcpy(register_key_cmd + 36, reader->jet_auth_key, 8);
		register_key_cmd[42] = 0;
		memcpy(register_key_cmd + 44, reader->jet_derive_key + 44, 4);
		jet_write_cmd(reader, register_key_cmd, sizeof(register_key_cmd), 0x15, "confirm auth");

		//change vendor key
		jet_write_cmd(reader, change_vendorkey_cmd, sizeof(change_vendorkey_cmd), 0x15, "change vendorkey");
		memset(temp, 0, sizeof(temp));
		memcpy(temp, cta_res + 5, cta_res[4]);
		if(48 == twofish_decrypt(&ctx, temp, cta_res[4], buf, sizeof(buf)) &&
		    buf[0] == 0x42 && buf[1] == 0x20){
			memcpy(reader->jet_vendor_key, buf + 4, 32);
			twofish_setkey(&ctx, reader->jet_vendor_key, sizeof(reader->jet_vendor_key));
		}
		else{
			rdr_log(reader, "update vendor key faild!(return data incorrect)...");
			return ERROR;
		}
	}

	//pairing step1
	if(reader->boxkey_length)
		memcpy(pairing_cmd01 + 4, reader->boxkey, 32);
	pairing_cmd01[36] = 0x00;
	pairing_cmd01[37] = 0x01;
	jet_write_cmd(reader, pairing_cmd01, sizeof(pairing_cmd01), 0x15, "pairing step 1");
	memset(temp, 0, sizeof(temp));
	memcpy(temp, cta_res + 5, cta_res[4]);
	twofish_decrypt(&ctx, temp, cta_res[4], buf, sizeof(buf));
	if(buf[0] != 0x41){
		rdr_log(reader, "error: pairing step 1 failed(invalid data) ...");
		return ERROR;
	}

	//pairing step 2
	if(reader->boxkey_length)
		memcpy(pairing_cmd02 + 4, reader->boxkey, 32);
	pairing_cmd02[36] = 0x01;
	for(i = 37;i < 45; i++)
		pairing_cmd02[i] = 0x30;
	if(reader->cas_version >= 5)
		memcpy(pairing_cmd02 + 45, reader->jet_derive_key + 45, 8);
	jet_write_cmd(reader, pairing_cmd02, sizeof(pairing_cmd02), 0x15, "pairing step 2");

	if(reader->cas_version < 5){
		for( i = 1; i <= 7; i++){
			memcpy(cmd_buf, confirm_box_cmd, sizeof(confirm_box_cmd));
			cmd_buf[0] = 0x38;
			cmd_buf[4] = i;
			if(reader->boxkey_length)
				memcpy(confirm_box_cmd + 6, reader->boxkey, 32);
			confirm_box_cmd[38] = 0x01;
			for(i = 39;i < 47; i++)
				confirm_box_cmd[i] = 0x30;
			jet_write_cmd_hold(reader, confirm_box_cmd, sizeof(confirm_box_cmd), 0x15, "confirm box");
		}

	}
	else{
		//get service key
		memset(cmd_buf, 0, sizeof(cmd_buf));
		memcpy(cmd_buf, get_key_cmd, sizeof(get_key_cmd));
		if(reader->boxkey_length)
			memcpy(cmd_buf + 4, reader->boxkey, 2);
		jet_write_cmd(reader, cmd_buf, sizeof(get_key_cmd), 0xAA, "get service key");
		memset(temp, 0, sizeof(temp));
		memcpy(temp, cta_res + 5, cta_res[4]);
		twofish_decrypt(&ctx, temp, cta_res[4], buf, sizeof(buf));
		memcpy(reader->jet_service_key, buf + 4, 8);
		reader->jet_service_key[3] += reader->jet_service_key[1];

		//register service key
		memset(cmd_buf, 0, sizeof(cmd_buf));
		memcpy(cmd_buf, register_key_cmd, sizeof(register_key_cmd));
		if(reader->boxkey_length)
			memcpy(cmd_buf + 4, reader->boxkey, 32);
		memcpy(cmd_buf + 36, reader->jet_service_key, 8);
		memcpy(cmd_buf + 44, reader->jet_derive_key + 44, 4);
		cmd_buf[44] = 0x30;
		jet_write_cmd(reader, cmd_buf, sizeof(register_key_cmd), 0x15, "register service key");

		//confirm box 1
		confirm_box_cmd[4] = 0x0F;
		if(reader->boxkey_length)
			memcpy(confirm_box_cmd + 6, reader->boxkey, 32);
		confirm_box_cmd[38] = 0x01;
		for(i = 39;i < 47; i++)
			confirm_box_cmd[i] = 0x30;
		memcpy(confirm_box_cmd + 47, reader->jet_derive_key + 47, 8);
		jet_write_cmd(reader, confirm_box_cmd, sizeof(confirm_box_cmd), 0x15, "confirm box step 1");
	}

	//unknow cmd 1
	if(reader->boxkey_length)
		memcpy(unknow_cmd1 + 7, reader->boxkey, 32);
	jet_write_cmd_hold(reader, unknow_cmd1, sizeof(unknow_cmd1), 0x15, "unknow_cmd1");

	//update card serial
	get_serial_cmd[4] = 0x01;
	if(reader->boxkey_length)
		memcpy(get_serial_cmd + 5, reader->boxkey, 32);
	jet_write_cmd_hold(reader, get_serial_cmd, sizeof(get_serial_cmd), 0xAA, "update serial");
	memset(temp, 0, sizeof(temp));
	memcpy(temp, cta_res + 5, cta_res[4]);
	twofish_decrypt(&ctx, temp, cta_res[4], buf, sizeof(buf));
	memcpy(reader->hexserial, buf + 4, 8);

	if(reader->cas_version >= 5){
		//confirm box 2
		confirm_box_cmd[4] = 0x10;
		jet_write_cmd_hold(reader, confirm_box_cmd, sizeof(confirm_box_cmd), 0x15, "confirm box step 2");

		//confirm box 3
		confirm_box_cmd[4] = 0x0E;
		jet_write_cmd_hold(reader, confirm_box_cmd, sizeof(confirm_box_cmd), 0x15, "confirm box step 3");
	}

	rdr_log_sensitive(reader, "type: jet, caid: %04X, serial: %llu, hex serial: %08llX, boxkey: %s",
			reader->caid, (uint64_t) b2ll(8, reader->hexserial), (uint64_t) b2ll(8, reader->hexserial),
			cs_hexdump(0, reader->boxkey, 32, (char*)buf, sizeof(buf)));

	return OK;
}


static int32_t jet_do_ecm(struct s_reader *reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
	uint8_t cmd[256] = {0x00, 0xB2, 0x00, 0x00};
	uint8_t temp[256] = {0};
	uint8_t ecm[512] = {0};

	int i, offset, len;
	int ecm_len;
	char * tmp;

	def_resp;

	if(cs_malloc(&tmp, er->ecmlen * 3 + 1))
	{
		rdr_log_dbg(reader, D_IFD, "ECM: %s", cs_hexdump(1, er->ecm, er->ecmlen, tmp, er->ecmlen * 3 + 1));
		NULLFREE(tmp);
	}
	if((ecm_len = check_sct_len(er->ecm, 3, sizeof(er->ecm))) < 0) {
		rdr_log(reader, "error: check_sct_len failed, smartcard section too long %d > %d", SCT_LEN(er->ecm), sizeof(er->ecm) - 3);
		return ERROR;
	}

	memcpy(ecm, er->ecm, ecm_len);
	len = ((ecm[1] & 0x0F) << 8) + ecm[2];
	if(len < 0x8A){
		rdr_log(reader, "error: invalid ecm data...");
		return ERROR;
	}

	offset = 0;
	if(reader->cas_version < 5){
		ecm_len = len;
		len += 19;
	}
	else{
		if(ecm[2] == 0x8B)
			offset = 2;
		ecm_len = len - 13 + offset;
		if(ecm[2] == 0x9E){
			ecm[23] = ecm[23] ^ ecm[80] ^ ecm[90] ^ ecm[140];
			ecm[29] = ecm[29] ^ 0x59;
			ecm[41] = ecm[41] ^ 0xEA;
			ecm_len = 128;
		}
		len = ecm_len + 54;
	}

	if(ecm[8 - offset] == 4)
		cmd[0] = 0x1F;
	else if(ecm[8 - offset] == 3)
		cmd[0] = 0x1E;
	else if(reader->cas_version >= 5 && (ecm[8 - offset] & 0x7F) == 4 && ecm[2] == 0x9E)
		cmd[0] = 0x1F;
	else
		cmd[0] = 0x1B;

	if(reader->cas_version < 5)
		cmd[1] = 0xA2;

	memcpy(cmd + 4, ecm + 12 - offset, ecm_len);
	memcpy(cmd + 4 + ecm_len, reader->boxkey, 32);
	cmd[ecm_len + 36] = ecm[10 - offset] ^ ecm[138 - offset];
	cmd[ecm_len + 37] = ecm[11 - offset] ^ ecm[139 - offset];
	if(reader->cas_version >= 5)
		memcpy(cmd + ecm_len + 38, reader->jet_service_key, 8);
	jet_write_cmd(reader, cmd, len, 0x16, "parse ecm");
	if(cta_lr < 29){
			rdr_log(reader, "error: get cw failed...(response data too short.)");
			return ERROR;
	}

	memset(temp, 0, sizeof(temp));
	memcpy(temp, cta_res, cta_res[4] + 5);
	for(i = 0; i < (cta_res[4] / 8); i++)
		des_ecb_encrypt(temp + 5 + 8 * i, reader->jet_vendor_key + (i % 4) * 8, 8);
	if(temp[9] == 0xFF){
		rdr_log(reader, "error: invalid cw data... (cw[9]=0xFF)");
		return ERROR;
	}
	memcpy(ea->cw, temp + 11, 16);
	if(ERROR == cw_is_valid(ea->cw)){
		rdr_log(reader, "error: invalid cw data... (all zero)");
		return ERROR;
	}

	return OK;
}

static int32_t jet_get_emm_type(EMM_PACKET *ep, struct s_reader *UNUSED(reader))
{
	ep->type = UNKNOWN;
	return 1;
}

static int32_t jet_do_emm(struct s_reader *reader, EMM_PACKET *ep)
{
	uint8_t cmd[256] = { 0x1A, 0xB2, 0x00, 0x00};

	int len;
	def_resp;

	len = ((ep->emm[1] & 0x0F) << 8) + ep->emm[2];
	if(len < 148){
		rdr_log(reader, "error: emm data too short,(%d) < 148 ...", len);
		return ERROR;
	}

	if(ep->emm[10] != reader->hexserial[7]){
		rdr_log(reader, "error: do emm failed, card not match...");
		return ERROR;
	}

	len -= 4;
	memcpy(cmd + 4, ep->emm + 17, len);
	memcpy(cmd + 4 + len, reader->boxkey, 32);
	memcpy(cmd + len + 40,ep->emm + 13, 4);
	cmd[len + 44] = 0x14;
	cmd[len + 46] = 0x01;
	cmd[len + 47] = 0x01;
	cmd[len + 52] = ep->emm[17] ^ ep->emm[145];
	cmd[len + 53] = ep->emm[144] ^ ep->emm[146];
	jet_write_cmd(reader, cmd, len + 54, 0x15, "parse emm");

	return OK;
}

static int32_t jet_card_info(struct s_reader *UNUSED(reader))
{

	return OK;
}

const struct s_cardsystem reader_jet =
{
	.desc         = "jet",
	.caids        = (uint16_t[]){ 0x4A30, 0 },
	.do_emm       = jet_do_emm,
	.do_ecm       = jet_do_ecm,
	.card_info    = jet_card_info,
	.card_init    = jet_card_init,
	.get_emm_type = jet_get_emm_type,
};

#endif
