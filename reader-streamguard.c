#include "globals.h"
#ifdef READER_STREAMGUARD
#include "reader-common.h"
#include "cscrypt/des.h"

/************* custom md5 functions begin *************/
typedef struct md5Context {
	uint32_t buf[4];
	uint32_t bits[2];
	uint32_t in[16];
} md5_CTX;


/* The four core functions - F1 is optimized somewhat */

/*#define F1(x, y, z) (x & y | ~x & z)*/
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

inline static int64_t md5_FF(uint64_t w, uint64_t x, uint64_t y, uint64_t z, uint64_t i, uint64_t s, uint64_t data) {
	int64_t v = F1(x, y, z) + i + data + w;
	return (int64_t)((((uint32_t)v)) >> (((int)(32 - s))) | (((int32_t)v) << s)) + x;
}

inline static int64_t md5_GG(uint64_t w, uint64_t x, uint64_t y, uint64_t z, uint64_t i, uint64_t s, uint64_t data) {
	int64_t v = F2(x, y, z) + i + data + w;
	return (int64_t)((((uint32_t)v)) >> (((int)(32 - s))) | (((int32_t)v) << s)) + x;
}

inline static int64_t md5_HH(uint64_t w, uint64_t x, uint64_t y, uint64_t z, uint64_t i, uint64_t s, uint64_t data) {
	int64_t v = F3(x, y, z) + i + data + w;
	return (int64_t)((((uint32_t)v)) >> (((int)(32 - s))) | (((int32_t)v) << s)) + x;
}

inline static int64_t md5_II(uint64_t w, uint64_t x, uint64_t y, uint64_t z, uint64_t i, uint64_t s, uint64_t data) {
	int64_t v = F4(x, y, z) + i + data + w;
	return (int64_t)((((uint32_t)v)) >> (((int)(32 - s))) | (((int32_t)v) << s)) + x;
}

#if __BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__
#define byteReverse(a, b)
#else
static void byteReverse(unsigned char *buf, unsigned int longs)
{
	uint32_t t;
	do
	{
		t = (uint32_t)((unsigned int)buf[3] << 8 | buf[2]) << 16 |
			((unsigned int)buf[1] << 8 | buf[0]);
		memcpy(buf, &t, 4);
		buf += 4;
	}
	while(--longs);
}
#endif

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 64 byte of new data.  MD5_Update blocks
 * the data and converts bytes into longwords for this routine.
 */
static void md5_transform(uint32_t *buf,  uint32_t *in)
{
	int64_t a = buf[0];
	int64_t b = buf[1];
	int64_t c = buf[2];
	int64_t d = buf[3];
	int64_t m = 0L;

        a = md5_FF(a, b, c, d, in[0], 7, 0xD76AA478L);
        d = md5_FF(d, a, b, c, in[1], 12, 0xE8C7B756L);
        c = md5_FF(c, d, a, b, in[2], 17, 0x242070DB);
        m = md5_FF(b, c, d, a, in[3], 22, 0xC1BDCEEEL);

        a = md5_FF(a, m, c, d, in[4], 7, 0xF57C0FAFL);
        d = md5_FF(d, a, m, c, in[5], 12, 0x4787C62A);
        b = md5_FF(c, d, a, m, in[6], 17, 0xA8304613L);
        c = md5_FF(m, b, d, a, in[7], 22, 0xFD469501L);

        a = md5_FF(a, c, b, d, in[8], 7, 0x698098D8);
        d = md5_FF(d, a, c, b, in[9], 12, 0x8B44F7AFL);
        b = md5_FF(b, d, a, c, in[10], 17, 0xFFFF5BB1L);
        c = md5_FF(c, b, d, a, in[11], 22, 0x895CD7BEL);

        a = md5_FF(a, c, b, d, in[12], 7, 0x6B901122);
        d = md5_FF(d, a, c, b, in[13], 12, 0xFD987193L);
        b = md5_FF(b, d, a, c, in[14], 17, 0xA679438EL);
        m = md5_FF(c, b, d, a, in[15], 22, 0x49B40821);

        a = md5_GG(a, m, b, d, in[1], 5, 0xF61E2562L);
        c = md5_GG(d, a, m, b, in[6], 9, 0xC040B340L);
        b = md5_GG(b, c, a, m, in[11], 14, 0x265E5A51);
        m = md5_GG(m, b, c, a, in[0], 20, 0xE9B6C7AAL);

        d = md5_GG(a, m, b, c, in[5], 5, 0xD62F105DL);
        c = md5_GG(c, d, m, b, in[10], 9, 0x2441453);
        b = md5_GG(b, c, d, m, in[15], 14, 0xD8A1E681L);
        a = md5_GG(m, b, c, d, in[4], 20, 0xE7D3FBC8L);

        d = md5_GG(d, a, b, c, in[9], 5, 0x21E1CDE6);
        c = md5_GG(c, d, a, b, in[14], 9, 0xC33707D6L);
        b = md5_GG(b, c, d, a, in[3], 14, 0xF4D50D87L);
        a = md5_GG(a, b, c, d, in[8], 20, 0x455A14ED);

        d = md5_GG(d, a, b, c, in[13], 5, 0xA9E3E905L);
        c = md5_GG(c, d, a, b, in[2], 9, 0xFCEFA3F8L);
        b = md5_GG(b, c, d, a, in[7], 14, 0x676F02D9);
        a = md5_GG(a, b, c, d, in[12], 20, 0x8D2A4C8AL);

        d = md5_HH(d, a, b, c, in[5], 4, 0xFFFA3942L);
        c = md5_HH(c, d, a, b, in[8], 11, 0x8771F681L);
        b = md5_HH(b, c, d, a, in[11], 16, 0x6D9D6122);
        a = md5_HH(a, b, c, d, in[14], 23, 0xFDE5380CL);

        d = md5_HH(d, a, b, c, in[1], 4, 0xA4BEEA44L);
        c = md5_HH(c, d, a, b, in[4], 11, 0x4BDECFA9);
        b = md5_HH(b, c, d, a, in[7], 16, 0xF6BB4B60L);
        a = md5_HH(a, b, c, d, in[10], 23, 0xBEBFBC70L);

        d = md5_HH(d, a, b, c, in[13], 4, 0x289B7EC6);
        c = md5_HH(c, d, a, b, in[0], 11, 0xEAA127FAL);
        b = md5_HH(b, c, d, a, in[3], 16, 0xD4EF3085L);
        a = md5_HH(a, b, c, d, in[6], 23, 0x4881D05);

        d = md5_HH(d, a, b, c, in[9], 4, 0xD9D4D039L);
        c = md5_HH(c, d, a, b, in[12], 11, 0xE6DB99E5L);
        b = md5_HH(b, c, d, a, in[15], 16, 0x1FA27CF8);
        a = md5_HH(a, b, c, d, in[2], 23, 0xC4AC5665L);

        d = md5_II(d, a, b, c, in[0], 6, 0xF4292244L);
        c = md5_II(c, d, a, b, in[7], 10, 0x432AFF97);
        b = md5_II(b, c, d, a, in[14], 15, 0xAB9423A7L);
        a = md5_II(a, b, c, d, in[5], 21, 0xFC93A039L);

        d = md5_II(d, a, b, c, in[12], 6, 0x655B59C3);
        c = md5_II(c, d, a, b, in[3], 10, 0x8F0CCC92L);
        b = md5_II(b, c, d, a, in[10], 15, 0xFFEFF47DL);
        a = md5_II(a, b, c, d, in[1], 21, 0x85845DD1L);

        d = md5_II(d, a, b, c, in[8], 6, 0x6FA87E4F);
        c = md5_II(c, d, a, b, in[15], 10, 0xFE2CE6E0L);
        b = md5_II(b, c, d, a, in[6], 15, 0xA3014314L);
        a = md5_II(a, b, c, d, in[13], 21, 0x4E0811A1);

        d = md5_II(d, a, b, c, in[4], 6, 0xF7537E82L);
        c = md5_II(c, d, a, b, in[11], 10, 0xBD3AF235L);
        b = md5_II(b, c, d, a, in[2], 15, 0x2AD7D2BB);
        a = md5_II(a, b, c, d, in[9], 21, 0xEB86D391L);

	buf[0] += d;
	buf[1] += a;
	buf[2] += b;
	buf[3] += c;
}

void md5_init(md5_CTX *ctx)
{
	ctx->buf[0] = 0x67452301;
	ctx->buf[1] = 0xefcdab89;
	ctx->buf[2] = 0x98badcfe;
	ctx->buf[3] = 0x10325476;

	ctx->bits[0] = 0;
	ctx->bits[1] = 0;

	memset(ctx->in, 0, 64);
}

static void md5_update(md5_CTX *ctx, const uint8_t *buf, uint32_t len)
{
	uint32_t temp[16];
	memset(temp, 0 ,sizeof(temp));

	int32_t t = (ctx->bits[0] >> 3) & 0x3F;
	ctx->bits[0] += (len << 3);
	if (ctx->bits[0] < (len << 3))
		ctx->bits[1] += 1L;
	ctx->bits[1] += (len >> 29);
	if ((int32_t)len >= 64 - t)
	{
		memcpy((uint8_t*)ctx->in + t, buf, 64 - t);
		byteReverse((uint8_t*)ctx->in, 16);
		md5_transform(ctx->buf,ctx->in);
		t = 64 - t;
		while (t + 64 <= (int32_t)len)
		{
			memcpy((uint8_t*)temp, buf + t, 64);
			byteReverse((uint8_t*)temp, 16);
			md5_transform(ctx->buf, temp);
			t += 64;
		}
		memcpy((uint8_t*)ctx->in, buf + t, len - t);
		byteReverse((uint8_t*)ctx->in, 16);
		return;
	}
	memcpy((uint8_t*)ctx->in + t, buf, len);
	byteReverse((uint8_t*)ctx->in, t + len);
}

static void md5_final(unsigned char *digest, md5_CTX *ctx)
{
	unsigned char temp[8]={0};
	unsigned char padding[64];
	memset(padding, 0, 64);
	padding[0] = 0x80;
	memcpy(temp, (unsigned char*)ctx->bits, 8);
	byteReverse(temp, 2);

	uint32_t count = (ctx->bits[0] >> 3) & 0x3f;
	if(count < 56)
		count = 56 - count;
	else
		count = 120 - count;
	md5_update(ctx, padding, count);
	md5_update(ctx, temp, 8);
	memcpy(digest,(unsigned char*)ctx->buf, 16);
	byteReverse((unsigned char*)ctx->buf, 16);
}

unsigned char *md5(const unsigned char *input, unsigned long len, unsigned char *output)
{
	md5_CTX ctx;
	md5_init(&ctx);
	md5_update(&ctx, input, len);
	md5_final(output, &ctx);
	memset(&ctx, 0, sizeof(ctx));
	return output;
}

/*********** custom md5 function end ****************/

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

static void  decrypt_cw_ex(int32_t tag, int32_t a, int32_t b, int32_t c, uchar *data)
{
        uchar key1[16] = {0xB5, 0xD5, 0xE8, 0x8A, 0x09, 0x98, 0x5E, 0xD0, 0xDA, 0xEE, 0x3E, 0xC3, 0x30, 0xB9, 0xCA, 0x35};
        uchar key2[16] = {0x5F, 0xE2, 0x76, 0xF8, 0x04, 0xCB, 0x5A, 0x24, 0x79, 0xF9, 0xC9, 0x7F, 0x23, 0x21, 0x45, 0x84};
        uchar key3[16] = {0xE3, 0x78, 0xB9, 0x8C, 0x74, 0x55, 0xBC, 0xEE, 0x03, 0x85, 0xFD, 0xA0, 0x2A, 0x86, 0xEF, 0xAF};
	uchar keybuf[22] = {0xCC,0x65,0xE0, 0xCB,0x60,0x62,0x06,0x33,0x87,0xE3,0xB5,0x2D,0x4B,0x12,0x90,0xD9,0x00,0x00,0x00,0x00,0x00,0x00};
	uchar md5key[16];
	uchar md5tmp[20];
	uchar deskey1[8], deskey2[8];

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
	md5(keybuf,22,md5tmp);

	md5tmp[16] = (b >> 8)& 0xFF;
	md5tmp[17] = b & 0xFF;
	md5tmp[18] = (a >> 8) & 0xFF;
	md5tmp[19] = a & 0xff;
	md5(md5tmp,20,md5key);

	//3des decrypt
	memcpy(deskey1, md5key, 8);
	memcpy(deskey2, md5key + 8, 8);
	des_ecb_decrypt(data, deskey1, 16);  //decrypt
	des_ecb_encrypt(data, deskey2, 16);  //crypt
	des_ecb_decrypt(data, deskey1, 16);  //decrypt
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
	uchar begin_cmd2[5] = {0x00,0x84,0x00,0x00,0x08};
	uchar begin_cmd3[11] = {0x00,0x20,0x04,0x02,0x06,0x12,0x34,0x56,0x78,0x00,0x00};
	uchar begin_cmd4[5] = {0x00,0xFC,0x00,0x00,0x00};
	uchar pairing_cmd[25] = {0x80,0x5A,0x00,0x00,0x10,0x36,0x9A,0xEE,0x31,0xB2,0xDA,0x94,
				 0x3D,0xEF,0xBA,0x10,0x22,0x67,0xA5,0x1F,0xFB,0x3B,0x9E,0x1F,0xCB};
	uchar confirm_pairing_cmd[9] = {0x80,0x5A,0x00,0x01,0x04,0x3B,0x9E,0x1F,0xCB};

	uchar seed[] = {0x00,0x00,0x00,0x00,0x24,0x30,0x28,0x73,0x40,0x33,0x46,0x2C,0x6D,0x2E,0x7E,0x3B,0x3D,0x6E,0x3C,0x37};
	uchar randkey[16]={0};
	uchar key1[8], key2[8];
	uchar data[257];
	uchar boxID[4] = {0xff, 0xff, 0xff, 0xff};
	uchar md5_key[16] = {0};

	int32_t data_len = 0;
	uint16_t status = 0;

	def_resp;
	get_atr;

	rdr_log(reader, "[reader-streamguard] StreamGuard atr_size:%d, atr[0]:%02x, atr[1]:%02x", atr_size, atr[0], atr[1]);

	if ((atr_size != 4) || (atr[0] != 0x3b) || (atr[1] != 0x02)) return ERROR;

	reader->caid = 0x4AD2;
	if(reader->cas_version == 0)
		reader->cas_version=3;	//new version

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

	if(reader->cas_version > 1){
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

	if(reader->cas_version > 1){
		memcpy(seed,data + 3, 4);
		md5(seed,sizeof(seed),md5_key);

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
		if(reader->cas_version > 2){
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
	uchar ecm_cmd[256] = {0x80,0x32,0x00,0x00,0x3C};
	uchar data[256];
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
		if (reader->cas_version == 3 && data[i] == 0xB4 && data[i + 1] == 0x04)
			tag = b2i(2, data + i + 4);
;
		if (data[i] == 0x83 && data[i + 1] == 0x16)
		{
			if(reader->cas_version <= 2 || data[i + 2] != 0 || data[i + 3] != 1)
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

	if(reader->cas_version == 1)
		return OK;

	if(((uint16_t)(ea->cw[0]) + (uint16_t)(ea->cw[1]) + (uint16_t)(ea->cw[2])) == (uint16_t)(ea->cw[3])
	   && ((uint16_t)(ea->cw[4]) + (uint16_t)(ea->cw[5]) + (uint16_t)(ea->cw[6])) == (uint16_t)(ea->cw[7])
	   && ((uint16_t)(ea->cw[8]) + (uint16_t)(ea->cw[9]) + (uint16_t)(ea->cw[10])) == (uint16_t)(ea->cw[11])
	   && ((uint16_t)(ea->cw[12]) + (uint16_t)(ea->cw[13]) + (uint16_t)(ea->cw[14])) == (uint16_t)(ea->cw[15]))
		return OK;

	if((data[i + 5] & 0x10) != 0){
		//3des decrypt
		uchar key1[8], key2[8];
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
	uchar data[256];

	if(SCT_LEN(ep->emm) < 8) {
		rdr_log(reader, "error: emm data too short !");
		return ERROR;
	}

	if(reader->cas_version > 2 && ep->emm[0] == 0x83){
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

	return OK;
}

static int32_t streamguard_card_info(struct s_reader *reader)
{
	uchar get_provid_cmd[12] = {0x00,0xb2,0x00,0x06,0x07,0x00,0x05,0xff,0x00,0x02,0xff,0xff};
	uchar get_subscription_cmd[12] = {0x00,0xb2,0x00,0x0d,0x07,0x00,0x01,0x28,0x00,0x02,0x05,0xd2};
	uchar data[256];
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
		get_subscription_cmd[5] = bankid;
		get_subscription_cmd[10] = reader->prid[i][2];
		get_subscription_cmd[11] = reader->prid[i][3];
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

		uint16_t count = data[1];
		int j;
		for(j = 0; j < count; j++){
			if(data[j * 19 + 3] == 0 && data[j * 19 + 4] == 0) continue;

			time_t start_t,end_t;
			start_t = b2i(4, data + j * 19 + 12) * 24 * 3600L;
			end_t = b2i(4, data + j * 19 + 16) * 24 * 3600L;
			uint64_t product_id=b2i(2, data + j * 19 + 5);

			cs_add_entitlement(reader, reader->caid, b2i(2, &reader->prid[i][2]), product_id, 0, start_t, end_t, 0, 1);
		}
		bankid = data[0];
	}

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
