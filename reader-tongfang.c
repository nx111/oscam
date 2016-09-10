#include "globals.h"
#ifdef READER_TONGFANG
#include "reader-common.h"

void tongfang3_transfer(uchar* lpSrc, uchar* lpDest, uchar* lpTable);
void tongfang3_keygenerate(uchar* lpKeyIn, uchar* lpKeySub, int nCount);
void tongfang3_dtob(uchar Data, uchar* lpResult);
void tongfang3_circle(uchar* lpBuf, int nLength);	// to complete left circel shift 1 bit per time
void tongfang3_des_algo(uchar* lpSrc, uchar* lpDest, uchar* lpKey, bool bEncrypt);
void tongfang3_s_change(uchar* lpBuf);
void tongfang3_str_xor(uchar* lpSrc, uchar* lpDest, int nLen);
uint32_t tongfang3_get_true_calibsn(uint32_t value);


static const uint32_t  tongfang3_calibsn=2991124752UL;	//B248F110<=;

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

void tongfang3_transfer(uchar* lpSrc, uchar* lpDest, uchar* lpTable)
{
	int nTableLength, i;

	nTableLength = 0;
	while( lpTable[ nTableLength ] != 255 )
		nTableLength++;

	for( i = 0; i < nTableLength; i++ )
	{
		lpDest[ i ] = lpSrc[ lpTable[ i ] ];
	}
}

void tongfang3_keygenerate(uchar* lpKeyIn, uchar* lpKeySub, int nCount)
{
	uchar Buffer[ 56 ];
	uchar C0[ 28 ];
	uchar D0[ 28 ];
	int i;

	uchar shift[] = {
		1,  2,  4,  6,  8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
	};

	uchar PC_1[] = {
		56, 48, 40, 32, 24, 16,  8,  0, 57, 49, 41, 33, 25, 17,
		 9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35,
		62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37, 29, 21,
		13,  5, 60, 52, 44, 36, 28, 20, 12,  4, 27, 19, 11,  3,
	       255
	};

	uchar PC_2[] = {
		13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9, 22, 18, 11,  3,
		25,  7, 15,  6, 26, 19, 12,  1, 40, 51, 30, 36, 46, 54, 29, 39,
		50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31,
		255
	};

	tongfang3_transfer( lpKeyIn, Buffer, PC_1 );

	for( i = 0; i < 28; i++ )
	{
		C0[ i ] = Buffer[ i ];
		D0[ i ] = Buffer[ i + 28 ];
	}

	for( i = 0; i < shift[ nCount ]; i++ )
	{
		tongfang3_circle( C0, 28 );
		tongfang3_circle( D0, 28 );
	}

	for ( i = 0; i < 28; i++ )
	{
		Buffer[ i ] = C0[ i ];
		Buffer[ i + 28 ] = D0[ i ];
	}

	tongfang3_transfer( Buffer, lpKeySub, PC_2 );
}

void tongfang3_keygenerate_ex(uchar* KeyBlock, uchar* lpKeySub, int nCount)
{
	int i = 0;

	for (i=0; i<48; i++)
	{
		lpKeySub[i] = (KeyBlock[i*2+nCount/8]>>(nCount%8))&1;
	}
}


void tongfang3_dtob(uchar Data, uchar* lpResult)
{
	int i;

	for( i = 0; i < 8; i++ )
	{
		lpResult[ i ] = 0;
		if( Data & 0x80 )
		  lpResult[ i ] = 1;
		Data = Data << 1;
	}
}

void tongfang3_circle(uchar* lpBuf, int nLength)	// to complete left circel shift 1 bit per time
{
	uchar tmp;
	int i;

	tmp = lpBuf[ 0 ];
	for( i = 0; i < nLength - 1; i++ )
		lpBuf[ i ] = lpBuf[ i + 1 ];
	lpBuf[ nLength - 1 ] = tmp;
}

void tongfang3_des_algo(uchar* lpSrc, uchar* lpDest, uchar* lpKey, bool bEncrypt)
{
	uchar SubKey[ 48 ];
	uchar Tmp[ 32 ];
	uchar Buffer[ 48 ];
	uchar Left[ 32 ];
	uchar Right[ 32 ];
	int i;
	uchar IP[] = {
		57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
		61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7,
		56, 48, 40, 32, 24, 16,  8,  0, 58, 50, 42, 34, 26, 18, 10,  2,
		60, 52, 44, 36, 28, 20, 12,  4, 62, 54, 46, 38, 30, 22, 14,  6,
		255
	};

	uchar IP_1[] = {
		39,  7, 47, 15, 55, 23, 63, 31, 38,  6, 46, 14, 54, 22, 62, 30,
		37,  5, 45, 13, 53, 21, 61, 29, 36,  4, 44, 12, 52, 20, 60, 28,
		35,  3, 43, 11, 51, 19, 59, 27, 34,  2, 42, 10, 50, 18, 58, 26,
		33,  1, 41,  9, 49, 17, 57, 25, 32,  0, 40,  8, 48, 16, 56, 24,
		255
	};

	uchar E[] = {
		31,  0,  1,  2,  3,  4,  3,  4,  5,  6,  7,  8,  7,  8,  9, 10,
		11, 12,	11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20,
		21, 22, 23, 24,	23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31,  0,
		255
	};

	uchar P[] = {
		15,  6, 19, 20, 28, 11, 27, 16,  0, 14, 22, 25,  4, 17, 30,  9,
		 1,  7, 23, 13, 31, 26,  2,  8, 18, 12, 29,  5, 21, 10,  3, 24,
		255
	};

	tongfang3_transfer( lpSrc, lpDest, IP );

	for( i = 0; i < 32; i++ )
	{
		Left[ i ] = lpDest[ i ];
		Right[ i ] = lpDest[ i + 32 ];
	}

	for( i = 0; i < 16; i++ )
	{
		if( bEncrypt )
		  tongfang3_keygenerate( lpKey, SubKey, i );
		else
		  tongfang3_keygenerate( lpKey, SubKey, 15 - i );
		memcpy( Tmp,Right,32 );

		tongfang3_transfer( Right, Buffer, E );
		tongfang3_str_xor( SubKey, Buffer, 48 );
		tongfang3_s_change( Buffer );
		tongfang3_transfer( Buffer, Right, P );

		tongfang3_str_xor( Left, Right, 32 );
		memcpy( Left, Tmp, 32 );
	}

	for( i = 0; i < 32; i++ )
	{
		lpSrc[ i ] = Right[ i ];
		lpSrc[ 32 + i ] = Left[ i ];
	}

	tongfang3_transfer( lpSrc, lpDest, IP_1 );
}



void tongfang3_des_algo_ex(uchar* lpSrc, uchar* lpDest, uchar* KeyBlock, int bEncrypt)
{
	uchar SubKey[ 48 ];
	uchar Tmp[ 32 ];
	uchar Buffer[ 48 ];
	uchar Left[ 32 ];
	uchar Right[ 32 ];
	int i;
	uchar IP[] = {
		57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
		61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7,
		56, 48, 40, 32, 24, 16,  8,  0, 58, 50, 42, 34, 26, 18, 10,  2,
		60, 52, 44, 36, 28, 20, 12,  4, 62, 54, 46, 38, 30, 22, 14,  6,
		255
	};

	uchar IP_1[] = {
		39,  7, 47, 15, 55, 23, 63, 31, 38,  6, 46, 14, 54, 22, 62, 30,
		37,  5, 45, 13, 53, 21, 61, 29, 36,  4, 44, 12, 52, 20, 60, 28,
		35,  3, 43, 11, 51, 19, 59, 27, 34,  2, 42, 10, 50, 18, 58, 26,
		33,  1, 41,  9, 49, 17, 57, 25, 32,  0, 40,  8, 48, 16, 56, 24,
		255
	};

	uchar E[] = {
		31,  0,  1,  2,  3,  4,  3,  4,  5,  6,  7,  8,  7,  8,  9, 10,
		11, 12,	11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20,
		21, 22, 23, 24,	23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31,  0,
		255
	};

	uchar P[] = {
		15,  6, 19, 20, 28, 11, 27, 16,  0, 14, 22, 25,  4, 17, 30,  9,
		 1,  7, 23, 13, 31, 26,  2,  8, 18, 12, 29,  5, 21, 10,  3, 24,
		255
	};

	tongfang3_transfer( lpSrc, lpDest, IP );

	for( i = 0; i < 32; i++ )
	{
		Left[ i ] = lpDest[ i ];
		Right[ i ] = lpDest[ i + 32 ];
	}

	for( i = 0; i < 16; i++ )
	{
		if( bEncrypt )
			tongfang3_keygenerate_ex( KeyBlock, SubKey, i );
		else
			tongfang3_keygenerate_ex( KeyBlock, SubKey, 15 - i );

		memcpy( Tmp, Right, 32 );
		tongfang3_transfer( Right, Buffer, E );//lpSrc
		tongfang3_str_xor( SubKey, Buffer, 48 );//lpSrc
		tongfang3_s_change( Buffer );//lpSrc
		tongfang3_transfer( Buffer, Right, P );//lpSrc
		tongfang3_str_xor( Left, Right, 32 );
		memcpy( Left, Tmp, 32 );

	}

	for( i = 0; i < 32; i++ )
	{
		lpSrc[ i ] = Right[ i ];
		lpSrc[ 32 + i ] = Left[ i ];
	}

	tongfang3_transfer( lpSrc, lpDest, IP_1 );
}


void tongfang3_s_change(uchar* lpBuf)
{
	uchar Src[ 8 ][ 6 ];
	uchar Dest[ 8 ][ 4 ];
	int	 i, j;
	int nAdr;

	uchar S[ 8 ][ 64 ] = {
		{14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
		  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
		  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
		 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
		},

		{15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
		  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
		  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
		 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
		},

		{10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
		 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
		 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
		  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
		},

		{ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
		 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
		 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
		  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
		},

		{ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
		 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
		 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
		 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
		},

		{12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
		 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
		  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
		  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
		},

		{ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
		 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
		  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
		  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
		},

		{13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
		  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
		  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
		  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
		}
	};

	for( i = 0; i < 8; i++ )
		for( j = 0; j < 6; j++ )
		  Src[ i ][ j ] = lpBuf[ i * 6 + j ];

	for( i = 0; i < 8; i++ )
	{
		j = Src[ i ][ 1 ] * 8 + Src[ i ][ 2 ] * 4 + Src[ i ][ 3 ] * 2 + Src[ i ][ 4 ];
		nAdr = ( Src[ i ][ 0 ] * 2 + Src[ i ][ 5 ] ) * 16 + j;
		j = S[ i ][ nAdr ];
		Dest[ i ][ 0 ] = j / 8;
		j %= 8;
		Dest[ i ][ 1 ] = j / 4;
		j %= 4;
		Dest[ i ][ 2 ] = j / 2;
		Dest[ i ][ 3 ] = j % 2;
	}

	for( i = 0; i < 8; i++ )
		for( j = 0; j < 4; j++ )
		  lpBuf[ i * 4 + j ] = Dest[ i ][ j ];
}

void tongfang3_str_xor(uchar* lpSrc, uchar* lpDest, int nLen)
{
	int i;
	for( i = 0; i < nLen; i++ )
		lpDest[ i ] = ( lpSrc[ i ] + lpDest[ i ] ) % 2;
}

void tongfang3_des0(bool bEncrypt, uchar* lpSrc, uchar* lpKey, uchar* lpResult)
{
	uchar Src[ 64 ];
	uchar Dest[ 64 ];
	uchar KeyMain[ 64 ];
	int  i, j;

	for( i = 0; i < 8; i++ )
	{
		tongfang3_dtob( lpSrc[ i ], Src + i * 8 );
		tongfang3_dtob( lpKey[ i ], KeyMain + i * 8 );
	}

	tongfang3_des_algo( Src, Dest, KeyMain, bEncrypt );

	for( i = 0; i < 8; i++ )
	{
		lpResult[ i ] = 0;
		for( j = 0; j < 8; j++ )
		  lpResult[ i ] |= ( 1 << ( 7 - j ) ) * Dest[ 8 * i + j ];
	}

}

void tongfang3_des0_ex(int bEncrypt, uchar* lpSrc, uchar* KeyBlock, uchar* lpResult)
{
	uchar Src[ 64 ];
	uchar Dest[ 64 ];
	int  i, j;

	for( i = 0; i < 8; i++ )
	{
		tongfang3_dtob( lpSrc[ i ], Src + i * 8 );

	}

	tongfang3_des_algo_ex( Src, Dest, KeyBlock, bEncrypt );

	for( i = 0; i < 8; i++ )
	{
		lpResult[ i ] = 0;
		for( j = 0; j < 8; j++ )
			lpResult[ i ] |= ( 1 << ( 7 - j ) ) * Dest[ 8 * i + j ];
	}
}

void tongfang3_trides0(bool bEncrypt, uchar* lpSrc, uchar* lpKey, uchar* lpResult)
{
	uchar Src0[ 8 ];
	uchar Key0[ 8 ];
	int i;

	for( i = 0; i < 8; i++ )
	{
		Src0[ i ] = lpSrc[ i ];
		Key0[ i ] = lpKey[ i ];
	}

	tongfang3_des0( bEncrypt, Src0, Key0, lpResult );

	bEncrypt = !bEncrypt;
	for( i = 0; i < 8; i++ )
	{
		Src0[ i ] = lpResult[ i ];
		Key0[ i ] = lpKey[ i + 8 ];
	}
	tongfang3_des0( bEncrypt, Src0, Key0, lpResult );

	bEncrypt = !bEncrypt;
	for( i = 0; i < 8; i++ )
	{
		Src0[ i ] = lpResult[ i ];
		Key0[ i ] = lpKey[ i ];
	}
	tongfang3_des0( bEncrypt, Src0, Key0, lpResult );
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
	const uchar begin_cmdv2[] = {0x00, 0xa4, 0x04, 0x00, 0x05, 0xf9, 0x5a, 0x54, 0x00, 0x06};
	const uchar begin_cmdv3[] = {0x80, 0x46, 0x00, 0x00, 0x04, 0x07, 0x00, 0x00, 0x08};
	uchar get_serial_cmdv2[] = {0x80, 0x46, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x04};
	uchar get_serial_cmdv3[] = {0x80, 0x46, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x14};
	uchar get_commkey_cmd[17] = {0x80, 0x56, 0x00, 0x00, 0x0c};
	uchar confirm_commkey_cmd[21] = {0x80, 0x4c, 0x00, 0x00, 0x10};
	uchar pairing_cmd[200] = {0x80, 0x4c, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF};

	uchar data[257];
	uchar card_id[20];
	uint16_t status = 0;
	uchar boxID[] = {0xFF, 0xFF, 0xFF, 0xFF};
	uchar stbid[16] = {0x01,0x00,0x12,0x34,0x00,0x00,0x00,0x00};
	uchar zero[16] =  {0};
	uchar	tongfang3_seed[8];
	int32_t i;
	uint32_t calibsn=0;
	int8_t readsize=0;

	def_resp;
	get_hist;

	if((hist_size < 4) || (memcmp(hist, "NTIC", 4))) { return ERROR; }
	//rdr_log(reader, "Tongfang module (%s)",__TIMESTAMP__);

	reader->caid = 0x4A02;
	// For now, only one provider, 0000
	reader->nprov = 1;
	memset(reader->prid, 0x00, sizeof(reader->prid));

	if(hist_size < 5 || hist[4] == '0' || hist[4] == '1'){	//tongfang 1-2
		reader->tongfang_version=2;
		write_cmd(begin_cmdv2, begin_cmdv2 + 5);
		if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00)) { return ERROR; }
		rdr_log(reader, "Tongfang 1/2 card detected");

		//get card serial
		write_cmd(get_serial_cmdv2, get_serial_cmdv2 + 5);
		if((cta_res[cta_lr - 2] & 0xf0) != 0x60) {
			write_cmd(get_serial_cmdv3, get_serial_cmdv3 + 5);
			if((cta_res[cta_lr - 2] & 0xf0) != 0x60) {
				rdr_log(reader, "error: get card serial failed.");
				return ERROR;
			}
		}
		readsize=cta_res[cta_lr -1];
		if(readsize != tongfang_read_data(reader, readsize,data,&status) || status != 0x9000){
			rdr_log(reader, "error: card get serial failed.");
			return ERROR;
		}
		//rdr_log(reader, "card serial got.");

		memset(reader->hexserial, 0, 8);
		memcpy(reader->hexserial + 2, data, 4); // might be incorrect offset

		memset(card_id, 0, sizeof(card_id));
		memcpy(card_id,data + 4, (readsize-4) > ((int32_t)sizeof(card_id) - 1) ? (int32_t)sizeof(card_id) - 1 : readsize - 5);
		card_id[sizeof(card_id) - 1] = '\0';
	}
	else if(hist_size >= 5 && hist[4] == '2' ){	//tongfang 3
		reader->tongfang_version=3;
		write_cmd(begin_cmdv3, begin_cmdv3 + 5);
		if((cta_res[cta_lr - 2] & 0xf0) != 0x60) { return ERROR; }
		rdr_log(reader, "Tongfang3 card detected");

		// get commkey
		tongfang3_des0_ex(1, zero, tongfang3_keyblock, data);
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
		memcpy(tongfang3_seed,data,8);
		tongfang3_des0_ex(1, tongfang3_seed, tongfang3_keyblock, reader->tongfang3_commkey);
		rdr_log(reader, "card commkey got(%02X%02X%02X%02X%02X%02X%02X%02X)",reader->tongfang3_commkey[0],
			reader->tongfang3_commkey[1],reader->tongfang3_commkey[2],reader->tongfang3_commkey[3],
			reader->tongfang3_commkey[4],reader->tongfang3_commkey[5],reader->tongfang3_commkey[6],
			reader->tongfang3_commkey[7]);

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

		memset(card_id, 0, sizeof(card_id));
		memcpy(card_id,data + 4, (readsize-4) > ((int32_t)sizeof(card_id) - 1) ? (int32_t)sizeof(card_id) - 1 : readsize - 5);
		card_id[sizeof(card_id) - 1] = '\0';

		//confirm commkey
		memcpy(zero + 2, reader->hexserial + 2, 4);
		tongfang3_des0(1, stbid, reader->tongfang3_commkey, data);
		tongfang3_des0(1, zero, reader->tongfang3_commkey, data+8);
		memcpy(confirm_commkey_cmd + 5, data, 16);
		write_cmd(confirm_commkey_cmd, confirm_commkey_cmd + 5);

		readsize=cta_res[cta_lr -1];
		if(readsize != tongfang_read_data(reader, readsize, data, &status) || status != 0x9000){
			rdr_log(reader, "error: confirm commkey failed.");
			return ERROR;
		}
	}
	else {
		rdr_log(reader, "error: NTIC%c card not support yet!",hist[4]);
		return ERROR;
	}

	//pairing box and card
	/* the boxid is specified in the config */
	if (reader->boxid > 0){
		for(i = 0; (size_t)i < sizeof(boxID); i++){
			boxID[i] = (reader->boxid >> (8 * (3 - i))) % 0x100;
		}
		memcpy(pairing_cmd + 5, boxID, sizeof(boxID));
	}
	write_cmd(pairing_cmd, pairing_cmd + 5);
	if((cta_res[cta_lr - 2] == 0x94) && (cta_res[cta_lr - 1] == 0xB1) ) {
		rdr_log(reader, "This card is not binding to any box,continue...");
	}
	else if((cta_res[cta_lr - 2] == 0x94) && (cta_res[cta_lr - 1] == 0xB2))
	{
		if(reader->tongfang_version >= 3){
			memcpy(pairing_cmd + 5, reader->hexserial + 2, 4);
			write_cmd(pairing_cmd, pairing_cmd + 5);

			if((cta_res[cta_lr - 2] == 0x90) && (cta_res[cta_lr - 1] == 0x00) ) {
				rdr_log(reader, "This card and the box pairing succeed!");
			}
			else {
				rdr_log(reader, "error: this card is not binding to this box!");
				return ERROR;
			}
		}
		else
			rdr_log(reader, "This card and the box pairing succeed!");
	}
	else
	{
		rdr_log(reader, "warning: pairing card and box failed! continue...");
		//return ERROR;
	}

	rdr_log_sensitive(reader, "type: Tongfang, caid: %04X, serial: {%llu}, hex serial: {%02x%02x%02x%02x},"\
			"Card ID: {%s}, BoxID: {%02X%02X%02X%02X}",
			reader->caid, (unsigned long long) b2ll(6, reader->hexserial), reader->hexserial[2],
			reader->hexserial[3], reader->hexserial[4], reader->hexserial[5], card_id,
			boxID[0], boxID[1], boxID[2], boxID[3]);

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
	if((ecm_len = check_sct_len(er->ecm, 3)) < 0) {
		rdr_log(reader, "error: check_sct_len failed, smartcard section too long %d > %d", SCT_LEN(er->ecm), MAX_LEN - 3);
		return ERROR;
	}

	for(i = 0; i < ecm_len; i++)
	{
		if((i < ecm_len-1) && (er->ecm[i] == 0x80) && (er->ecm[i+1] == 0x3a)
		     && (er->ecm[i+2] == er->ecm[5]) && (er->ecm[i+3]==er->ecm[6]))
			break;
	}
	if(i == ecm_len){
		rdr_log(reader, "error: not valid ecm data...");
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
		rdr_log(reader,"error: cw is unvalid.");
		return ERROR;
	}

	if(reader->tongfang_version >=3 ){
		uchar cw[16];
		tongfang3_des0(1, ea->cw, reader->tongfang3_commkey, cw);
		tongfang3_des0(1, ea->cw+8, reader->tongfang3_commkey, cw+8);
		memcpy(ea->cw,cw,16);
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
	def_resp;
	int32_t i;

	write_cmd(get_provider_cmd, NULL);
	if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00)) { return ERROR; }

	for(i = 0; i < 4; i++)
	{
		rdr_log(reader, "Provider:%02x%02x", cta_res[i * 2], cta_res[i * 2 + 1]);
	}
	return OK;
}

const struct s_cardsystem reader_tongfang =
{
	.desc         = "tongfang",
	.caids        = (uint16_t[]){ 0x4B, 0 },
	.do_emm       = tongfang_do_emm,
	.do_ecm       = tongfang_do_ecm,
	.card_info    = tongfang_card_info,
	.card_init    = tongfang_card_init,
	.get_emm_type = tongfang_get_emm_type,
};

#endif
