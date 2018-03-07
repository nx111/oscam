#ifndef _CSCRIPT_JET_DH_H_
#define _CSCRIPT_JET_DH_H_

//typedef	unsigned short uint16_t;
//typedef	unsigned long uint64_t;

#if defined( M_XENIX )
#define	P(x)	x
#else
#define	P(x)	()
#endif

/*
 *	MAXINT		Maximum number per Elemenmt (must be uint16_t)
 *	MAXBIT		Maximum bit of MAXINT
 *	LOWBITS		Number of consekutiven low bits of MAXINT
 *	HIGHBIT		Highest bit MAXINT
 *	TOINT		must evaluate (uint16_t) ((x) % MAXINT)
 *	MAXLEN		Length of the uint16_t of array in each DH_NUMBERS
 */

#define MAXINT		0xFFFF

#if MAXINT == 99
#define	MAXBIT		7
#define	LOWBITS 	2
#endif
#if MAXINT == 9
#define	MAXBIT		4
#define	LOWBITS 	1
#endif
#if MAXINT == 1
#define MAXBIT		1
#endif
#if MAXINT == 0xFF
#define MAXBIT		8
#define	TOINT(x)	((uint16_t)(x))
#endif
#if MAXINT == 0xFFFF
#define MAXBIT		16
#define	TOINT(x)	((uint16_t)(x))
#endif

#ifndef	MAXBIT
#include	"<< ERROR: MAXBIT must be defined >>"
#endif
#ifndef	LOWBITS
#if MAXINT == (1 << MAXBIT) - 1
#define	LOWBITS		MAXBIT
#else
#include	"<< ERROR: LOWBITS must be defined >>"
#endif
#endif

#define	MAXLEN		(300*8/(MAXBIT + 1))
#define	STRLEN		(MAXLEN*MAXBIT/4)
#define	HIGHBIT		(1 << (MAXBIT-1) )

#if LOWBITS == MAXBIT
#define	DIVMAX1(x)	((x) >> MAXBIT)
#define	MODMAX1(x)	((x) & MAXINT)
#define	MULMAX1(x)	((x) << MAXBIT)
#else
#define	DIVMAX1(x)	((x) / (MAXINT+1))
#define	MODMAX1(x)	((x) % (MAXINT+1))
#define	MULMAX1(x)	((x) * (unsigned)(MAXINT+1))
#endif

#ifndef	TOINT
#define	TOINT(x)	((uint16_t)MODMAX1(x))
#endif

typedef struct
{
	int             length;
	uint16_t       values[MAXLEN];
} DH_NUMBERS;

#define	NUM0P	((DH_NUMBERS *)0)

void DH_Public_Key_Gen(unsigned char *in_buf, int len, unsigned char *out_buf);
void DH_Agree_Key_Gen(unsigned char *Y, int len, unsigned char *xx, int len1, unsigned char *kb);
#endif
