#include <stdio.h>
#include <string.h>
#include <memory.h>
#include "../globals.h"
#include "jet_dh.h"

static unsigned char default_DH[128] =
{
	0x01, 0x0B, 0xDC, 0x71, 0x5D, 0x2B, 0xCE, 0xFB, 0x36, 0xC6, 0x89, 0xFB, 0x0A, 0x6D, 0x31, 0x9E,
	0x05, 0xB9, 0x16, 0xFC, 0xA9, 0x61, 0xB1, 0x77, 0x56, 0x82, 0x95, 0x9B, 0xC4, 0x05, 0x70, 0xEE,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xDD, 0x2D, 0x72, 0x2A, 0x47, 0x8F, 0xCC, 0x51, 0xDA, 0xD2, 0x14, 0x24, 0x8B, 0xEB, 0x30, 0xC0,
	0xF5, 0x41, 0xBD, 0x16, 0x82, 0x1F, 0xD5, 0x8A, 0x4F, 0x10, 0x56, 0x3F, 0xCC, 0xB2, 0x92, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static inline int  IsLittleEndian(void)
{
	int i = 1;
	return (int) * ((unsigned char *)&i) == 1;
}

DH_NUMBERS NUMBERS_ONE =
{
	1,
	{ (uint16_t)1, },
};

DH_NUMBERS NUMBERS_TWO =
{
#if MAXINT == 1
	2,
	{ 0, (uint16_t)1, },
#else
	1,
	{ (uint16_t)2, },
#endif
};


static int n_cmp( uint16_t *i1, uint16_t *i2, int  l )
{
	i1 += (l - 1);
	i2 += (l - 1);

	for (; l--;)
		if ( *i1-- != *i2-- )
		    return( i1[1] > i2[1] ? 1 : -1 );

	return(0);
}

static int nm_cmp( DH_NUMBERS *c1, DH_NUMBERS *c2 )
{
	int l;
	if ( (l = c1->length) != c2->length)
		return( l - c2->length);

	return( n_cmp( c1->values, c2->values, l) );
}

static void nm_assign( DH_NUMBERS *d, DH_NUMBERS *s )
{
	int l;

	if (s == d)
		return;

	if ((l = s->length))
		memcpy( d->values, s->values, sizeof(uint16_t) * l);

	d->length = l;
}


static int n_sub( uint16_t *p1, uint16_t *p2, uint16_t *p3, int l, int lo )
{
	int ld, lc, same;
	int over = 0;
	register uint64_t dif;
	uint64_t a, b;

	same = (p1 == p3);

	for (lc = 1, ld = 0; l--; lc++)
	{
		a = (uint64_t) * p1++;
		if (lo)
		{
		    lo--;
		    b = (uint64_t) * p2++;
		}
		else
		    b = 0;

		if (over)
		    b++;
		if ( b > a )
		{
		    over = 1;
		    dif = (MAXINT + 1) + a;
		}
		else
		{
		    over = 0;
		    dif = a;
		}
		dif -= b;
		*p3++ = (uint16_t)dif;

		if (dif)
		    ld = lc;
		if (!lo && same && !over)
		{
		    if (l > 0)
		        ld = lc + l;
		    break;
		}
	}

	return( ld );
}

static void nm_imult( DH_NUMBERS *n, uint16_t m, DH_NUMBERS *d )
{

	if (m == 0)
		d->length = 0;
	else if (m == 1)
		nm_assign( d, n );
	else{

		int i;
		register uint64_t mul;

		int l = n->length;
		uint16_t *pvn = n->values, *pvd = d->values;

		for (i = l, mul = 0; i; i--)
		{
			mul += (uint64_t)m * (uint64_t)*pvn++;
			*pvd++ = TOINT(mul);
			mul  = DIVMAX1( mul );
		}

		if (mul)
		{
			 l++;
			*pvd = mul;
		}
		d->length = l;
	}
}

static void n_div( DH_NUMBERS *d1, DH_NUMBERS *z2, DH_NUMBERS *q, DH_NUMBERS *r )

{
	static	DH_NUMBERS dummy_rest;
	static	DH_NUMBERS dummy_quot;
	uint16_t *i1, *i1e, *i3;
	int l2, ld, l, lq;
#if MAXINT != 1
	uint16_t z;
	int pw, l2t;
#endif

	if (!z2->length)
		// abort();
		return;

	if (!r)
		r = &dummy_rest;
	if (!q)
		q = &dummy_quot;

	nm_assign( r, d1 );

	l2 = z2->length;
	l = r->length - l2;
	lq = l + 1;
	i3 = q->values + l;
	i1 = r->values + l;
	ld = l2;
	i1e = i1 + (ld - 1);

	for (; l >= 0; ld++, i1--, i1e--, l--, i3--)
	{
		*i3 = 0;

		if (ld == l2 && ! *i1e)
		{
		    ld--;
		    continue;
		}

		if ( ld > l2 || (ld == l2 && n_cmp( i1, z2->values, l2) >= 0 ) )
		{
#if MAXINT != 1
		    for (pw = MAXBIT - 1, z = (uint16_t)HIGHBIT; pw >= 0; pw--, z /= 2)
		    {
		        if ( ld > (l2t = z2[pw].length)
		                || (ld == l2t
		                    && n_cmp( i1, z2[pw].values, ld) >= 0) )
		        {
		            ld = n_sub( i1, z2[pw].values, i1, ld, l2t );
		            (*i3) += z;
		        }
		    }
#else
		    ld = n_sub( i1, z2->values, i1, ld, l2 );
		    (*i3) ++;
#endif
		}
	}

	l ++;
	lq -= l;
	ld += l;

	if (lq > 0 && !q->values[lq - 1])
		lq--;

	q->length = lq;
	r->length = ld - 1;
}


static void nm_div2( DH_NUMBERS *n )
{
#if MAXBIT == LOWBITS
	register uint16_t *p;
	int i;

#if MAXINT != 1
	register uint16_t h;
	register int c;

	c = 0;
	i = n->length;
	p = &n->values[i - 1];

	for (; i--;)
	{
		if (c)
		{
		    c = (h = *p) & 1;
		    h /= 2;
		    h |= HIGHBIT;
		}
		else
		{
		    c = (h = *p) & 1;
		    h /= 2;
		}

		*p-- = h;
	}

	if ( (i = n->length) && n->values[i - 1] == 0 )
		n->length = i - 1;

#else  /* MAXBIT != 1 */
	p = n->values;
	i = n->length;

	if (i)
	{
		n->length = i - 1;
		for (; --i ; p++)
		    p[0] = p[1];
	}
#endif /* MAXBIT != 1 */
#else  /* MAXBIT == LOWBITS */
	a_div( n, &NUMBERS_TWO, n, NUM0P );
#endif /* MAXBIT == LOWBITS */
}

static DH_NUMBERS mod_z2[ MAXBIT ];

static void nm_init( DH_NUMBERS *n, DH_NUMBERS *o)
{
	uint16_t z;
	int i;

	if (o)
		nm_assign( o, &mod_z2[0] );

	if (!nm_cmp( n, &mod_z2[0] ) )
		return;

	for (i = 0, z = 1; i < MAXBIT; i++, z *= 2)
	{
		nm_imult( n, z, &mod_z2[i] );
	}
}


static void nm_mult( DH_NUMBERS *m1, DH_NUMBERS *m2, DH_NUMBERS *d )

{
	static uint16_t id[ MAXLEN ];
	register uint16_t *vp;
	register uint64_t sum;
	register uint64_t tp1;
	register uint16_t *p2;
	uint16_t *p1;
	int l1, l2, ld, lc, l, i, j;

	l1 = m1->length;
	l2 = m2->length;
	l = l1 + l2;
	if (l >= MAXLEN)
		// abort();
		return;

	for (i = l, vp = id; i--;)
		*vp++ = 0;

	for ( p1 = m1->values, i = 0; i < l1 ; i++, p1++ )
	{

		tp1 = (uint64_t) * p1;
		vp = &id[i];
		sum = 0;
		for ( p2 = m2->values, j = l2; j--;)
		{
		    sum += (uint64_t) * vp + (tp1 * (uint64_t) * p2++);
		    *vp++ = TOINT( sum );
		    sum = DIVMAX1(sum);
		}
		*vp++ += (uint16_t)sum;
	}

	ld = 0;
	for (lc = 0, vp = id, p1 = d->values; lc++ < l;)
	{
		if ( *p1++ = *vp++ )
		    ld = lc;
	}

	d->length = ld;

	n_div( d, mod_z2, NUM0P, d );
}

static void nm_exp( DH_NUMBERS *x, DH_NUMBERS *n, DH_NUMBERS *z )
{
	DH_NUMBERS xt, nt;

	nm_assign( &nt, n );
	nm_assign( &xt, x );
	nm_assign( z, &NUMBERS_ONE );

	while (nt.length)
	{
		while ( ! (nt.values[0] & 1) )
		{
		    nm_mult( &xt, &xt, &xt );
		    nm_div2( &nt );
		}
		nm_mult( &xt, z, z );
		nt.length = n_sub( nt.values, NUMBERS_ONE.values, nt.values, nt.length, NUMBERS_ONE.length );

	}
}



static void nm_toBytes(DH_NUMBERS *n, unsigned char *s)
{

	unsigned int result = 0;
	unsigned char my_char, *p;
	int i;


	p = (unsigned char *)n->values;

	if ( ! IsLittleEndian() )
	{
		i = 0;
		do
		{
		    result = 2 * i;
		    i++;
		    my_char = p[result + 1 ];
		    p[result + 1] = p[result];
		    p[result] = my_char;
		}
		while ( i < n->length );
	}

	memcpy(s, (char *)n->values, n->length * 2);

}



static void bytesToNumbers( DH_NUMBERS *n, unsigned char *s, int len )
{
	unsigned int result = 0;
	unsigned char my_char, *p;
	int i;

	n->length = len / 2;
	p = (unsigned char *)n->values;


	memcpy((char *)n->values, s, len);

	if ( ! IsLittleEndian() )
	{
		i = 0;
		do
		{
		    result = 2 * i;
		    i++;
		    my_char = p[result + 1 ];
		    p[result + 1] = p[result];
		    p[result] = my_char;
		}
		while ( i < n->length );
	}


}


void DH_Public_Key_Gen(unsigned char *in_buf, int len, unsigned char *out_buf)
{
	DH_NUMBERS n, x, g;
	DH_NUMBERS o;

	bytesToNumbers( &n, default_DH, 32);
	bytesToNumbers( &x, in_buf, len);
	bytesToNumbers( &g, default_DH + 64 , 32);
	nm_init( &n, NUM0P );
	nm_exp(  &g, &x, &o );
	nm_toBytes(&o, out_buf);
}


void DH_Agree_Key_Gen(unsigned char *Y, int len, unsigned char *xx, int len1, unsigned char *kb)
{
	DH_NUMBERS n, x, g;
	DH_NUMBERS o;

	bytesToNumbers( &n, default_DH, 32);
	bytesToNumbers( &g, Y , len);
	bytesToNumbers( &x, xx,   len1);
	nm_init( &n, NUM0P );
	nm_exp(  &g, &x, &o );
	nm_toBytes(&o, kb);
}
