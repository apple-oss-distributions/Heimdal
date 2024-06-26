/*
 * Copyright (c) 2009 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 - 2010 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "der_locl.h"
#include <com_err.h>

#undef HEIMDAL_PRINTF_ATTRIBUTE
#define HEIMDAL_PRINTF_ATTRIBUTE(x)
#undef HEIMDAL_NORETURN_ATTRIBUTE
#define HEIMDAL_NORETURN_ATTRIBUTE

#ifdef __APPLE__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wlanguage-extension-token"

const char *__crashreporter_info__ = NULL;
asm(".desc ___crashreporter_info__, 0x10");
static char crashreporter_info[100];

#pragma clang diagnostic pop
#endif


void
asn1_abort(const char *fmt, ...)
    HEIMDAL_PRINTF_ATTRIBUTE((printf, 1, 2))
    HEIMDAL_NORETURN_ATTRIBUTE
{
#ifdef __APPLE__
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(crashreporter_info, sizeof(crashreporter_info), fmt, ap);
    va_end(ap);
    __crashreporter_info__ = crashreporter_info;
#endif
    abort();
}



struct asn1_type_func asn1_template_prim[A1T_NUM_ENTRY] = {
#define el(name, type) {				\
	(asn1_type_encode)der_put_##name,		\
	(asn1_type_decode)der_get_##name,		\
	(asn1_type_length)der_length_##name,		\
	(asn1_type_copy)der_copy_##name,		\
	(asn1_type_release)der_free_##name,		\
	sizeof(type)					\
    }
#define elber(name, type) {				\
	(asn1_type_encode)der_put_##name,		\
	(asn1_type_decode)der_get_##name##_ber,		\
	(asn1_type_length)der_length_##name,		\
	(asn1_type_copy)der_copy_##name,		\
	(asn1_type_release)der_free_##name,		\
	sizeof(type)					\
    }
    el(integer, int),
    el(heim_integer, heim_integer),
    el(integer, int),
    el(unsigned, unsigned),
    el(general_string, heim_general_string),
    el(octet_string, heim_octet_string),
    elber(octet_string, heim_octet_string),
    el(ia5_string, heim_ia5_string),
    el(bmp_string, heim_bmp_string),
    el(universal_string, heim_universal_string),
    el(printable_string, heim_printable_string),
    el(visible_string, heim_visible_string),
    el(utf8string, heim_utf8_string),
    el(generalized_time, time_t),
    el(utctime, time_t),
    el(bit_string, heim_bit_string),
    { (asn1_type_encode)der_put_boolean, (asn1_type_decode)der_get_boolean,
      (asn1_type_length)der_length_boolean, (asn1_type_copy)der_copy_integer,
      (asn1_type_release)der_free_integer, sizeof(int)
    },
    el(oid, heim_oid),
    el(general_string, heim_general_string),
#undef el
#undef elber
};

size_t
_asn1_sizeofType(const struct asn1_template *t)
{
    return t->offset;
}

/*
 * Here is abstraction to not so well evil fact of bit fields in C,
 * they are endian dependent, so when getting and setting bits in the
 * host local structure we need to know the endianness of the host.
 *
 * Its not the first time in Heimdal this have bitten us, and some day
 * we'll grow up and use #defined constant, but bit fields are still
 * so pretty and shiny.
 */

static void
_asn1_bmember_get_bit(const unsigned char *p, void *data,
		      unsigned int bit, size_t size)
{
    unsigned int localbit = bit % 8;
    if ((*p >> (7 - localbit)) & 1) {
#ifdef WORDS_BIGENDIAN
	*(unsigned int *)data |= (1 << ((size * 8) - bit - 1));
#else
	*(unsigned int *)data |= (1 << bit);
#endif
    }
}

int
_asn1_bmember_isset_bit(const void *data, unsigned int bit, size_t size)
{
#ifdef WORDS_BIGENDIAN
    if ((*(const unsigned int *)data) & (1 << ((size * 8) - bit - 1)))
	return 1;
    return 0;
#else
    if ((*(const unsigned int *)data) & (1 << bit))
	return 1;
    return 0;
#endif
}

void
_asn1_bmember_put_bit(unsigned char *p, const void *data, unsigned int bit,
		      size_t size, unsigned int *bitset)
{
    unsigned int localbit = bit % 8;

    if (_asn1_bmember_isset_bit(data, bit, size)) {
	*p |= (1 << (7 - localbit));
	if (*bitset == 0)
	    *bitset = (7 - localbit) + 1;
    }
}

int
_asn1_decode(const struct asn1_template *t, unsigned flags,
	     const unsigned char *p, size_t len, void *data, size_t *size)
{
    size_t elements = A1_HEADER_LEN(t);
    size_t oldlen = len;
    int ret = 0;
    const unsigned char *startp = NULL;
    unsigned int template_flags = t->tt;

    /* skip over header */
    t++;

    if (template_flags & A1_HF_PRESERVE)
	startp = p;

    while (elements) {
	switch (t->tt & A1_OP_MASK) {
	case A1_OP_TYPE:
	case A1_OP_TYPE_EXTERN: {
	    size_t newsize, elsize;
	    void *el = DPO(data, t->offset);
	    void **pel = (void **)el;

	    if ((t->tt & A1_OP_MASK) == A1_OP_TYPE) {
		elsize = _asn1_sizeofType(t->ptr);
	    } else {
		const struct asn1_type_func *f = t->ptr;
		elsize = f->size;
	    }

	    if (t->tt & A1_FLAG_OPTIONAL) {
		*pel = calloc(1, elsize);
		if (*pel == NULL)
		    return ENOMEM;
		el = *pel;
	    }
	    if ((t->tt & A1_OP_MASK) == A1_OP_TYPE) {
		ret = _asn1_decode(t->ptr, flags, p, len, el, &newsize);
	    } else {
		const struct asn1_type_func *f = t->ptr;
		ret = (f->decode)(p, len, el, &newsize);
	    }
	    if (ret) {
		if (t->tt & A1_FLAG_OPTIONAL) {
		    free(*pel);
		    *pel = NULL;
		    break;
		}
		return ret;
	    }
	    p += newsize; len -= newsize;

	    break;
	}
	case A1_OP_TAG: {
	    Der_type dertype;
	    size_t newsize;
	    size_t datalen, l;
	    void *olddata = data;
	    int is_indefinite = 0;
	    int subflags = flags;

	    ret = der_match_tag_and_length(p, len, A1_TAG_CLASS(t->tt),
					   &dertype, A1_TAG_TAG(t->tt),
					   &datalen, &l);
	    if (ret) {
		if (t->tt & A1_FLAG_OPTIONAL)
		    break;
		return ret;
	    }

	    p += l; len -= l;

	    /*
	     * Only allow indefinite encoding for OCTET STRING and nested BER
	     * for now. Should handle BIT STRING too.
	     */

	    if (dertype != A1_TAG_TYPE(t->tt) && (flags & A1_PF_ALLOW_BER)) {
		const struct asn1_template *subtype = t->ptr;
		subtype++; /* skip header */

		if (((subtype->tt & A1_OP_MASK) == A1_OP_PARSE) &&
		    A1_PARSE_TYPE(subtype->tt) == A1T_OCTET_STRING)
		    subflags |= A1_PF_NESTED_INDEFINITE;
	    }

	    if (datalen == ASN1_INDEFINITE) {
		if ((flags & A1_PF_ALLOW_BER) == 0)
		    return ASN1_GOT_BER;
		is_indefinite = 1;
		subflags |= A1_PF_INDEFINITE;
		datalen = len;
		if (datalen < 2)
		    return ASN1_OVERRUN;
		/* hide EndOfContent for sub-decoder, catching it below */
		datalen -= 2;
	    } else if (datalen > len)
		return ASN1_OVERRUN;

	    data = DPO(data, t->offset);

	    if (t->tt & A1_FLAG_OPTIONAL) {
		void **el = (void **)data;
		size_t ellen = _asn1_sizeofType(t->ptr);

		*el = calloc(1, ellen);
		if (*el == NULL)
		    return ENOMEM;
		data = *el;
	    }

	    ret = _asn1_decode(t->ptr, subflags, p, datalen, data, &newsize);
	    if (ret)
		return ret;

	    if (is_indefinite) {
		/* If we use indefinite encoding, the newsize is the datasize. */
		datalen = newsize;
	    } else if (newsize != datalen) {
		/* Check for hidden data that might be after the real tag */
		return ASN1_EXTRA_DATA;
	    }

	    len -= datalen;
	    p += datalen;

	    /*
	     * Indefinite encoding needs a trailing EndOfContent,
	     * check for that.
	     */
	    if (is_indefinite) {
		ret = der_match_tag_and_length(p, len, ASN1_C_UNIV,
					       &dertype, UT_EndOfContent,
					       &datalen, &l);
		if (ret)
		    return ret;
		if (dertype != PRIM)
		    return ASN1_BAD_ID;
		if (datalen != 0)
		    return ASN1_INDEF_EXTRA_DATA;
		p += l; len -= l;
	    }
	    data = olddata;

	    break;
	}
	case A1_OP_PARSE: {
	    unsigned int type = A1_PARSE_TYPE(t->tt);
	    size_t newsize;
	    void *el = DPO(data, t->offset);

	    /*
	     * INDEFINITE primitive types are one element after the
	     * same type but non-INDEFINITE version.
	    */
	    if (flags & A1_PF_NESTED_INDEFINITE)
		type++;

	    if (type >= sizeof(asn1_template_prim)/sizeof(asn1_template_prim[0])) {
		ABORT_ON_ERROR("type larger then asn1_template_prim: %d", type);
	    }

	    ret = (asn1_template_prim[type].decode)(p, len, el, &newsize);
	    if (ret)
		return ret;
	    p += newsize; len -= newsize;

	    break;
	}
	case A1_OP_SETOF:
	case A1_OP_SEQOF: {
	    struct template_of *el = DPO(data, t->offset);
	    size_t newsize;
	    size_t ellen = _asn1_sizeofType(t->ptr);
	    size_t vallength = 0;

	    while (len > 0) {
		/* If the outer SEQ OF/SET_OF was indefinite, check for EOC to stop
		 * parsing items. */
		if (flags & A1_PF_INDEFINITE) {
		    Der_type dertype;
		    size_t datalen, l;
		    ret = der_match_tag_and_length(p, len, ASN1_C_UNIV,
						   &dertype, UT_EndOfContent,
						   &datalen, &l);
		    if (ret == 0)
			break;
		}

		void *tmp;
		size_t newlen = vallength + ellen;
		if (vallength > newlen)
		    return ASN1_OVERFLOW;

		tmp = realloc(el->val, newlen);
		if (tmp == NULL)
		    return ENOMEM;

		memset(DPO(tmp, vallength), 0, ellen);
		el->val = tmp;
		el->len++;

		ret = _asn1_decode(t->ptr, flags & (~(A1_PF_INDEFINITE | A1_PF_NESTED_INDEFINITE)), p, len,
				   DPO(el->val, vallength), &newsize);
		if (ret)
		    return ret;
		vallength = newlen;
		p += newsize; len -= newsize;
	    }

	    break;
	}
	case A1_OP_BMEMBER: {
	    const struct asn1_template *bmember = t->ptr;
	    size_t bsize = bmember->offset;
	    size_t belements = A1_HEADER_LEN(bmember);
	    size_t pos = 0;

	    bmember++;

	    memset(data, 0, bsize);

	    if (len < 1)
		return ASN1_OVERRUN;
	    p++; len--;

	    while (belements && len) {
		while (bmember->offset / 8 > pos / 8) {
		    if (len < 1)
			break;
		    p++; len--;
		    pos += 8;
		}
		if (len) {
		    _asn1_bmember_get_bit(p, data, bmember->offset, bsize);
		    belements--; bmember++;
		}
	    }
	    len = 0;
	    break;
	}
	case A1_OP_CHOICE: {
	    const struct asn1_template *choice = t->ptr;
	    int *element = DPO(data, choice->offset);
	    size_t datalen;
	    unsigned int i;

	    /* provide a invalid value as default (0, so same as memset) */
	    *element = ASN1_CHOICE_INVALID;
	   
	    for (i = 1; i < A1_HEADER_LEN(choice) + 1; i++) {
		/* should match first tag instead, store it in choice.tt */
		ret = _asn1_decode(choice[i].ptr, 0, p, len,
				   DPO(data, choice[i].offset), &datalen);
		if (ret == 0) {
		    *element = i;
		    p += datalen; len -= datalen;
		    break;
		} else if (ret != ASN1_BAD_ID && ret != ASN1_MISPLACED_FIELD && ret != ASN1_MISSING_FIELD) {
		    _asn1_free_top(choice[i].ptr, DPO(data, choice[i].offset));
		    return ret;
		}
		_asn1_free_top(choice[i].ptr, DPO(data, choice[i].offset));
	    }
	    if (i >= A1_HEADER_LEN(choice) + 1) {
		if (choice->tt == 0)
		    return ASN1_BAD_ID;

		*element = ASN1_CHOICE_ELLIPSIS;
		ret = der_get_octet_string(p, len,
					   DPO(data, choice->tt), &datalen);
		if (ret)
		    return ret;
		p += datalen; len -= datalen;
	    }

	    break;
	}
	default:
	    ABORT_ON_ERROR("unknown opcode: %d", (t->tt & A1_OP_MASK));
	}
	t++;
	elements--;
    }
    /* if we are using padding, eat up read of context */
    if (template_flags & A1_HF_ELLIPSIS)
	len = 0;

    oldlen -= len;

    if (size)
	*size = oldlen;

    /*
     * saved the raw bits if asked for it, useful for signature
     * verification.
     */
    if (startp) {
	heim_octet_string *save = data;

	save->data = malloc(oldlen);
	if (save->data == NULL)
	    return ENOMEM;
	else {
	    save->length = oldlen;
	    memcpy(save->data, startp, oldlen);
	}
    }
    return 0;
}

int
_asn1_encode(const struct asn1_template *t, unsigned char *p, size_t len, const void *data, size_t *size)
{
    size_t elements = A1_HEADER_LEN(t);
    int ret = 0;
    size_t oldlen = len;

    t += A1_HEADER_LEN(t);

    while (elements) {
	switch (t->tt & A1_OP_MASK) {
	case A1_OP_TYPE:
	case A1_OP_TYPE_EXTERN: {
	    size_t newsize;
	    const void *el = DPOC(data, t->offset);

	    if (t->tt & A1_FLAG_OPTIONAL) {
		void * const *pel = (void * const *)el;
		if (*pel == NULL)
		    break;
		el = *pel;
	    }

	    if ((t->tt & A1_OP_MASK) == A1_OP_TYPE) {
		ret = _asn1_encode(t->ptr, p, len, el, &newsize);
	    } else {
		const struct asn1_type_func *f = t->ptr;
		ret = (f->encode)(p, len, el, &newsize);
	    }

	    if (ret)
		return ret;
	    p -= newsize; len -= newsize;

	    break;
	}
	case A1_OP_TAG: {
	    const void *olddata = data;
	    size_t l, datalen;

	    data = DPOC(data, t->offset);

	    if (t->tt & A1_FLAG_OPTIONAL) {
		void * const *el = (void * const *)data;
		if (*el == NULL) {
		    data = olddata;
		    break;
		}
		data = *el;
	    }

	    ret = _asn1_encode(t->ptr, p, len, data, &datalen);
	    if (ret)
		return ret;

	    len -= datalen; p -= datalen;

	    ret = der_put_length_and_tag(p, len, datalen,
					 A1_TAG_CLASS(t->tt),
					 A1_TAG_TYPE(t->tt),
					 A1_TAG_TAG(t->tt), &l);
	    if (ret)
		return ret;

	    p -= l; len -= l;

	    data = olddata;

	    break;
	}
	case A1_OP_PARSE: {
	    unsigned int type = A1_PARSE_TYPE(t->tt);
	    size_t newsize;
	    const void *el = DPOC(data, t->offset);

	    if (type > sizeof(asn1_template_prim)/sizeof(asn1_template_prim[0])) {
		ABORT_ON_ERROR("type larger then asn1_template_prim: %d", type);
	    }

	    ret = (asn1_template_prim[type].encode)(p, len, el, &newsize);
	    if (ret)
		return ret;
	    p -= newsize; len -= newsize;

	    break;
	}
	case A1_OP_SETOF: {
	    const struct template_of *el = DPOC(data, t->offset);
	    size_t ellen = _asn1_sizeofType(t->ptr);
	    heim_octet_string *val;
	    unsigned char *elptr = el->val;
	    size_t i, totallen;

	    if (el->len == 0)
		break;

	    if (el->len > UINT_MAX/sizeof(val[0]))
		return ERANGE;

	    val = calloc(el->len, sizeof(val[0]));
	    if (val == NULL)
		return ENOMEM;

	    for(totallen = 0, i = 0; i < el->len; i++) {
		unsigned char *next;
		size_t l;

		val[i].length = _asn1_length(t->ptr, elptr);
		if (val[i].length) {
		    val[i].data = malloc(val[i].length);
		    if (val[i].data == NULL) {
			ret = ENOMEM;
			break;
		    }
		}

		ret = _asn1_encode(t->ptr, DPO(val[i].data, val[i].length - 1),
				   val[i].length, elptr, &l);
		if (ret)
		    break;

		next = elptr + ellen;
		if (next < elptr) {
		    ret = ASN1_OVERFLOW;
		    break;
		}
		elptr = next;
		totallen += val[i].length;
	    }
	    if (ret == 0 && totallen > len)
		ret = ASN1_OVERFLOW;
	    if (ret) {
		for (i = 0; i < el->len; i++)
		    free(val[i].data);
		free(val);
		return ret;
	    }

	    len -= totallen;

	    qsort(val, el->len, sizeof(val[0]), _heim_der_set_sort);

	    i = el->len - 1;
	    do {
		p -= val[i].length;
		memcpy(p + 1, val[i].data, val[i].length);
		free(val[i].data);
	    } while(i-- > 0);
	    free(val);

	    break;

	}
	case A1_OP_SEQOF: {
	    const struct template_of *el = DPOC(data, t->offset);
	    size_t ellen = _asn1_sizeofType(t->ptr);
	    size_t newsize;
	    unsigned int i;
	    unsigned char *elptr = el->val;

	    if (el->len == 0)
		break;

	    elptr += ellen * (el->len - 1);

	    for (i = 0; i < el->len; i++) {
		ret = _asn1_encode(t->ptr, p, len,
				   elptr,
				   &newsize);
		if (ret)
		    return ret;
		p -= newsize; len -= newsize;
		elptr -= ellen;
	    }

	    break;
	}
	case A1_OP_BMEMBER: {
	    const struct asn1_template *bmember = t->ptr;
	    size_t bsize = bmember->offset;
	    size_t belements = A1_HEADER_LEN(bmember);
	    size_t pos;
	    unsigned char c = 0;
	    unsigned int bitset = 0;
	    int rfc1510 = (bmember->tt & A1_HBF_RFC1510);

	    bmember += belements;

	    if (rfc1510)
		pos = 31;
	    else
		pos = bmember->offset;

	    while (belements && len) {
		while (bmember->offset / 8 < pos / 8) {
		    if (rfc1510 || bitset || c) {
			if (len < 1)
			    return ASN1_OVERFLOW;
			*p-- = c; len--;
		    }
		    c = 0;
		    pos -= 8;
		}
		_asn1_bmember_put_bit(&c, data, bmember->offset, bsize, &bitset);
		belements--; bmember--;
	    }
	    if (rfc1510 || bitset) {
		if (len < 1)
		    return ASN1_OVERFLOW;
		*p-- = c; len--;
	    }

	    if (len < 1)
		return ASN1_OVERFLOW;
	    if (rfc1510 || bitset == 0)
		*p-- = 0;
	    else
		*p-- = bitset - 1;

	    len--;

	    break;
	}
	case A1_OP_CHOICE: {
	    const struct asn1_template *choice = t->ptr;
	    const int *element = DPOC(data, choice->offset);
	    size_t datalen;
	    const void *el;

	    if (*element == ASN1_CHOICE_INVALID || *element > (int)A1_HEADER_LEN(choice)) {
		ABORT_ON_ERROR("invalid choice: %d", *element);
	    }

	    if (*element == ASN1_CHOICE_ELLIPSIS) {
		ret += der_put_octet_string(p, len,
					    DPOC(data, choice->tt), &datalen);
	    } else {
		choice += *element;
		el = DPOC(data, choice->offset);
		ret = _asn1_encode(choice->ptr, p, len, el, &datalen);
		if (ret)
		    return ret;
	    }
	    len -= datalen; p -= datalen;

	    break;
	}
	default:
	    ABORT_ON_ERROR("unknown opcode: %d", (t->tt & A1_OP_MASK));
	}
	t--;
	elements--;
    }
    if (size)
	*size = oldlen - len;

    return 0;
}

size_t
_asn1_length(const struct asn1_template *t, const void *data)
{
    size_t elements = A1_HEADER_LEN(t);
    size_t ret = 0;

    t += A1_HEADER_LEN(t);

    while (elements) {
	switch (t->tt & A1_OP_MASK) {
	case A1_OP_TYPE:
	case A1_OP_TYPE_EXTERN: {
	    const void *el = DPOC(data, t->offset);

	    if (t->tt & A1_FLAG_OPTIONAL) {
		void * const * pel = (void * const *)el;
		if (*pel == NULL)
		    break;
		el = *pel;
	    }

	    if ((t->tt & A1_OP_MASK) == A1_OP_TYPE) {
		ret += _asn1_length(t->ptr, el);
	    } else {
		const struct asn1_type_func *f = t->ptr;
		ret += (f->length)(el);
	    }
	    break;
	}
	case A1_OP_TAG: {
	    size_t datalen;
	    const void *olddata = data;

	    data = DPOC(data, t->offset);

	    if (t->tt & A1_FLAG_OPTIONAL) {
		void * const *el = (void * const *)data;
		if (*el == NULL) {
		    data = olddata;
		    break;
		}
		data = *el;
	    }
	    datalen = _asn1_length(t->ptr, data);
	    ret += der_length_tag(A1_TAG_TAG(t->tt)) + der_length_len(datalen);
	    ret += datalen;
	    data = olddata;
	    break;
	}
	case A1_OP_PARSE: {
	    unsigned int type = A1_PARSE_TYPE(t->tt);
	    const void *el = DPOC(data, t->offset);

	    if (type > sizeof(asn1_template_prim)/sizeof(asn1_template_prim[0])) {
		ABORT_ON_ERROR("type larger then asn1_template_prim: %d", type);
	    }
	    ret += (asn1_template_prim[type].length)(el);
	    break;
	}
	case A1_OP_SETOF:
	case A1_OP_SEQOF: {
	    const struct template_of *el = DPOC(data, t->offset);
	    size_t ellen = _asn1_sizeofType(t->ptr);
	    const unsigned char *element = el->val;
	    unsigned int i;

	    for (i = 0; i < el->len; i++) {
		ret += _asn1_length(t->ptr, element);
		element += ellen;
	    }

	    break;
	}
	case A1_OP_BMEMBER: {
	    const struct asn1_template *bmember = t->ptr;
	    size_t size = bmember->offset;
	    size_t belements = A1_HEADER_LEN(bmember);
	    int rfc1510 = (bmember->tt & A1_HBF_RFC1510);

	    if (rfc1510) {
		ret += 5;
	    } else {

		ret += 1;

		bmember += belements;

		while (belements) {
		    if (_asn1_bmember_isset_bit(data, bmember->offset, size)) {
			ret += (bmember->offset / 8) + 1;
			break;
		    }
		    belements--; bmember--;
		}
	    }
	    break;
	}
	case A1_OP_CHOICE: {
	    const struct asn1_template *choice = t->ptr;
	    const int *element = DPOC(data, choice->offset);

	    if (*element == ASN1_CHOICE_INVALID || *element > (int)A1_HEADER_LEN(choice)) {
		ABORT_ON_ERROR("invalid choice: %d", *element);
	    }

	    if (*element == ASN1_CHOICE_ELLIPSIS) {
		ret += der_length_octet_string(DPOC(data, choice->tt));
	    } else {
		choice += *element;
		ret += _asn1_length(choice->ptr, DPOC(data, choice->offset));
	    }
	    break;
	}
	default:
	    ABORT_ON_ERROR("unknown opcode: %d", (t->tt & A1_OP_MASK));
	}
	elements--;
	t--;
    }
    return ret;
}

void
_asn1_free(const struct asn1_template *t, void *data)
{
    size_t elements = A1_HEADER_LEN(t);

    if (t->tt & A1_HF_PRESERVE)
	der_free_octet_string(data);

    t++;

    while (elements) {
	switch (t->tt & A1_OP_MASK) {
	case A1_OP_TYPE:
	case A1_OP_TYPE_EXTERN: {
	    void *el = DPO(data, t->offset);

	    if (t->tt & A1_FLAG_OPTIONAL) {
		void **pel = (void **)el;
		if (*pel == NULL)
		    break;
		el = *pel;
	    }

	    if ((t->tt & A1_OP_MASK) == A1_OP_TYPE) {
		_asn1_free(t->ptr, el);
	    } else {
		const struct asn1_type_func *f = t->ptr;
		(f->release)(el);
	    }
	    if (t->tt & A1_FLAG_OPTIONAL)
		free(el);

	    break;
	}
	case A1_OP_PARSE: {
	    unsigned int type = A1_PARSE_TYPE(t->tt);
	    void *el = DPO(data, t->offset);

	    if (type > sizeof(asn1_template_prim)/sizeof(asn1_template_prim[0])) {
		ABORT_ON_ERROR("type larger then asn1_template_prim: %d", type);
	    }
	    (asn1_template_prim[type].release)(el);
	    break;
	}
	case A1_OP_TAG: {
	    void *el = DPO(data, t->offset);

	    if (t->tt & A1_FLAG_OPTIONAL) {
		void **pel = (void **)el;
		if (*pel == NULL)
		    break;
		el = *pel;
	    }

	    _asn1_free(t->ptr, el);

	    if (t->tt & A1_FLAG_OPTIONAL)
		free(el);

	    break;
	}
	case A1_OP_SETOF:
	case A1_OP_SEQOF: {
	    struct template_of *el = DPO(data, t->offset);
	    size_t ellen = _asn1_sizeofType(t->ptr);
	    unsigned char *element = el->val;
	    unsigned int i;

	    for (i = 0; i < el->len; i++) {
		_asn1_free(t->ptr, element);
		element += ellen;
	    }
	    free(el->val);
	    el->val = NULL;
	    el->len = 0;

	    break;
	}
	case A1_OP_BMEMBER:
	    break;
	case A1_OP_CHOICE: {
	    const struct asn1_template *choice = t->ptr;
	    const int *element = DPOC(data, choice->offset);

	    if (*element == ASN1_CHOICE_INVALID)
		break;

	    if (*element > (int)A1_HEADER_LEN(choice)) {
		ABORT_ON_ERROR("invalid choice: %d", *element);
	    }

	    if (*element == ASN1_CHOICE_ELLIPSIS) {
		der_free_octet_string(DPO(data, choice->tt));
	    } else {
		choice += *element;
		_asn1_free(choice->ptr, DPO(data, choice->offset));
	    }
	    break;
	}
	default:
	    ABORT_ON_ERROR("unknown opcode: %d", (t->tt & A1_OP_MASK));
	}
	t++;
	elements--;
    }
}

int
_asn1_copy(const struct asn1_template *t, const void *from, void *to)
{
    size_t elements = A1_HEADER_LEN(t);
    int ret = 0;
    int preserve = (t->tt & A1_HF_PRESERVE);

    t++;

    if (preserve) {
	ret = der_copy_octet_string(from, to);
	if (ret)
	    return ret;
    }

    while (elements) {
	switch (t->tt & A1_OP_MASK) {
	case A1_OP_TYPE:
	case A1_OP_TYPE_EXTERN: {
	    const void *fel = DPOC(from, t->offset);
	    void *tel = DPO(to, t->offset);
	    void **ptel = (void **)tel;
	    size_t size;

	    if ((t->tt & A1_OP_MASK) == A1_OP_TYPE) {
		size = _asn1_sizeofType(t->ptr);
	    } else {
		const struct asn1_type_func *f = t->ptr;
		size = f->size;
	    }

	    if (t->tt & A1_FLAG_OPTIONAL) {
		void * const *pfel = (void *const *)fel;
		if (*pfel == NULL)
		    break;
		fel = *pfel;

		tel = *ptel = calloc(1, size);
		if (tel == NULL)
		    return ENOMEM;
	    }

	    if ((t->tt & A1_OP_MASK) == A1_OP_TYPE) {
		ret = _asn1_copy(t->ptr, fel, tel);
	    } else {
		const struct asn1_type_func *f = t->ptr;
		ret = (f->copy)(fel, tel);
	    }

	    if (ret) {
		if (t->tt & A1_FLAG_OPTIONAL) {
		    free(*ptel);
		    *ptel = NULL;
		}
		return ret;
	    }
	    break;
	}
	case A1_OP_PARSE: {
	    unsigned int type = A1_PARSE_TYPE(t->tt);
	    const void *fel = DPOC(from, t->offset);
	    void *tel = DPO(to, t->offset);

	    if (type > sizeof(asn1_template_prim)/sizeof(asn1_template_prim[0])) {
		ABORT_ON_ERROR("type larger then asn1_template_prim: %d", type);
	    }
	    ret = (asn1_template_prim[type].copy)(fel, tel);
	    if (ret)
		return ret;
	    break;
	}
	case A1_OP_TAG: {
	    const void *oldfrom = from;
	    void *oldto = to;
	    void **tel = NULL;

	    from = DPOC(from, t->offset);
	    to = DPO(to, t->offset);

	    if (t->tt & A1_FLAG_OPTIONAL) {
		void * const * fel = (void * const *)from;
		tel = (void **)to;
		if (*fel == NULL) {
		    from = oldfrom;
		    to = oldto;
		    break;
		}
		from = *fel;

		to = *tel = calloc(1, _asn1_sizeofType(t->ptr));
		if (to == NULL)
		    return ENOMEM;
	    }

	    ret = _asn1_copy(t->ptr, from, to);
	    if (ret) {
		if (tel) {
		    free(*tel);
		    *tel = NULL;
		}
		return ret;
	    }

	    from = oldfrom;
	    to = oldto;

	    break;
	}
	case A1_OP_SETOF:
	case A1_OP_SEQOF: {
	    const struct template_of *fel = DPOC(from, t->offset);
	    struct template_of *tel = DPO(to, t->offset);
	    size_t ellen = _asn1_sizeofType(t->ptr);
	    unsigned int i;

	    tel->val = calloc(fel->len, ellen);
	    if (tel->val == NULL)
		return ENOMEM;

	    tel->len = fel->len;

	    for (i = 0; i < fel->len; i++) {
		ret = _asn1_copy(t->ptr,
				 DPOC(fel->val, (i * ellen)),
				 DPO(tel->val, (i *ellen)));
		if (ret)
		    return ret;
	    }
	    break;
	}
	case A1_OP_BMEMBER: {
	    const struct asn1_template *bmember = t->ptr;
	    size_t size = bmember->offset;
	    memcpy(to, from, size);
	    break;
	}
	case A1_OP_CHOICE: {
	    const struct asn1_template *choice = t->ptr;
	    const int *felement = DPOC(from, choice->offset);
	    int *telement = DPO(to, choice->offset);

	    if (*felement == ASN1_CHOICE_INVALID || *felement > (int)A1_HEADER_LEN(choice))
		return ASN1_INVALID_CHOICE;

	    *telement = *felement;

	    if (*felement == ASN1_CHOICE_ELLIPSIS) {
		ret = der_copy_octet_string(DPOC(from, choice->tt), DPO(to, choice->tt));
	    } else {
		choice += *felement;
		ret = _asn1_copy(choice->ptr,
				 DPOC(from, choice->offset),
				 DPO(to, choice->offset));
	    }
	    if (ret)
		return ret;
	    break;
	}
	default:
	    ABORT_ON_ERROR("unknown opcode: %d", (t->tt & A1_OP_MASK));
	}
	t++;
	elements--;
    }
    return 0;
}

int
_asn1_decode_top(const struct asn1_template *t, unsigned flags, const unsigned char *p, size_t len, void *data, size_t *size)
{
    int ret;
    memset(data, 0, t->offset);
    ret = _asn1_decode(t, flags, p, len, data, size);
    if (ret)
	_asn1_free_top(t, data);

    return ret;
}

int
_asn1_copy_top(const struct asn1_template *t, const void *from, void *to)
{
    int ret;
    memset(to, 0, t->offset);
    ret = _asn1_copy(t, from, to);
    if (ret)
	_asn1_free_top(t, to);

    return ret;
}

void
_asn1_free_top(const struct asn1_template *t, void *data)
{
    _asn1_free(t, data);
    memset(data, 0, t->offset);
}

#ifdef ASN1_CAPTURE_DATA

void
_asn1_capture_data(const char *type, const unsigned char *p, size_t len)
{
    static unsigned long count = 0;
    char *filename = NULL;
    int fd;

    asprintf(&filename, "/tmp/asn1/heimdal-%s-%s-%d-%lu", getprogname(), type, getpid(), count++);
    if (filename == NULL)
	return;

    fd = open(filename, O_WRONLY|O_TRUNC|O_CREAT, 0644);
    free(filename);
    if (fd < 0)
	return;
    write(fd, type, strlen(type) + 1);
    write(fd, p, len);
    close(fd);
}

#endif
