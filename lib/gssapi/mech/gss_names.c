/*-
 * Copyright (c) 2005 Doug Rabson
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/lib/libgssapi/gss_names.c,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */

#include "mech_locl.h"


__nullable gss_name_t
_gss_mg_get_underlaying_mech_name(__nonnull gss_name_t name,
				  __nonnull gss_const_OID mech)
{
	struct _gss_name *n = (struct _gss_name *)name;
	struct _gss_mechanism_name *mn;

	HEIM_SLIST_FOREACH(mn, &n->gn_mn, gmn_link) {
		if (gss_oid_equal(mech, mn->gmn_mech_oid))
			return mn->gmn_name;
	}
	return GSS_C_NO_NAME;
}


OM_uint32
_gss_find_mn(OM_uint32 *__nonnull minor_status,
	     struct _gss_name *__nonnull name,
	     __nonnull gss_const_OID mech,
	     struct _gss_mechanism_name * __nullable * __nonnull output_mn)
{
	OM_uint32 major_status;
	gssapi_mech_interface m;
	struct _gss_mechanism_name *mn;

	*output_mn = NULL;

	/* null names are ok, some mechs might not have names */
	if (name == NULL)
	    return GSS_S_COMPLETE;

	HEIM_SLIST_FOREACH(mn, &name->gn_mn, gmn_link) {
		if (gss_oid_equal(mech, mn->gmn_mech_oid))
			break;
	}

	if (!mn) {
		/*
		 * If this name is canonical (i.e. there is only an
		 * MN but it is from a different mech), give up now.
		 */
		if (!name->gn_value.value)
			return GSS_S_BAD_NAME;

		m = __gss_get_mechanism(mech);
		if (!m)
			return (GSS_S_BAD_MECH);

		mn = malloc(sizeof(struct _gss_mechanism_name));
		if (!mn)
			return GSS_S_FAILURE;

		major_status = m->gm_import_name(minor_status,
		    &name->gn_value,
		    (name->gn_type.elements
			? &name->gn_type : GSS_C_NO_OID),
		    &mn->gmn_name);
		if (major_status != GSS_S_COMPLETE) {
			_gss_mg_error(m, *minor_status);
			free(mn);
			return major_status;
		}

		mn->gmn_mech = m;
		mn->gmn_mech_oid = &m->gm_mech_oid;
		HEIM_SLIST_INSERT_HEAD(&name->gn_mn, mn, gmn_link);
	}
	*output_mn = mn;
	return 0;
}


/*
 * Make a name from an MN.
 */
struct _gss_name * __nullable
_gss_create_name(__nullable gss_name_t new_mn,
		 struct gssapi_mech_interface_desc * __nullable m)
{
	struct _gss_name *name;
	struct _gss_mechanism_name *mn;

	name = calloc(1, sizeof(struct _gss_name));
	if (!name)
		return (0);

	HEIM_SLIST_INIT(&name->gn_mn);

	if (new_mn) {
		mn = malloc(sizeof(struct _gss_mechanism_name));
		if (!mn) {
			free(name);
			return (0);
		}

		mn->gmn_mech = m;
		mn->gmn_mech_oid = &m->gm_mech_oid;
		mn->gmn_name = new_mn;
		HEIM_SLIST_INSERT_HEAD(&name->gn_mn, mn, gmn_link);
	}

	return (name);
}

/*
 *
 */

void
_gss_mg_release_name(struct _gss_name *__nonnull name)
{
	OM_uint32 junk;

	_gss_free_oid(&junk, &name->gn_type);

	while (HEIM_SLIST_FIRST(&name->gn_mn)) {
		struct _gss_mechanism_name *mn;
		mn = HEIM_SLIST_FIRST(&name->gn_mn);
		HEIM_SLIST_REMOVE_HEAD(&name->gn_mn, gmn_link);
		mn->gmn_mech->gm_release_name(&junk, &mn->gmn_name);
		free(mn);
	}
	gss_release_buffer(&junk, &name->gn_value);
	free(name);
}

void
_gss_mg_check_name(__nonnull gss_name_t name)
{
	if (name == NULL) return;
}

/*
 *
 */

OM_uint32
_gss_mech_import_name(OM_uint32 * __nonnull minor_status,
		      __nonnull gss_const_OID mech,
		      struct _gss_name_type *__nonnull names,
		      __nonnull const gss_buffer_t input_name_buffer,
		      __nonnull gss_const_OID input_name_type,
		      __nullable gss_name_t * __nonnull output_name)
{
    struct _gss_name_type *name;
    gss_buffer_t name_buffer = input_name_buffer;
    gss_buffer_desc export_name;

    *minor_status = 0;

    if (output_name == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    *output_name = GSS_C_NO_NAME;

    /*
     * If its a exported name, strip of the mech glue.
     */

    if (gss_oid_equal(input_name_type, GSS_C_NT_EXPORT_NAME)) {
	unsigned char *p;
	uint32_t length;

	if (name_buffer->length < 10 + mech->length)
	    return GSS_S_BAD_NAME;

	/* TOK, MECH_OID_LEN, DER(MECH_OID), NAME_LEN, NAME */

	p = name_buffer->value;

	if (memcmp(&p[0], "\x04\x01\x00", 3) != 0 ||
	    p[3] != mech->length + 2 ||
	    p[4] != 0x06 ||
	    p[5] != mech->length ||
	    memcmp(&p[6], mech->elements, mech->length) != 0)
	    return GSS_S_BAD_NAME;

	p += 6 + mech->length;

	length = p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
	p += 4;

	if (length > name_buffer->length - 10 - mech->length)
	    return GSS_S_BAD_NAME;

	/*
	 * Point this to the mech specific name part, don't modifity
	 * orignal input_name_buffer.
	 */

	export_name.length = length;
	export_name.value = p;

	name_buffer = &export_name;
    }

    for (name = names; name->gnt_parse != NULL; name++) {
	if (gss_oid_equal(input_name_type, name->gnt_name_type)
	    || (name->gnt_name_type == GSS_C_NO_OID && input_name_type == GSS_C_NO_OID))
	    return name->gnt_parse(minor_status, mech, name_buffer,
				   input_name_type, output_name);
    }

    return GSS_S_BAD_NAMETYPE;
}

OM_uint32
_gss_mech_inquire_names_for_mech(OM_uint32 * __nonnull minor_status,
				 struct _gss_name_type *__nonnull names,
				 gss_OID_set __nullable * __nonnull name_types)
{
    struct _gss_name_type *name;
    OM_uint32 ret, junk;

    ret = gss_create_empty_oid_set(minor_status, name_types);
    if (ret != GSS_S_COMPLETE)
	return ret;

    for (name = names; name->gnt_parse != NULL; name++) {
	if (name->gnt_name_type == GSS_C_NO_OID)
	    continue;
	ret = gss_add_oid_set_member(minor_status,
				     name->gnt_name_type,
				     name_types);
	if (ret != GSS_S_COMPLETE)
	    break;
    }

    if (ret != GSS_S_COMPLETE)
	gss_release_oid_set(&junk, name_types);
	
    return GSS_S_COMPLETE;
}
