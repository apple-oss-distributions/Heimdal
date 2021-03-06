/*
 * Copyright (c) 2010, PADL Software Pty Ltd.
 * All rights reserved.
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
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "mech_locl.h"

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_inquire_name(OM_uint32 *__nonnull minor_status,
		 __nonnull gss_name_t input_name,
		 int *__nonnull name_is_MN,
		 __nullable gss_OID * __nullable MN_mech,
		 __nullable gss_buffer_set_t * __nullable attrs)
{
    OM_uint32 major_status = GSS_S_UNAVAILABLE;
    struct _gss_name *name = (struct _gss_name *) input_name;
    struct _gss_mechanism_name *mn;

    *minor_status = 0;
    if (name_is_MN != NULL)
        *name_is_MN = 0;
    if (MN_mech != NULL)
        *MN_mech = GSS_C_NO_OID;
    if (attrs != NULL)
        *attrs = GSS_C_NO_BUFFER_SET;

    if (input_name == GSS_C_NO_NAME)
        return GSS_S_BAD_NAME;

    HEIM_SLIST_FOREACH(mn, &name->gn_mn, gmn_link) {
        gssapi_mech_interface m = mn->gmn_mech;

        if (!m->gm_inquire_name)
            continue;

        major_status = m->gm_inquire_name(minor_status,
                                          mn->gmn_name,
                                          NULL,
                                          MN_mech,
                                          attrs);
        if (major_status == GSS_S_COMPLETE) {
            if (name_is_MN != NULL)
                *name_is_MN = 1;
            if (MN_mech != NULL && *MN_mech == GSS_C_NO_OID)
                *MN_mech = &m->gm_mech_oid;
            break;
        }
        _gss_mg_error(m, *minor_status);
    }

    return major_status;
}
