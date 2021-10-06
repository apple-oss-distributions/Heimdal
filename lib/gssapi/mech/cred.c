/*
 * Copyright (c) 2011 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2011 Apple Inc. All rights reserved.
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
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "mech_locl.h"
#include "heim_threads.h"
#include "heimbase.h"


void
_gss_mg_release_cred(struct _gss_cred *cred)
{
	struct _gss_mechanism_cred *mc;
	OM_uint32 junk;

	while (HEIM_SLIST_FIRST(&cred->gc_mc)) {
		mc = HEIM_SLIST_FIRST(&cred->gc_mc);
		HEIM_SLIST_REMOVE_HEAD(&cred->gc_mc, gmc_link);
		mc->gmc_mech->gm_release_cred(&junk, &mc->gmc_cred);
		free(mc);
	}
	free(cred);
}

struct _gss_cred *
_gss_mg_alloc_cred(void)
{
	struct _gss_cred *cred;
	cred = malloc(sizeof(struct _gss_cred));
	if (!cred)
		return NULL;
	HEIM_SLIST_INIT(&cred->gc_mc);

	return cred;
}

gss_name_t
_gss_cred_copy_name(OM_uint32 *minor_status, gss_cred_id_t credential, gss_const_OID mech)
{
	struct _gss_cred *cred = (struct _gss_cred *)credential;
	struct _gss_mechanism_cred *mc;
	struct _gss_name *name;
	OM_uint32 major_status;

	name = _gss_create_name(NULL, NULL);
	if (name == NULL)
		return NULL;

	HEIM_SLIST_FOREACH(mc, &cred->gc_mc, gmc_link) {
		struct _gss_mechanism_name *mn;
		gss_name_t mc_name;
		
		if (mech && !gss_oid_equal(mech, mc->gmc_mech_oid))
			continue;

		major_status = mc->gmc_mech->gm_inquire_cred(minor_status,
			mc->gmc_cred, &mc_name, NULL, NULL, NULL);
		if (major_status)
			continue;

		mn = malloc(sizeof(struct _gss_mechanism_name));
		if (!mn) {
			mc->gmc_mech->gm_release_name(minor_status, &mc_name);
			continue;
		}
		mn->gmn_mech = mc->gmc_mech;
		mn->gmn_mech_oid = mc->gmc_mech_oid;
		mn->gmn_name = mc_name;
		HEIM_SLIST_INSERT_HEAD(&name->gn_mn, mn, gmn_link);
	}
	if (HEIM_SLIST_EMPTY(&name->gn_mn)) {
		_gss_mg_release_name(name);
		return NULL;
	}

	return (gss_name_t)name;
}
