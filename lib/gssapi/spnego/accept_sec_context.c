/*
 * Copyright (c) 1997 - 2006 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * Portions Copyright (c) 2004 PADL Software Pty Ltd.
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

#include "spnego_locl.h"

static OM_uint32
send_reject (OM_uint32 *minor_status,
	     gss_buffer_t output_token)
{
    NegotiationToken nt;
    size_t size;

    nt.element = choice_NegotiationToken_negTokenResp;

    ALLOC(nt.u.negTokenResp.negResult, 1);
    if (nt.u.negTokenResp.negResult == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }
    *(nt.u.negTokenResp.negResult)  = reject;
    nt.u.negTokenResp.supportedMech = NULL;
    nt.u.negTokenResp.responseToken = NULL;
    nt.u.negTokenResp.mechListMIC   = NULL;

    ASN1_MALLOC_ENCODE(NegotiationToken,
		       output_token->value, output_token->length, &nt,
		       &size, *minor_status);
    free_NegotiationToken(&nt);
    if (*minor_status != 0)
	return GSS_S_FAILURE;

    return GSS_S_BAD_MECH;
}

static OM_uint32
acceptor_approved(void *userptr,
		  gss_name_t target_name, 
		  const gss_cred_id_t cred_handle,
		  gss_OID mech)
{
    OM_uint32 junk, ret;
    gss_OID_set oidset;

    if (cred_handle) {
	int present = 0;

	ret = gss_inquire_cred(&junk,
			       cred_handle,
			       NULL,
			       NULL,
			       NULL,
			       &oidset);
	if (ret != GSS_S_COMPLETE)
	    return ret;

	ret = gss_test_oid_set_member(&junk, mech, oidset, &present);
	gss_release_oid_set(&junk, &oidset);
	
	if (ret != GSS_S_COMPLETE || present == 0)
	    return GSS_S_FAILURE;

    } else {
	gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;

	if (target_name == GSS_C_NO_NAME)
	    return GSS_S_COMPLETE;
	
	gss_create_empty_oid_set(&junk, &oidset);
	gss_add_oid_set_member(&junk, mech, &oidset);

	ret = gss_acquire_cred(&junk, target_name, GSS_C_INDEFINITE, oidset,
			       GSS_C_ACCEPT, &cred, NULL, NULL);
	gss_release_oid_set(&junk, &oidset);
	if (ret != GSS_S_COMPLETE)
	    return ret;
	gss_release_cred(&junk, &cred);
    }

    return GSS_S_COMPLETE;
}

static OM_uint32
send_supported_mechs (OM_uint32 *minor_status,
		      gss_buffer_t output_token)
{
    NegotiationTokenWin nt;
    size_t buf_len = 0;
    gss_buffer_desc data;
    OM_uint32 ret;

    memset(&nt, 0, sizeof(nt));

    nt.element = choice_NegotiationTokenWin_negTokenInit;
    nt.u.negTokenInit.reqFlags = NULL;
    nt.u.negTokenInit.mechToken = NULL;
    nt.u.negTokenInit.negHints = NULL;

    ret = _gss_spnego_indicate_mechtypelist(minor_status, GSS_C_NO_NAME,
					    acceptor_approved, NULL, 1, NULL,
					    &nt.u.negTokenInit.mechTypes, NULL);
    if (ret != GSS_S_COMPLETE) {
	return ret;
    }

    ALLOC(nt.u.negTokenInit.negHints, 1);
    if (nt.u.negTokenInit.negHints == NULL) {
	*minor_status = ENOMEM;
	free_NegotiationTokenWin(&nt);
	return GSS_S_FAILURE;
    }

    ALLOC(nt.u.negTokenInit.negHints->hintName, 1);
    if (nt.u.negTokenInit.negHints->hintName == NULL) {
	*minor_status = ENOMEM;
	free_NegotiationTokenWin(&nt);
	return GSS_S_FAILURE;
    }

    *nt.u.negTokenInit.negHints->hintName = strdup("not_defined_in_RFC4178@please_ignore");
    nt.u.negTokenInit.negHints->hintAddress = NULL;

    ASN1_MALLOC_ENCODE(NegotiationTokenWin,
		       data.value, data.length, &nt, &buf_len, ret);
    free_NegotiationTokenWin(&nt);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }
    if (data.length != buf_len) {
	abort();
        UNREACHABLE(return GSS_S_FAILURE);
    }

    ret = gss_encapsulate_token(&data, GSS_SPNEGO_MECHANISM, output_token);

    free (data.value);

    if (ret != GSS_S_COMPLETE)
	return ret;

    *minor_status = 0;

    return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
send_accept (OM_uint32 *minor_status,
	     gssspnego_ctx context_handle,
	     gss_buffer_t mech_token,
	     int initial_response,
	     gss_buffer_t mech_buf,
	     gss_buffer_t output_token)
{
    NegotiationToken nt;
    OM_uint32 ret;
    gss_buffer_desc mech_mic_buf;
    size_t size;

    memset(&nt, 0, sizeof(nt));

    nt.element = choice_NegotiationToken_negTokenResp;

    ALLOC(nt.u.negTokenResp.negResult, 1);
    if (nt.u.negTokenResp.negResult == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    if (context_handle->flags.open) {
	if (mech_token != GSS_C_NO_BUFFER
	    && mech_token->length != 0
	    && mech_buf != GSS_C_NO_BUFFER)
	    *(nt.u.negTokenResp.negResult)  = accept_incomplete;
	else
	    *(nt.u.negTokenResp.negResult)  = accept_completed;
    } else {
	if (initial_response && context_handle->flags.require_mic)
	    *(nt.u.negTokenResp.negResult)  = request_mic;
	else
	    *(nt.u.negTokenResp.negResult)  = accept_incomplete;
    }

    if (initial_response) {
	ALLOC(nt.u.negTokenResp.supportedMech, 1);
	if (nt.u.negTokenResp.supportedMech == NULL) {
	    free_NegotiationToken(&nt);
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}

	ret = der_get_oid(context_handle->preferred_mech_type->elements,
			  context_handle->preferred_mech_type->length,
			  nt.u.negTokenResp.supportedMech,
			  NULL);
	if (ret) {
	    ret = GSS_S_FAILURE;
	    *minor_status = ENOMEM;
	    goto out;
	}
    } else {
	nt.u.negTokenResp.supportedMech = NULL;
    }

    if (mech_token != GSS_C_NO_BUFFER && mech_token->length != 0) {
	ALLOC(nt.u.negTokenResp.responseToken, 1);
	if (nt.u.negTokenResp.responseToken == NULL) {
	    free_NegotiationToken(&nt);
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}
	nt.u.negTokenResp.responseToken->length = mech_token->length;
	nt.u.negTokenResp.responseToken->data   = mech_token->value;
	mech_token->length = 0;
	mech_token->value  = NULL;
    } else {
	nt.u.negTokenResp.responseToken = NULL;
    }

    /* 
     * Can't send mechbuf until Lion is fixed to not send SIGN/SEAL,
     * and then when we get around to verifying, can't actually handle
     * gss_verify_mic(), only do this when its safe to omit though.
     */
    if (gss_oid_equal(context_handle->negotiated_mech_type, GSS_NTLM_MECHANISM)
	&& context_handle->flags.safe_omit)
	mech_buf = NULL;

    if (mech_buf != GSS_C_NO_BUFFER) {
	ret = gss_get_mic(minor_status,
			  context_handle->negotiated_ctx_id,
			  0,
			  mech_buf,
			  &mech_mic_buf);
	if (ret == GSS_S_COMPLETE) {
	    ALLOC(nt.u.negTokenResp.mechListMIC, 1);
	    if (nt.u.negTokenResp.mechListMIC == NULL) {
		gss_release_buffer(minor_status, &mech_mic_buf);
		ret = GSS_S_FAILURE;
		*minor_status = ENOMEM;
		goto out;
	    }
	    nt.u.negTokenResp.mechListMIC->length = mech_mic_buf.length;
	    nt.u.negTokenResp.mechListMIC->data   = mech_mic_buf.value;
	} else if (ret == GSS_S_UNAVAILABLE) {
	    nt.u.negTokenResp.mechListMIC = NULL;
	} else {
	    free_NegotiationToken(&nt);
	    return ret;
	}

    } else
	nt.u.negTokenResp.mechListMIC = NULL;

    ASN1_MALLOC_ENCODE(NegotiationToken,
		       output_token->value, output_token->length,
		       &nt, &size, ret);
    if (ret) {
	ret = GSS_S_FAILURE;
	*minor_status = ENOMEM;
	goto out;
    }

    /*
     * The response should not be encapsulated, because
     * it is a SubsequentContextToken (note though RFC 1964
     * specifies encapsulation for all _Kerberos_ tokens).
     */

    if (*(nt.u.negTokenResp.negResult) == accept_completed)
	ret = GSS_S_COMPLETE;
    else
	ret = GSS_S_CONTINUE_NEEDED;
 out:
    free_NegotiationToken(&nt);
    return ret;
}

/*
 *
 */

static OM_uint32
select_mech(OM_uint32 *minor_status, MechType *mechType, int verify_p,
	    gss_OID *mech_p)
{
    char mechbuf[64];
    size_t mech_len;
    gss_OID_desc oid;
    gss_OID oidp;
    gss_OID_set mechs;
    OM_uint32 ret, junk;
    unsigned int n;

    ret = der_put_oid ((unsigned char *)mechbuf + sizeof(mechbuf) - 1,
		       sizeof(mechbuf),
		       mechType,
		       &mech_len);
    if (ret) {
	return GSS_S_DEFECTIVE_TOKEN;
    }

    oid.length   = (OM_uint32)mech_len;
    oid.elements = mechbuf + sizeof(mechbuf) - mech_len;

    if (gss_oid_equal(&oid, GSS_SPNEGO_MECHANISM)) {
	return GSS_S_BAD_MECH;
    }

    *minor_status = 0;

    /* Translate broken MS Kebreros OID */
    if (gss_oid_equal(&oid, &_gss_spnego_mskrb_mechanism_oid_desc))
	oidp = &_gss_spnego_krb5_mechanism_oid_desc;
    else
	oidp = &oid;


    ret = gss_indicate_mechs(&junk, &mechs);
    if (ret) {
	return (ret);
    }

    for (n = 0; n < mechs->count; n++) {
	    if (gss_oid_equal(&mechs->elements[n], oidp))
		    break;
    }

    if (n == mechs->count) {
	    gss_release_oid_set(&junk, &mechs);
	    return GSS_S_BAD_MECH;
    }

    ret = gss_duplicate_oid(minor_status, &oid, mech_p);
    gss_release_oid_set(&junk, &mechs);
    if (ret)
	return ret;

    if (verify_p) {
	gss_name_t name = GSS_C_NO_NAME;
	gss_buffer_desc namebuf;
	char *str = NULL, *host, hostname[MAXHOSTNAMELEN];

	host = getenv("GSSAPI_SPNEGO_NAME");
	if (host == NULL || issuid()) {
	    int rv;
	    if (gethostname(hostname, sizeof(hostname)) != 0) {
		*minor_status = errno;
		return GSS_S_FAILURE;
	    }
	    rv = asprintf(&str, "host@%s", hostname);
	    if (rv < 0 || str == NULL) {
		*minor_status = ENOMEM;
		return GSS_S_FAILURE;
	    }
	    host = str;
	}

	namebuf.length = strlen(host);
	namebuf.value = host;

	ret = gss_import_name(minor_status, &namebuf,
			      GSS_C_NT_HOSTBASED_SERVICE, &name);
	if (str)
	    free(str);
	if (ret != GSS_S_COMPLETE)
	    return ret;

	ret = acceptor_approved(NULL, name, GSS_C_NO_CREDENTIAL, *mech_p);
	gss_release_name(&junk, &name);
    }

    return ret;
}


static OM_uint32
acceptor_complete(OM_uint32 * minor_status,
		  gssspnego_ctx ctx,
		  int *get_mic,
		  gss_buffer_t mech_input_token,
		  gss_buffer_t mech_output_token,
		  heim_octet_string *mic,
		  gss_buffer_t output_token)
{
    gss_buffer_desc buf;
    OM_uint32 ret;
    int verify_mic;

    buf.length = 0;
    buf.value = NULL;

    ctx->flags.require_mic = _gss_spnego_require_mechlist_mic(ctx);

    if (mic != NULL)
	ctx->flags.require_mic = 1;

    if (ctx->flags.open && ctx->flags.require_mic) {
	if (mech_input_token == GSS_C_NO_BUFFER) { /* Even/One */
	    verify_mic = 1;
	    *get_mic = 0;
	} else if (mech_output_token != GSS_C_NO_BUFFER &&
		   mech_output_token->length == 0) { /* Odd */
	    *get_mic = verify_mic = 1;
	} else { /* Even/One */
	    verify_mic = 0;
	    *get_mic = 1;
	}

	if (verify_mic && mic == NULL && ctx->flags.safe_omit) {
	    /*
	     * Peer is old and didn't send a mic while we expected
	     * one, but since it safe to omit, let do that
	     */
	} else if (verify_mic) {
	    ret = _gss_spnego_verify_mechtypes_mic(minor_status, ctx, mic);
	    if (ret) {
		if (*get_mic)
		    send_reject(minor_status, output_token);
		if (buf.value)
		    free(buf.value);
		return ret;
	    }
	}
    } else
	*get_mic = 0;

    return GSS_S_COMPLETE;
}


static OM_uint32 GSSAPI_CALLCONV
acceptor_start
	   (OM_uint32 * minor_status,
	    gss_ctx_id_t * context_handle,
	    const gss_cred_id_t acceptor_cred_handle,
	    const gss_buffer_t input_token_buffer,
	    const gss_channel_bindings_t input_chan_bindings,
	    gss_name_t * src_name,
	    gss_OID * mech_type,
	    gss_buffer_t output_token,
	    OM_uint32 * ret_flags,
	    OM_uint32 * time_rec,
	    gss_cred_id_t *delegated_cred_handle
	   )
{
    OM_uint32 ret, junk;
    NegotiationToken nt;
    size_t size;
    NegTokenInit *ni;
    gss_buffer_desc data;
    gss_buffer_t mech_input_token = GSS_C_NO_BUFFER;
    gss_buffer_desc mech_output_token;
    gss_OID preferred_mech_type = GSS_C_NO_OID;
    gssspnego_ctx ctx;
    int get_mic = 0;
    int first_ok = 0;

    memset(&nt, 0, sizeof(nt));

    mech_output_token.value = NULL;
    mech_output_token.length = 0;

    if (input_token_buffer->length == 0)
	return send_supported_mechs (minor_status, output_token);

    ret = _gss_spnego_alloc_sec_context(minor_status, context_handle);
    if (ret != GSS_S_COMPLETE)
	return ret;

    ctx = (gssspnego_ctx)*context_handle;

    HEIMDAL_MUTEX_lock(&ctx->ctx_id_mutex);

    /*
     * The GSS-API encapsulation is only present on the initial
     * context token (negTokenInit).
     */
    ret = gss_decapsulate_token (input_token_buffer,
				 GSS_SPNEGO_MECHANISM,
				 &data);
    if (ret)
	goto out;

    ret = decode_NegotiationToken(data.value, data.length, &nt, &size);
    gss_release_buffer(minor_status, &data);
    if (ret) {
	*minor_status = ret;
	ret = GSS_S_DEFECTIVE_TOKEN;
	goto out;
    }
    if (nt.element != choice_NegotiationToken_negTokenInit) {
	*minor_status = 0;
	ret = GSS_S_DEFECTIVE_TOKEN;
	goto out;
    }
    ni = &nt.u.negTokenInit;

    if (ni->mechTypes.len < 1) {
	*minor_status = 0;
	ret = GSS_S_DEFECTIVE_TOKEN;
	goto out;
    }

    {
	MechTypeList mt;
	int kret;

	mt.len = ni->mechTypes.len;
	mt.val = ni->mechTypes.val;

	ASN1_MALLOC_ENCODE(MechTypeList,
			   ctx->NegTokenInit_mech_types.value,
			   ctx->NegTokenInit_mech_types.length,
			   &mt, &size, kret);
	if (kret) {
	    *minor_status = kret;
	    ret = GSS_S_FAILURE;
	    goto out;
	}
	//XXX heim_assert(ctx->NegTokenInit_mech_types.length == size, "asn1 internal error");
    }

    /*
     * First we try the opportunistic token if we have support for it,
     * don't try to verify we have credential for the token,
     * gss_accept_sec_context() will (hopefully) tell us that.
     * If that failes,
     */

    ret = select_mech(minor_status,
		      &ni->mechTypes.val[0],
		      0,
		      &preferred_mech_type);

    if (ret == 0 && ni->mechToken != NULL) {
	gss_buffer_desc ibuf;

	ibuf.length = ni->mechToken->length;
	ibuf.value = ni->mechToken->data;
	mech_input_token = &ibuf;

	if (ctx->mech_src_name != GSS_C_NO_NAME)
	    gss_release_name(&junk, &ctx->mech_src_name);

	ret = gss_accept_sec_context(minor_status,
				     &ctx->negotiated_ctx_id,
				     acceptor_cred_handle,
				     mech_input_token,
				     input_chan_bindings,
				     &ctx->mech_src_name,
				     &ctx->negotiated_mech_type,
				     &mech_output_token,
				     &ctx->mech_flags,
				     &ctx->mech_time_rec,
				     delegated_cred_handle);

	if (ret == GSS_S_COMPLETE || ret == GSS_S_CONTINUE_NEEDED) {
	    ctx->preferred_mech_type = preferred_mech_type;
	    preferred_mech_type = GSS_C_NO_OID;
	    first_ok = 1;
	} else {
	    gss_mg_collect_error(preferred_mech_type, ret, *minor_status);
	    gss_release_oid(&junk, &preferred_mech_type);
	}

	if (ret == GSS_S_COMPLETE) {
	    ret = acceptor_complete(minor_status,
				    ctx,
				    &get_mic,
				    mech_input_token,
				    &mech_output_token,
				    ni->mechListMIC,
				    output_token);
	    if (ret != GSS_S_COMPLETE)
		goto out;
	    ctx->flags.open = 1;
	}
    } else {
	*minor_status = 0;
	return gss_mg_set_error_string(GSS_C_NO_OID, GSS_S_NO_CONTEXT,
				       *minor_status,
				       "SPNEGO acceptor didn't find a prefered mechanism");
    }

    /*
     * If opportunistic token failed, lets try the other mechs.
     */

    if (!first_ok && ni->mechToken != NULL) {
	size_t j;

	gss_release_oid(&junk, &preferred_mech_type);

	/* Call glue layer to find first mech we support */
	for (j = 1; j < ni->mechTypes.len; ++j) {
	    ret = select_mech(&junk,
			      &ni->mechTypes.val[j],
			      1,
			      &preferred_mech_type);
	    if (ret == 0)
		break;
	    gss_release_oid(&junk, &preferred_mech_type);
	}
	if (preferred_mech_type == GSS_C_NO_OID) {
	    goto out;
	}

	ctx->preferred_mech_type = preferred_mech_type;
	preferred_mech_type = GSS_C_NO_OID;
    }

    /*
     * The initial token always have a response
     */

    ret = send_accept (minor_status,
		       ctx,
		       &mech_output_token,
		       1,
		       get_mic ? &ctx->NegTokenInit_mech_types : NULL,
		       output_token);
    if (ret)
	goto out;

out:
    if(preferred_mech_type)
	gss_release_oid(&junk, &preferred_mech_type);

    if (mech_output_token.value != NULL)
	gss_release_buffer(&junk, &mech_output_token);
    free_NegotiationToken(&nt);


    if (ret == GSS_S_COMPLETE) {
	_gss_spnego_fixup_ntlm(ctx);

	if (src_name != NULL && ctx->mech_src_name != NULL) {
	    spnego_name name;

	    name = calloc(1, sizeof(*name));
	    if (name) {
		name->mech = ctx->mech_src_name;
		ctx->mech_src_name = NULL;
		*src_name = (gss_name_t)name;
	    }
	}
    }

    if (mech_type != NULL)
	*mech_type = ctx->negotiated_mech_type;
    if (ret_flags != NULL)
	*ret_flags = ctx->mech_flags;
    if (time_rec != NULL)
	*time_rec = ctx->mech_time_rec;

    if (ret == GSS_S_COMPLETE || ret == GSS_S_CONTINUE_NEEDED) {
	HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);
 	return ret;
    }

    _gss_spnego_internal_delete_sec_context(&junk, context_handle,
					    GSS_C_NO_BUFFER);

    return ret;
}


static OM_uint32 GSSAPI_CALLCONV
acceptor_continue
	   (OM_uint32 * minor_status,
	    gss_ctx_id_t * context_handle,
	    const gss_cred_id_t acceptor_cred_handle,
	    const gss_buffer_t input_token_buffer,
	    const gss_channel_bindings_t input_chan_bindings,
	    gss_name_t * src_name,
	    gss_OID * mech_type,
	    gss_buffer_t output_token,
	    OM_uint32 * ret_flags,
	    OM_uint32 * time_rec,
	    gss_cred_id_t *delegated_cred_handle
	   )
{
    OM_uint32 ret, ret2, minor, junk;
    NegotiationToken nt;
    size_t nt_len;
    NegTokenResp *na;
    unsigned int negResult = accept_incomplete;
    gss_buffer_t mech_input_token = GSS_C_NO_BUFFER;
    gss_buffer_t mech_output_token = GSS_C_NO_BUFFER;
    gssspnego_ctx ctx;

    ctx = (gssspnego_ctx)*context_handle;

    /*
     * The GSS-API encapsulation is only present on the initial
     * context token (negTokenInit).
     */

    ret = decode_NegotiationToken(input_token_buffer->value,
				  input_token_buffer->length,
				  &nt, &nt_len);
    if (ret) {
	*minor_status = ret;
	return GSS_S_DEFECTIVE_TOKEN;
    }
    if (nt.element != choice_NegotiationToken_negTokenResp) {
	*minor_status = 0;
	return GSS_S_DEFECTIVE_TOKEN;
    }
    na = &nt.u.negTokenResp;

    if (na->negResult != NULL) {
	negResult = *(na->negResult);
    }

    HEIMDAL_MUTEX_lock(&ctx->ctx_id_mutex);

    {
	gss_buffer_desc ibuf, obuf;
	int get_mic = 0;
	int require_response;

	if (na->responseToken != NULL) {
	    ibuf.length = na->responseToken->length;
	    ibuf.value = na->responseToken->data;
	    mech_input_token = &ibuf;
	} else {
	    ibuf.value = NULL;
	    ibuf.length = 0;
	}

	if (mech_input_token != GSS_C_NO_BUFFER) {

	    if (ctx->mech_src_name != GSS_C_NO_NAME)
		gss_release_name(&minor, &ctx->mech_src_name);

	    ret = gss_accept_sec_context(minor_status,
					 &ctx->negotiated_ctx_id,
					 acceptor_cred_handle,
					 mech_input_token,
					 input_chan_bindings,
					 &ctx->mech_src_name,
					 &ctx->negotiated_mech_type,
					 &obuf,
					 &ctx->mech_flags,
					 &ctx->mech_time_rec,
					 delegated_cred_handle);

	    if (ret == GSS_S_COMPLETE || ret == GSS_S_CONTINUE_NEEDED) {
		mech_output_token = &obuf;
	    }
	    if (ret != GSS_S_COMPLETE && ret != GSS_S_CONTINUE_NEEDED) {
		free_NegotiationToken(&nt);
		gss_mg_collect_error(ctx->negotiated_mech_type, ret, *minor_status);
		send_reject(&junk, output_token);
		HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);
		return ret;
	    }
	    if (ret == GSS_S_COMPLETE)
		ctx->flags.open = 1;
	} else
	    ret = GSS_S_COMPLETE;

	if (ret == GSS_S_COMPLETE)
	    ret = acceptor_complete(minor_status,
				    ctx,
				    &get_mic,
				    mech_input_token,
				    mech_output_token,
				    na->mechListMIC,
				    output_token);

	if (ctx->mech_flags & GSS_C_DCE_STYLE)
	    require_response = (negResult != accept_completed);
	else
	    require_response = 0;

	/*
	 * Check whether we need to send a result: there should be only
	 * one accept_completed response sent in the entire negotiation
	 */
	if ((mech_output_token != GSS_C_NO_BUFFER &&
	     mech_output_token->length != 0)
	    || (ctx->flags.open && negResult == accept_incomplete)
	    || require_response
	    || get_mic) {
	    ret2 = send_accept (minor_status,
				ctx,
				mech_output_token,
				0,
				get_mic ? &ctx->NegTokenInit_mech_types : NULL,
				output_token);
	    if (ret2)
		goto out;
	} else
	    ret2 = GSS_S_COMPLETE;

     out:
	if (ret2 != GSS_S_COMPLETE)
	    ret = ret2;
	if (mech_output_token != NULL)
	    gss_release_buffer(&minor, mech_output_token);
	free_NegotiationToken(&nt);
    }

    if (ret == GSS_S_COMPLETE) {

	_gss_spnego_fixup_ntlm(ctx);

	if (src_name != NULL && ctx->mech_src_name != NULL) {
	    spnego_name name;

	    name = calloc(1, sizeof(*name));
	    if (name) {
		name->mech = ctx->mech_src_name;
		ctx->mech_src_name = NULL;
		*src_name = (gss_name_t)name;
	    }
	}
    }

    if (mech_type != NULL)
	*mech_type = ctx->negotiated_mech_type;
    if (ret_flags != NULL)
	*ret_flags = ctx->mech_flags;
    if (time_rec != NULL)
	*time_rec = ctx->mech_time_rec;

    if (ret == GSS_S_COMPLETE || ret == GSS_S_CONTINUE_NEEDED) {
	HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);
 	return ret;
    }

    _gss_spnego_internal_delete_sec_context(&minor, context_handle,
				   GSS_C_NO_BUFFER);

    return ret;
}

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_accept_sec_context
	   (OM_uint32 * minor_status,
	    gss_ctx_id_t * context_handle,
	    const gss_cred_id_t acceptor_cred_handle,
	    const gss_buffer_t input_token_buffer,
	    const gss_channel_bindings_t input_chan_bindings,
	    gss_name_t * src_name,
	    gss_OID * mech_type,
	    gss_buffer_t output_token,
	    OM_uint32 * ret_flags,
	    OM_uint32 * time_rec,
	    gss_cred_id_t *delegated_cred_handle
	   )
{
    _gss_accept_sec_context_t *func;

    *minor_status = 0;

    output_token->length = 0;
    output_token->value  = NULL;

    if (src_name != NULL)
	*src_name = GSS_C_NO_NAME;
    if (mech_type != NULL)
	*mech_type = GSS_C_NO_OID;
    if (ret_flags != NULL)
	*ret_flags = 0;
    if (time_rec != NULL)
	*time_rec = 0;
    if (delegated_cred_handle != NULL)
	*delegated_cred_handle = GSS_C_NO_CREDENTIAL;


    if (*context_handle == GSS_C_NO_CONTEXT)
	func = acceptor_start;
    else
	func = acceptor_continue;


    return (*func)(minor_status, context_handle, acceptor_cred_handle,
		   input_token_buffer, input_chan_bindings,
		   src_name, mech_type, output_token, ret_flags,
		   time_rec, delegated_cred_handle);
}
