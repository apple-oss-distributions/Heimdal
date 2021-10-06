/*
 * Copyright (c) 2005, PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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

#include "kcm_locl.h"
#include <heimntlm.h>
#include <heimscram.h>

static void
kcm_drop_default_cache(krb5_context context, kcm_client *client, char *name);

int
kcm_is_same_session(kcm_client *client, uid_t uid, pid_t session)
{
    /*
     * Only same session
     * Let user access any credential regardless of session.
     * Deny otherwise.
     */

    if (use_uid_matching && client->uid != 0 && client->uid == uid) {
	kcm_log(1, "allowed (uid matching)");
	return 1;
    } else if (client->session == session) {
	kcm_log(1, "allowed (session matching)");
	return 1;
    }


    kcm_log(1, "denied");
    return 0;
}

static krb5_error_code
kcm_op_noop(krb5_context context,
	    kcm_client *client,
	    kcm_operation opcode,
	    krb5_storage *request,
	    krb5_storage *response)
{
    KCM_LOG_REQUEST(context, client, opcode);

    return 0;
}

/*
 * Request:
 *	NameZ
 * Response:
 *	NameZ
 *
 */
static krb5_error_code
kcm_op_get_name(krb5_context context,
		kcm_client *client,
		kcm_operation opcode,
		krb5_storage *request,
		krb5_storage *response)

{
    krb5_error_code ret;
    char *name = NULL;
    kcm_ccache ccache;

    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);

    ret = kcm_ccache_resolve_client(context, client, opcode,
				    name, &ccache);
    if (ret) {
	free(name);
	return ret;
    }

    ret = krb5_store_stringz(response, ccache->name);
    if (ret) {
	kcm_release_ccache(context, ccache);
	free(name);
	return ret;
    }

    free(name);
    kcm_release_ccache(context, ccache);
    return 0;
}

/*
 * Request:
 *
 * Response:
 *	NameZ
 */
static krb5_error_code
kcm_op_gen_new(krb5_context context,
	       kcm_client *client,
	       kcm_operation opcode,
	       krb5_storage *request,
	       krb5_storage *response)
{
    krb5_error_code ret;
    char *name;

    KCM_LOG_REQUEST(context, client, opcode);

    /* deprecated */

    name = kcm_ccache_nextid(client->pid, client->uid);
    if (name == NULL) {
	return KRB5_CC_NOMEM;
    }

    ret = krb5_store_stringz(response, name);
    free(name);

    return ret;
}

/*
 * Request:
 *	NameZ
 *	Principal
 *
 * Response:
 *
 */
static krb5_error_code
kcm_op_initialize(krb5_context context,
		  kcm_client *client,
		  kcm_operation opcode,
		  krb5_storage *request,
		  krb5_storage *response)
{
    kcm_ccache ccache;
    krb5_principal principal;
    krb5_error_code ret;
    char *name;
#if 0
    kcm_event event;
#endif

    KCM_LOG_REQUEST(context, client, opcode);

    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    ret = krb5_ret_principal(request, &principal);
    if (ret) {
	free(name);
	return ret;
    }

    ret = kcm_ccache_new_client(context, client, name, &ccache);
    if (ret) {
	free(name);
	krb5_free_principal(context, principal);
	return ret;
    }

    ccache->client = principal;

    free(name);

    kcm_release_ccache(context, ccache);

    kcm_data_changed = 1;

    return ret;
}

/*
 * Request:
 *	NameZ
 *
 * Response:
 *
 */
static krb5_error_code
kcm_op_destroy(krb5_context context,
	       kcm_client *client,
	       kcm_operation opcode,
	       krb5_storage *request,
	       krb5_storage *response)
{
    krb5_error_code ret;
    char *name;

    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);

    ret = kcm_ccache_destroy_client(context, client, name);
    if (ret == 0)
	kcm_drop_default_cache(context, client, name);

    free(name);

    kcm_data_changed = 1;

    return ret;
}

/*
 * Request:
 *	NameZ
 *	Creds
 *
 * Response:
 *
 */
static krb5_error_code
kcm_op_store(krb5_context context,
	     kcm_client *client,
	     kcm_operation opcode,
	     krb5_storage *request,
	     krb5_storage *response)
{
    krb5_creds creds;
    krb5_error_code ret;
    kcm_ccache ccache;
    char *name;

    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);

    ret = krb5_ret_creds(request, &creds);
    if (ret) {
	free(name);
	return ret;
    }

    ret = kcm_ccache_resolve_client(context, client, opcode,
				    name, &ccache);
    if (ret) {
	free(name);
	krb5_free_cred_contents(context, &creds);
	return ret;
    }

    ret = kcm_ccache_store_cred(context, ccache, &creds, 0);
    if (ret) {
	free(name);
	krb5_free_cred_contents(context, &creds);
	kcm_release_ccache(context, ccache);
	return ret;
    }

    if (creds.client && krb5_principal_is_root_krbtgt(context, creds.server))
	kcm_ccache_enqueue_default(context, ccache, &creds);

    free(name);
    kcm_release_ccache(context, ccache);

    kcm_data_changed = 1;

    return 0;
}

/*
 * Request:
 *	NameZ
 *	WhichFields
 *	MatchCreds
 *
 * Response:
 *	Creds
 *
 */
static krb5_error_code
kcm_op_retrieve(krb5_context context,
		kcm_client *client,
		kcm_operation opcode,
		krb5_storage *request,
		krb5_storage *response)
{
    uint32_t flags;
    krb5_creds mcreds;
    krb5_error_code ret;
    kcm_ccache ccache;
    char *name = NULL;
    krb5_creds *credp;

    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);

    ret = krb5_ret_uint32(request, &flags);
    if (ret) {
	goto out;
    }

    if (flags & KRB5_TC_MATCH_REFERRAL)
	flags |= KRB5_TC_DONT_MATCH_REALM;

    ret = krb5_ret_creds_tag(request, &mcreds);
    if (ret) {
	goto out;
    }

    if (disallow_getting_krbtgt &&
	mcreds.server->name.name_string.len == 2 &&
	strcmp(mcreds.server->name.name_string.val[0], KRB5_TGS_NAME) == 0)
    {
	krb5_free_cred_contents(context, &mcreds);
	ret = KRB5_FCC_PERM;
	goto out;
    }

    ret = kcm_ccache_resolve_client(context, client, opcode,
				    name, &ccache);
    if (ret) {
	krb5_free_cred_contents(context, &mcreds);
	goto out;
    }

    ret = kcm_ccache_retrieve_cred(context, ccache, flags,
				   &mcreds, &credp);
    if (ret == 0)
	ret = krb5_store_creds(response, credp);

    kcm_release_ccache(context, ccache);
    krb5_free_cred_contents(context, &mcreds);

 out:
    free(name);
    return ret;
}

/*
 * Request:
 *	NameZ
 *
 * Response:
 *	Principal
 */
static krb5_error_code
kcm_op_get_principal(krb5_context context,
		     kcm_client *client,
		     kcm_operation opcode,
		     krb5_storage *request,
		     krb5_storage *response)
{
    krb5_error_code ret;
    kcm_ccache ccache;
    char *name;

    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);

    ret = kcm_ccache_resolve_client(context, client, opcode,
				    name, &ccache);
    if (ret) {
	free(name);
	return ret;
    }

    if (ccache->client == NULL)
	ret = KRB5_CC_NOTFOUND;
    else
	ret = krb5_store_principal(response, ccache->client);

    free(name);
    kcm_release_ccache(context, ccache);

    return ret;
}

/*
 * Request:
 *	NameZ
 *
 * Response:
 *	UUIDs
 *
 */
static krb5_error_code
kcm_op_get_cred_uuid_list(krb5_context context,
			  kcm_client *client,
			  kcm_operation opcode,
			  krb5_storage *request,
			  krb5_storage *response)
{
    struct kcm_creds *creds;
    krb5_error_code ret;
    kcm_ccache ccache;
    char *name;

    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);

    ret = kcm_ccache_resolve_client(context, client, opcode,
				    name, &ccache);
    free(name);
    if (ret)
	return ret;

    for (creds = ccache->creds ; creds ; creds = creds->next) {
	ssize_t sret;
	sret = krb5_storage_write(response, &creds->uuid, sizeof(creds->uuid));
	if (sret != sizeof(creds->uuid)) {
	    ret = ENOMEM;
	    break;
	}
    }

    kcm_release_ccache(context, ccache);

    return ret;
}

/*
 * Request:
 *	NameZ
 *	Cursor
 *
 * Response:
 *	Creds
 */
static krb5_error_code
kcm_op_get_cred_by_uuid(krb5_context context,
			kcm_client *client,
			kcm_operation opcode,
			krb5_storage *request,
			krb5_storage *response)
{
    krb5_error_code ret;
    kcm_ccache ccache;
    char *name;
    struct kcm_creds *c;
    kcmuuid_t uuid;
    ssize_t sret;

    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);

    ret = kcm_ccache_resolve_client(context, client, opcode,
				    name, &ccache);
    free(name);
    if (ret)
	return ret;

    sret = krb5_storage_read(request, &uuid, sizeof(uuid));
    if (sret != sizeof(uuid)) {
	kcm_release_ccache(context, ccache);
	krb5_clear_error_message(context);
	return KRB5_CC_IO;
    }

    c = kcm_ccache_find_cred_uuid(context, ccache, uuid);
    if (c == NULL) {
	kcm_release_ccache(context, ccache);
	return KRB5_CC_END;
    }

    HEIMDAL_MUTEX_lock(&ccache->mutex);
    ret = krb5_store_creds(response, &c->cred);
    HEIMDAL_MUTEX_unlock(&ccache->mutex);

    kcm_release_ccache(context, ccache);

    return ret;
}

/*
 * Request:
 *	NameZ
 *	WhichFields
 *	MatchCreds
 *
 * Response:
 *
 */
static krb5_error_code
kcm_op_remove_cred(krb5_context context,
		   kcm_client *client,
		   kcm_operation opcode,
		   krb5_storage *request,
		   krb5_storage *response)
{
    uint32_t whichfields;
    krb5_creds mcreds;
    krb5_error_code ret;
    kcm_ccache ccache;
    char *name;

    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);

    ret = krb5_ret_uint32(request, &whichfields);
    if (ret) {
	free(name);
	return ret;
    }

    ret = krb5_ret_creds_tag(request, &mcreds);
    if (ret) {
	free(name);
	return ret;
    }

    ret = kcm_ccache_resolve_client(context, client, opcode,
				    name, &ccache);
    if (ret) {
	free(name);
	krb5_free_cred_contents(context, &mcreds);
	return ret;
    }

    ret = kcm_ccache_remove_cred(context, ccache, whichfields, &mcreds);

    /* XXX need to remove any events that match */

    free(name);
    krb5_free_cred_contents(context, &mcreds);
    kcm_release_ccache(context, ccache);

    kcm_data_changed = 1;

    return ret;
}

/*
 * Request:
 *	NameZ
 *	Flags
 *
 * Response:
 *
 */
static krb5_error_code
kcm_op_set_flags(krb5_context context,
		 kcm_client *client,
		 kcm_operation opcode,
		 krb5_storage *request,
		 krb5_storage *response)
{
    uint32_t flags;
    krb5_error_code ret;
    kcm_ccache ccache;
    char *name;

    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);

    ret = krb5_ret_uint32(request, &flags);
    if (ret) {
	free(name);
	return ret;
    }

    ret = kcm_ccache_resolve_client(context, client, opcode,
				    name, &ccache);
    if (ret) {
	free(name);
	return ret;
    }

    /* we don't really support any flags yet */
    free(name);
    kcm_release_ccache(context, ccache);

    return 0;
}

/*
 * Request:
 *	NameZ
 *	UID
 *	GID
 *
 * Response:
 *
 */
static krb5_error_code
kcm_op_chown(krb5_context context,
	     kcm_client *client,
	     kcm_operation opcode,
	     krb5_storage *request,
	     krb5_storage *response)
{
    uint32_t uid;
    uint32_t gid;
    krb5_error_code ret;
    kcm_ccache ccache;
    char *name;

    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);

    ret = krb5_ret_uint32(request, &uid);
    if (ret) {
	free(name);
	return ret;
    }

    ret = krb5_ret_uint32(request, &gid);
    if (ret) {
	free(name);
	return ret;
    }

    ret = kcm_ccache_resolve_client(context, client, opcode,
				    name, &ccache);
    if (ret) {
	free(name);
	return ret;
    }

    free(name);
    kcm_release_ccache(context, ccache);

    kcm_data_changed = 1;

    return ret;
}

/*
 * Request:
 *	NameZ
 *	Mode
 *
 * Response:
 *
 */
static krb5_error_code
kcm_op_chmod(krb5_context context,
	     kcm_client *client,
	     kcm_operation opcode,
	     krb5_storage *request,
	     krb5_storage *response)
{
    uint16_t mode;
    krb5_error_code ret;
    kcm_ccache ccache;
    char *name;

    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);

    ret = krb5_ret_uint16(request, &mode);
    if (ret) {
	free(name);
	return ret;
    }

    ret = kcm_ccache_resolve_client(context, client, opcode,
				    name, &ccache);
    if (ret) {
	free(name);
	return ret;
    }

    ret = kcm_chmod(context, client, ccache, mode);

    free(name);
    kcm_release_ccache(context, ccache);

    kcm_data_changed = 1;

    return ret;
}

/*
 * Protocol extensions for moving ticket acquisition responsibility
 * from client to KCM follow.
 */

/*
 * Request:
 *	NameZ
 *	clientPrincipal
 *	ServerPrincipalPresent
 *	ServerPrincipal OPTIONAL
 *	password
 *
 * Repsonse:
 *
 */
static krb5_error_code
kcm_op_get_initial_ticket(krb5_context context,
			  kcm_client *client,
			  kcm_operation opcode,
			  krb5_storage *request,
			  krb5_storage *response)
{
    char *name, *password;
    krb5_error_code ret;
    kcm_ccache ccache;
    int8_t not_tgt = 0;
    krb5_principal cprincipal = NULL;
    krb5_principal server = NULL;

    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);


    ret = krb5_ret_principal(request, &cprincipal);
    if (ret) {
	free(name);
	return ret;
    }

    ret = krb5_ret_int8(request, &not_tgt);
    if (ret) {
	free(name);
	return ret;
    }

    if (not_tgt) {
	ret = krb5_ret_principal(request, &server);
    } else {
	ret = krb5_make_principal(context,&server, cprincipal->realm,
				  KRB5_TGS_NAME, cprincipal->realm,
				  NULL);
    }
    if (ret) {
	krb5_free_principal(context, cprincipal);
	free(name);
	return ret;
    }

    ret = krb5_ret_stringz(request, &password);
    if (ret) {
	free(name);
	krb5_free_principal(context, cprincipal);
	if (server != NULL)
	    krb5_free_principal(context, server);
	return ret;
    }

    ret = kcm_ccache_resolve_client(context, client, opcode,
				    name, &ccache);
    if (ret == 0) {
	HEIMDAL_MUTEX_lock(&ccache->mutex);

	if (ccache->client)
	    krb5_free_principal(context, ccache->client);
	if (ccache->server)
	    krb5_free_principal(context, ccache->server);
	if (ccache->password) {
	    memset(ccache->password, 0, strlen(ccache->password));
	    free(ccache->password);
	}

	ccache->client = cprincipal;
	ccache->server = server;
	ccache->password = password;
    	ccache->flags |= KCM_FLAGS_USE_PASSWORD;
	ccache->renew_life = 3600 * 24 * 7; /* 1 week */

	kcm_ccache_update_acquire_status(kcm_context, ccache, KCM_STATUS_ACQUIRE_START, 0);

	HEIMDAL_MUTEX_unlock(&ccache->mutex);

	kcm_release_ccache(context, ccache);

	kcm_data_changed = 1;
    } else {
	krb5_free_principal(context, cprincipal);
	if (server)
	    krb5_free_principal(context, server);
	memset(password, 0, strlen(password));
	free(password);
    }


    free(name);

    return ret;
}

/*
 * Request:
 *	NameZ
 *	ServerPrincipal
 *	KDCFlags
 *	EncryptionType
 *
 * Repsonse:
 *
 */
static krb5_error_code
kcm_op_get_ticket(krb5_context context,
		  kcm_client *client,
		  kcm_operation opcode,
		  krb5_storage *request,
		  krb5_storage *response)
{
    krb5_error_code ret;
    kcm_ccache ccache;
    char *name;
    krb5_principal server = NULL;
    krb5_ccache_data ccdata;
    krb5_creds in, *out;
    krb5_kdc_flags flags;

    memset(&in, 0, sizeof(in));

    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);

    ret = krb5_ret_uint32(request, &flags.i);
    if (ret) {
	free(name);
	return ret;
    }

    ret = krb5_ret_int32(request, &in.session.keytype);
    if (ret) {
	free(name);
	return ret;
    }

    ret = krb5_ret_principal(request, &server);
    if (ret) {
	free(name);
	return ret;
    }

    ret = kcm_ccache_resolve_client(context, client, opcode,
				    name, &ccache);
    if (ret) {
	krb5_free_principal(context, server);
	free(name);
	return ret;
    }

    HEIMDAL_MUTEX_lock(&ccache->mutex);

    /* Fake up an internal ccache */
    kcm_internal_ccache(context, ccache, &ccdata);

    in.client = ccache->client;
    in.server = server;
    in.times.endtime = 0;

    /* glue cc layer will store creds */
    ret = krb5_get_credentials_with_flags(context, 0, flags,
					  &ccdata, &in, &out);

    HEIMDAL_MUTEX_unlock(&ccache->mutex);

    krb5_free_principal(context, server);

    if (ret == 0)
	krb5_free_cred_contents(context, out);

    kcm_release_ccache(context, ccache);
    free(name);

    kcm_data_changed = 1;

    return ret;
}

/*
 * Request:
 *	OldNameZ
 *	NewNameZ
 *
 * Repsonse:
 *
 */
static krb5_error_code
kcm_op_move_cache(krb5_context context,
		  kcm_client *client,
		  kcm_operation opcode,
		  krb5_storage *request,
		  krb5_storage *response)
{
    krb5_error_code ret;
    kcm_ccache oldid, newid;
    char *oldname, *newname;

    ret = krb5_ret_stringz(request, &oldname);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, oldname);

    ret = krb5_ret_stringz(request, &newname);
    if (ret) {
	free(oldname);
	return ret;
    }

    /* if we are renaming to ourself, done! */
    if (strcmp(newname, oldname) == 0) {
	free(oldname);
	free(newname);
	return 0;
    }

    ret = kcm_ccache_resolve_client(context, client, opcode, oldname, &oldid);
    if (ret) {
	free(oldname);
	free(newname);
	return ret;
    }

    /* Check if new credential cache exists, if not create one. */
    ret = kcm_ccache_resolve_client(context, client, opcode, newname, &newid);
    if (ret == KRB5_FCC_NOFILE)
	ret = kcm_ccache_new_client(context, client, newname, &newid);
    free(newname);

    if (ret) {
	free(oldname);
	kcm_release_ccache(context, oldid);
	return ret;
    }

    HEIMDAL_MUTEX_lock(&oldid->mutex);
    HEIMDAL_MUTEX_lock(&newid->mutex);

    /* move content */
    {
	struct kcm_ccache_data tmp;

#define MOVE(n,o,f) { tmp.f = n->f ; n->f = o->f; o->f = tmp.f; }

	MOVE(newid, oldid, flags);
	MOVE(newid, oldid, client);
	MOVE(newid, oldid, server);
	MOVE(newid, oldid, creds);
	MOVE(newid, oldid, tkt_life);
	MOVE(newid, oldid, renew_life);
	MOVE(newid, oldid, password);
	MOVE(newid, oldid, keytab);
	MOVE(newid, oldid, kdc_offset);
	MOVE(newid, oldid, expire);
#undef MOVE
    }

    kcm_update_renew_time(newid);

    if (newid->expire && (newid->flags & KCM_MASK_KEY_PRESENT) == 0 && time(NULL) < newid->expire)
	kcm_update_expire_time(newid, newid->expire);

    HEIMDAL_MUTEX_unlock(&oldid->mutex);
    HEIMDAL_MUTEX_unlock(&newid->mutex);

    kcm_release_ccache(context, oldid);
    kcm_release_ccache(context, newid);

    ret = kcm_ccache_destroy_client(context, client, oldname);
    if (ret == 0)
	kcm_drop_default_cache(context, client, oldname);

    free(oldname);

    kcm_data_changed = 1;

    return ret;
}

static krb5_error_code
kcm_op_get_cache_uuid_list(krb5_context context,
			   kcm_client *client,
			   kcm_operation opcode,
			   krb5_storage *request,
			   krb5_storage *response)
{
    KCM_LOG_REQUEST(context, client, opcode);

    return kcm_ccache_get_uuids(context, client, opcode, response);
}

static krb5_error_code
kcm_op_get_cache_principal_list(krb5_context context,
				kcm_client *client,
				kcm_operation opcode,
				krb5_storage *request,
				krb5_storage *response)
{
    KCM_LOG_REQUEST(context, client, opcode);

    return kcm_ccache_get_client_principals(context, client, opcode, response);
}

static krb5_error_code
kcm_op_get_cache_by_uuid(krb5_context context,
			 kcm_client *client,
			 kcm_operation opcode,
			 krb5_storage *request,
			 krb5_storage *response)
{
    krb5_error_code ret;
    kcmuuid_t uuid;
    ssize_t sret;
    kcm_ccache cache;

    KCM_LOG_REQUEST(context, client, opcode);

    sret = krb5_storage_read(request, &uuid, sizeof(uuid));
    if (sret != sizeof(uuid)) {
	krb5_clear_error_message(context);
	return KRB5_CC_IO;
    }

    ret = kcm_ccache_resolve_by_uuid(context, uuid, &cache);
    if (ret)
	return ret;

    ret = kcm_access(context, client, opcode, cache);
    if (ret)
	ret = KRB5_FCC_NOFILE;

    if (ret == 0)
	ret = krb5_store_stringz(response, cache->name);

    kcm_release_ccache(context, cache);

    return ret;
}

struct kcm_default_cache *default_caches;

static krb5_error_code
kcm_op_get_default_cache(krb5_context context,
			 kcm_client *client,
			 kcm_operation opcode,
			 krb5_storage *request,
			 krb5_storage *response)
{
    struct kcm_default_cache *c;
    krb5_error_code ret;
    const char *name = NULL;
    char *n = NULL;

    KCM_LOG_REQUEST(context, client, opcode);

    for (c = default_caches; c != NULL; c = c->next) {
	if (kcm_is_same_session(client, c->uid, c->session)) {
	    name = c->name;
	    break;
	}
    }
    if (name == NULL)
	name = n = kcm_ccache_first_name(client);

    if (name == NULL) {
	asprintf(&n, "%d", (int)client->uid);
	name = n;
    }
    if (name == NULL)
	return ENOMEM;
    ret = krb5_store_stringz(response, name);
    if (n)
	free(n);
    return ret;
}

static void
kcm_drop_default_cache(krb5_context context, kcm_client *client, char *name)
{
    struct kcm_default_cache **c;

    for (c = &default_caches; *c != NULL; c = &(*c)->next) {
	if (!kcm_is_same_session(client, (*c)->uid, (*c)->session))
	    continue;
	if (strcmp((*c)->name, name) == 0) {
	    struct kcm_default_cache *h = *c;
	    *c = (*c)->next;
	    free(h->name);
	    free(h);
	    break;
	}
    }
}

static krb5_error_code
kcm_op_set_default_cache(krb5_context context,
			 kcm_client *client,
			 kcm_operation opcode,
			 krb5_storage *request,
			 krb5_storage *response)
{
    struct kcm_default_cache *c;
    krb5_error_code ret;
    char *name;

    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);

    for (c = default_caches; c != NULL; c = c->next) {
	if (kcm_is_same_session(client, c->uid, c->session))
	    break;
    }
    if (c == NULL) {
	c = calloc(1, sizeof(*c));
	if (c == NULL) {
	    free(name);
	    return ENOMEM;
	}
	c->session = client->session;
	c->uid = client->uid;
	c->name = name;

	c->next = default_caches;
	default_caches = c;
    } else {
	free(c->name);
	c->name = name;
    }

    return 0;
}

static krb5_error_code
kcm_op_get_kdc_offset(krb5_context context,
		      kcm_client *client,
		      kcm_operation opcode,
		      krb5_storage *request,
		      krb5_storage *response)
{
    krb5_error_code ret;
    kcm_ccache ccache;
    char *name;

    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);

    ret = kcm_ccache_resolve_client(context, client, opcode, name, &ccache);
    free(name);
    if (ret)
	return ret;

    HEIMDAL_MUTEX_lock(&ccache->mutex);
    ret = krb5_store_int32(response, ccache->kdc_offset);
    HEIMDAL_MUTEX_unlock(&ccache->mutex);

    kcm_release_ccache(context, ccache);

    return ret;
}

static krb5_error_code
kcm_op_set_kdc_offset(krb5_context context,
		      kcm_client *client,
		      kcm_operation opcode,
		      krb5_storage *request,
		      krb5_storage *response)
{
    krb5_error_code ret;
    kcm_ccache ccache;
    int32_t offset;
    char *name;

    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);

    ret = krb5_ret_int32(request, &offset);
    if (ret) {
	free(name);
	return ret;
    }

    ret = kcm_ccache_resolve_client(context, client, opcode, name, &ccache);
    free(name);
    if (ret)
	return ret;

    HEIMDAL_MUTEX_lock(&ccache->mutex);
    ccache->kdc_offset = offset;
    HEIMDAL_MUTEX_unlock(&ccache->mutex);

    kcm_release_ccache(context, ccache);

    return ret;
}

static krb5_error_code
kcm_op_retain_kcred(krb5_context context,
		    kcm_client *client,
		    kcm_operation opcode,
		    krb5_storage *request,
		    krb5_storage *response)
{
    krb5_error_code ret;
    kcm_ccache ccache;
    char *name;
    
    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);

    ret = kcm_ccache_resolve_client(context, client, opcode, name, &ccache);
    if (ret) {
	free(name);
	return ret;
    }

    HEIMDAL_MUTEX_lock(&ccache->mutex);
    ccache->holdcount++;
    kcm_log(1, "retain_kcred: holdcount for %s is %ld", name, ccache->holdcount);
    HEIMDAL_MUTEX_unlock(&ccache->mutex);

    kcm_release_ccache(context, ccache);
    free(name);

    kcm_data_changed = 1;

    return 0;
}

static krb5_error_code
kcm_op_release_kcred(krb5_context context,
		     kcm_client *client,
		     kcm_operation opcode,
		     krb5_storage *request,
		     krb5_storage *response)
{
    krb5_error_code ret;
    kcm_ccache ccache;
    char *name;
    int destroy = 0;
    
    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;

    KCM_LOG_REQUEST_NAME(context, client, opcode, name);

    ret = kcm_ccache_resolve_client(context, client, opcode, name, &ccache);
    if (ret) {
	free(name);
	return ret;
    }

    HEIMDAL_MUTEX_lock(&ccache->mutex);
    ccache->holdcount--;
    if (ccache->holdcount < 1)
	destroy = 1;
    kcm_log(1, "release_kcred: holdcount for %s is %ld", name, ccache->holdcount);
    HEIMDAL_MUTEX_unlock(&ccache->mutex);

    kcm_release_ccache(context, ccache);

    if (destroy) {
	kcm_log(1, "holdcount for %s is zero, removing", name);

	ret = kcm_ccache_destroy_client(context, client, name);
	if (ret == 0)
	    kcm_drop_default_cache(context, client, name);
    }
    free(name);

    kcm_data_changed = 1;

    return 0;
}

static krb5_error_code
kcm_op_get_uuid(krb5_context context,
		kcm_client *client,
		kcm_operation opcode,
		krb5_storage *request,
		krb5_storage *response)
{
    krb5_error_code ret;
    kcm_ccache ccache;
    char *name;
    krb5_uuid uuid;
    
    ret = krb5_ret_stringz(request, &name);
    if (ret)
	return ret;
    
    KCM_LOG_REQUEST_NAME(context, client, opcode, name);
    
    ret = kcm_ccache_resolve_client(context, client, opcode, name, &ccache);
    free(name);
    if (ret) {
	return ret;
    }
    
    HEIMDAL_MUTEX_lock(&ccache->mutex);
    memcpy(uuid, ccache->uuid, sizeof(uuid));
    HEIMDAL_MUTEX_unlock(&ccache->mutex);
    
    kcm_release_ccache(context, ccache);

    (void)krb5_storage_write(response, uuid, sizeof(uuid));
    
    return 0;
}


/*
 *
 */

enum kcm_cred_type { KCM_NTLM_CRED, KCM_SCRAM_CRED };

struct kcm_ntlm_cred {
    enum kcm_cred_type type;
    kcmuuid_t uuid;
    char *user;
    char *domain;
#define nthash u.ntlm
    union {
	krb5_data ntlm;
	char *password;
    } u;
    uid_t uid;
    pid_t session;
    long refcount;
    heim_dict_t labels;
    struct kcm_ntlm_cred *next;
};

static struct kcm_ntlm_cred *ntlm_head;
static HEIMDAL_MUTEX cred_mutex = HEIMDAL_MUTEX_INITIALIZER;

#define CHECK(s) do { if ((s)) { goto out; } } while(0)

static krb5_error_code
kcm_unparse_digest_one(krb5_storage *inner, struct kcm_ntlm_cred *c)
{
    __block krb5_error_code ret;

    if (c->type == KCM_NTLM_CRED)
	CHECK(ret = krb5_store_stringz(inner, "ntlm-cache"));
    else if (c->type == KCM_SCRAM_CRED)
	CHECK(ret = krb5_store_stringz(inner, "scram-cache"));
    else
	heim_assert(false, "unknown cred type");

    CHECK(ret = krb5_store_uuid(inner, c->uuid));
    CHECK(ret = krb5_store_stringz(inner, c->user));
    if (c->domain) {
	CHECK(ret = krb5_store_uint8(inner, 1));
	CHECK(ret = krb5_store_stringz(inner, c->domain));
    } else {
	CHECK(ret = krb5_store_uint8(inner, 0));
    }

    if (c->type == KCM_NTLM_CRED)
	CHECK(ret = krb5_store_data(inner, c->u.ntlm));
    else if (c->type == KCM_SCRAM_CRED)
	CHECK(ret = krb5_store_stringz(inner, c->u.password));

    CHECK(ret = krb5_store_int32(inner, c->uid));
    CHECK(ret = krb5_store_int32(inner, c->session));
    CHECK(ret = krb5_store_uint32(inner, (uint32_t)c->refcount));

    heim_dict_iterate(c->labels, ^(heim_object_t key, heim_object_t value) {
	    heim_data_t d = value;
	    krb5_data data;
	    data.data = (void *)heim_data_get_bytes(d);
	    data.length = heim_data_get_length(d);
	    if (ret) return;
	    ret = krb5_store_uint8(inner, 1);
	    if (ret) return;
	    char *k = heim_string_copy_utf8(key);
	    ret = krb5_store_stringz(inner, k);
	    free(k);
	    if (ret) return;
	    ret = krb5_store_data(inner, data);
	    if (ret) return;
	});
    CHECK(ret);
    CHECK(ret = krb5_store_uint8(inner, 0));
 out:
    return ret;
}

krb5_error_code
kcm_unparse_digest_all(krb5_context context, krb5_storage *sp)
{
    struct kcm_ntlm_cred *c;
    krb5_error_code r = 0;

    HEIMDAL_MUTEX_lock(&cred_mutex);

    for (c = ntlm_head; r == 0 && c != NULL; c = c->next) {

	r = kcm_unparse_wrap(sp, "digest-cache", c->session, ^(krb5_storage *inner) {
		return kcm_unparse_digest_one(inner, c);
	    });
    }
    if (r)
	kcm_log(10, "failed to write digest-cred: %d", r);

    HEIMDAL_MUTEX_unlock(&cred_mutex);

    return r;
}

krb5_error_code
kcm_parse_digest_one(krb5_context context, krb5_storage *sp)
{
    struct kcm_ntlm_cred *c;
    krb5_error_code ret;
    char *type = NULL;
    uint32_t u32;
    int32_t s32;
    uint8_t u8;

    c = calloc(1, sizeof(*c));

    CHECK(ret = krb5_ret_stringz(sp, &type));

    if (strcmp(type, "ntlm-cache") == 0) {
	c->type = KCM_NTLM_CRED;
    } else if (strcmp(type, "scram-cache") == 0) {
	c->type = KCM_SCRAM_CRED;
    } else {
	free(type);
	return EINVAL;
    }

    CHECK(ret = krb5_ret_uuid(sp, c->uuid));
    CHECK(ret = krb5_ret_stringz(sp, &c->user));
    CHECK(ret = krb5_ret_uint8(sp, &u8));
    if (u8) {
	CHECK(ret = krb5_ret_stringz(sp, &c->domain));
    }

    if (c->type == KCM_NTLM_CRED)
	CHECK(ret = krb5_ret_data(sp, &c->u.ntlm));
    else if (c->type == KCM_SCRAM_CRED)
	CHECK(ret = krb5_ret_stringz(sp, &c->u.password));

    CHECK(ret = krb5_ret_int32(sp, &s32));
    c->uid = s32;
    CHECK(ret = krb5_ret_uint32(sp, &u32));
    c->session = u32;
    CHECK(ret = krb5_ret_uint32(sp, &u32));
    c->refcount = u32;

    c->labels = heim_dict_create(0);

    while (1) {
	krb5_data data;
	char *str;
	CHECK(ret = krb5_ret_uint8(sp, &u8));
	if (u8 == 0)
	    break;
	
	CHECK(ret = krb5_ret_stringz(sp, &str));
	heim_string_t s = heim_string_create(str);
	free(str);
	CHECK(ret = krb5_ret_data(sp, &data));
	heim_data_t d = heim_data_create(data.data, data.length);
	krb5_data_free(&data);
	heim_dict_set_value(c->labels, s, d);
	heim_release(s);
	heim_release(d);
    }

    c->next = ntlm_head;
    ntlm_head = c;

 out:
    free(type);
    if (ret) {
	kcm_log(10, "failed to read %s: %d", type, ret);
	/* free_cred(c); */
    }
    return ret;
}

static void
free_cred(struct kcm_ntlm_cred *cred)
{
    free(cred->user);
    free(cred->domain);

    if (cred->type == KCM_NTLM_CRED) {
	krb5_data_free(&cred->nthash);
    } else if (cred->type == KCM_SCRAM_CRED) {
	free(cred->u.password);
    } else {
	abort();
    }
    heim_release(cred->labels);
    free(cred);
}


static struct kcm_ntlm_cred *
find_ntlm_cred(enum kcm_cred_type type, const char *user, const char *domain, kcm_client *client)
{
    struct kcm_ntlm_cred *c;

    for (c = ntlm_head; c != NULL; c = c->next)
	if (c->type == type && (user[0] == '\0' || strcasecmp(user, c->user) == 0) && 
	    (domain == NULL || domain[0] == '\0' || strcasecmp(domain, c->domain) == 0) &&
	    kcm_is_same_session(client, c->uid, c->session))
	    return c;

    return NULL;
}

static struct kcm_ntlm_cred *
create_cred(enum kcm_cred_type type)
{
    struct kcm_ntlm_cred *cred;

    cred = calloc(1, sizeof(*cred));
    if (cred == NULL)
	return NULL;
	
    cred->type = type;
    cred->labels = heim_dict_create(0);
    cred->refcount = 1;

    krb5_generate_random_block(cred->uuid, sizeof(cred->uuid));

    return cred;
}

/*
 * name
 * domain
 * ntlm hash
 *
 * Reply:
 *   uuid
 */

static krb5_error_code
kcm_op_add_ntlm_cred(krb5_context context,
		     kcm_client *client,
		     kcm_operation opcode,
		     krb5_storage *request,
		     krb5_storage *response)
{
    struct kcm_ntlm_cred *cred, *c;
    krb5_error_code ret;

    cred = create_cred(KCM_NTLM_CRED);
    if (cred == NULL)
	return ENOMEM;
	
    ret = krb5_ret_stringz(request, &cred->user);
    if (ret)
	goto error;

    ret = krb5_ret_stringz(request, &cred->domain);
    if (ret)
	goto error;

    ret = krb5_ret_data(request, &cred->nthash);
    if (ret)
	goto error;

    HEIMDAL_MUTEX_lock(&cred_mutex);

    /* search for dups */
    c = find_ntlm_cred(KCM_NTLM_CRED, cred->user, cred->domain, client);
    if (c) {
	krb5_data hash = c->nthash;
	c->nthash = cred->nthash;
	cred->nthash = hash;
	free_cred(cred);
	cred = c;
    } else {
	cred->next = ntlm_head;
	ntlm_head = cred;
    }

    cred->uid = client->uid;
    cred->session = client->session;

    HEIMDAL_MUTEX_unlock(&cred_mutex);

    /* write response */
    (void)krb5_storage_write(response, &cred->uuid, sizeof(cred->uuid));

    kcm_data_changed = 1;

    return 0;

 error:
    free_cred(cred);

    return ret;
}

/*
 * { "HAVE_NTLM_CRED",		NULL },
 *
 * input:
 *  name
 *  domain
 */

static krb5_error_code
kcm_op_have_ntlm_cred(krb5_context context,
		     kcm_client *client,
		     kcm_operation opcode,
		     krb5_storage *request,
		     krb5_storage *response)
{
    struct kcm_ntlm_cred *c;
    char *user = NULL, *domain = NULL;
    krb5_error_code ret;

    ret = krb5_ret_stringz(request, &user);
    if (ret)
	goto error;

    ret = krb5_ret_stringz(request, &domain);
    if (ret)
	goto error;

    HEIMDAL_MUTEX_lock(&cred_mutex);

    c = find_ntlm_cred(KCM_NTLM_CRED, user, domain, client);
    if (c == NULL)
	ret = ENOENT;

    kcm_log(10, "ntlm checking for ntlm cred for %s@%s, -> %s",
	    user, domain, (c == NULL ? "no" : "yes"));

    if (c)
      (void)krb5_storage_write(response, &c->uuid, sizeof(c->uuid));

    HEIMDAL_MUTEX_unlock(&cred_mutex);

 error:
    free(user);
    if (domain)
	free(domain);

    return ret;
}

/*
 * { "DEL_CRED",		NULL },
 *
 * input:
 *  uuid
 */

static krb5_error_code
kcm_op_del_cred(krb5_context context,
		kcm_client *client,
		kcm_operation opcode,
		krb5_storage *request,
		krb5_storage *response)
{
    struct kcm_ntlm_cred **cp, *c;
    kcmuuid_t uuid;
    ssize_t sret;

    KCM_LOG_REQUEST(context, client, opcode);

    sret = krb5_storage_read(request, &uuid, sizeof(uuid));
    if (sret != sizeof(uuid)) {
	krb5_clear_error_message(context);
	return KRB5_CC_IO;
    }

    HEIMDAL_MUTEX_lock(&cred_mutex);

    for (cp = &ntlm_head; *cp != NULL; cp = &(*cp)->next) {
	if ((*cp)->type == KCM_NTLM_CRED &&
	    memcmp((*cp)->uuid, uuid, sizeof(uuid)) == 0 &&
	    kcm_is_same_session(client, (*cp)->uid, (*cp)->session))
	{
	    c = *cp;
	    *cp = c->next;

	    free_cred(c);
	    kcm_data_changed = 1;
	    break;
	}
    }

    HEIMDAL_MUTEX_unlock(&cred_mutex);

    return 0;
}

static struct ntlm_challenge {
    struct ntlm_challenge *next;
    uint8_t challenge[8];
    time_t ts;
} *ntlm_challenges = NULL;

static void
ntlm_delete_chain(struct ntlm_challenge *c)
{
    while (c) {
	struct ntlm_challenge *next = c->next;
	free(c);
	c = next;
    }
}

static int
ntlm_expiredp(struct ntlm_challenge *c, time_t now)
{
    return c->ts + heim_ntlm_time_skew < now;
}

static int
check_ntlm_challage(uint8_t chal[8])
{
    struct ntlm_challenge **q = &ntlm_challenges;
    time_t t = time(NULL);
    while (*q) {
	if (ntlm_expiredp(*q, t)) {
	    struct ntlm_challenge *c = *q;
	    *q = NULL;
	    ntlm_delete_chain(c);
	    return 0;
	}
	if (memcmp((*q)->challenge, chal, sizeof((*q)->challenge)) == 0)
	    return EAUTH;
	
	q = &(*q)->next;
    }
    return 0;
}

/*
 * { "SET_NTLM_CHALLAGE",	NULL }
 *
 * request:
 *   challage 8 byte
 */

static krb5_error_code
kcm_op_add_ntlm_challenge(krb5_context context,
			  kcm_client *client,
			  kcm_operation opcode,
			  krb5_storage *request,
			  krb5_storage *response)
{
    struct ntlm_challenge *c;
    ssize_t sret;

    KCM_LOG_REQUEST(context, client, opcode);

    c = malloc(sizeof(*c));
    if (c == NULL)
	return ENOMEM;

    sret = krb5_storage_read(request, c->challenge, sizeof(c->challenge));
    if (sret != sizeof(c->challenge)) {
	free(c);
	return KRB5_CC_IO;
    }

    c->ts = time(NULL);
    c->next = ntlm_challenges;
    ntlm_challenges = c;

    kcm_data_changed = 1;

    return 0;
}

/*
 * { "CHECK_NTLM_CHALLAGE",	NULL }
 *
 * request:
 *   challage 8 byte
 *
 * return:
 *   replay-detected 1 byte
 */

static krb5_error_code
kcm_op_check_ntlm_challenge(krb5_context context,
			    kcm_client *client,
			    kcm_operation opcode,
			    krb5_storage *request,
			    krb5_storage *response)
{
    uint8_t chal[8];
    ssize_t sret;
    int res;

    KCM_LOG_REQUEST(context, client, opcode);

    sret = krb5_storage_read(request, chal, sizeof(chal));
    if (sret != sizeof(chal))
	return KRB5_CC_IO;

    res = check_ntlm_challage(chal);
    if (res)
	kcm_log(10, "ntlm reflection attack detected");

    return krb5_store_uint8(response, !!res);
}


krb5_error_code
kcm_parse_ntlm_challenge_one(krb5_context context, krb5_storage *sp)
{
    struct ntlm_challenge *c, **q;
    krb5_error_code ret;
    int32_t ts;
    ssize_t sret;
    
    c = malloc(sizeof(*c));
    if (c == NULL)
	return ENOMEM;

    sret = krb5_storage_read(sp, c->challenge, sizeof(c->challenge));
    if (sret != sizeof(c->challenge)) {
	free(c);
	return KRB5_CC_IO;
    }

    ret = krb5_ret_int32(sp, &ts);
    if (ret) {
	free(c);
	return ret;
    }
    c->ts = ts;
    c->next = NULL;

    if (ntlm_expiredp(c, time(NULL))) {
	free(c);
    } else {
	/* find end and add c, XXX performance */
	for (q = &ntlm_challenges; *q != NULL; q = &(*q)->next)
	    ;
	*q = c;
    }

    return 0;
}

krb5_error_code
kcm_unparse_challenge_all(krb5_context context, krb5_storage *sp)
{
    struct ntlm_challenge *c;
    krb5_error_code r = 0;
    time_t now = time(NULL);

    for (c = ntlm_challenges; r == 0 && c != NULL; c = c->next) {

	if (ntlm_expiredp(c, now)) /* stop when they have expired */
	    break;

	r = kcm_unparse_wrap(sp, "ntlm-chal", 0, ^(krb5_storage *inner) {
		ssize_t sret;
		sret = krb5_storage_write(inner, c->challenge,
					  sizeof(c->challenge));
		if (sret != sizeof(c->challenge))
		    return EINVAL;
		return  krb5_store_int32(inner, (int32_t)c->ts);
	    });
    }
    if (r)
	kcm_log(10, "failed to write ntlm-chal: %d", r);
    return r;
}

#if ENABLE_NTLM

static dispatch_queue_t ntlmDomainQueue;
static char *ntlmDomain;

static void
update_ntlm(SCDynamicStoreRef store, CFArrayRef changedKeys, void *info)
{
    CFDictionaryRef settings;
    CFStringRef n;

    if (store == NULL)
	return;

    settings = (CFDictionaryRef)SCDynamicStoreCopyValue(store, CFSTR("com.apple.smb"));
    if (settings == NULL)
	return;

    n = CFDictionaryGetValue(settings, CFSTR("NetBIOSName"));
    if (n == NULL || CFGetTypeID(n) != CFStringGetTypeID())
	goto fin;

    if (ntlmDomain)
	free(ntlmDomain);
    ntlmDomain = rk_cfstring2cstring(n);
    strupr(ntlmDomain);

fin:
    CFRelease(settings);
    return;
}
#endif

static void
setup_ntlm_notification(void)
{
#if ENABLE_NTLM
    SCDynamicStoreRef store;

    store = SCDynamicStoreCreate(kCFAllocatorDefault, CFSTR("kcm-NetBIOSName"), update_ntlm, NULL);
    if (store == NULL)
	return;

    CFTypeRef key[] = {CFSTR("com.apple.smb")};
    CFArrayRef keys = CFArrayCreate(kCFAllocatorDefault, key, 1, NULL);
    SCDynamicStoreSetNotificationKeys(store, keys, NULL);
    CFRelease(keys);

    ntlmDomainQueue = dispatch_queue_create("kcm-NetBIOSName", NULL);
    if (ntlmDomainQueue == NULL) {
	CFRelease(store);
	errx(1, "dispatch_queue_create");
    }

    SCDynamicStoreSetDispatchQueue(store, ntlmDomainQueue);
    CFRelease(store);

    dispatch_sync(ntlmDomainQueue, ^{ update_ntlm(store, NULL, NULL); });
#endif
}

static char *
copy_netbios_name(void)
{
    __block char *domain = NULL;
    dispatch_sync(ntlmDomainQueue, ^{
	    if (ntlmDomain)
		domain = strdup(ntlmDomain);
	});
    if (domain == NULL)
	domain = strdup("workstation");
    return domain;
}

/*
 *
 */

static int
ntlm_domain_is_hostname(const char *name)
{
    return (name[0] == '\\');
}

/*
 * { "DO_NTLM_AUTH",		NULL },
 *
 * input:
 *  name:string
 *  domain:string
 *  type2:data
 *
 * reply:
 *  type3:data
 *  flags:int32
 *  session-key:data
 */

static krb5_error_code
kcm_op_do_ntlm(krb5_context context,
	       kcm_client *client,
	       kcm_operation opcode,
	       krb5_storage *request,
	       krb5_storage *response)
{
#ifdef ENABLE_NTLM
    struct kcm_ntlm_cred *c;
    struct ntlm_type2 type2;
    struct ntlm_type3 type3;
    char *user = NULL, *domain = NULL, *targetname = NULL;
    struct ntlm_buf ndata, sessionkey, tidata;
    krb5_data type2data, cb, type1data, tempdata;
    krb5_error_code ret;
    uint32_t type1flags, flags = 0;
    char flagname[256];
    size_t mic_offset = 0;
    static dispatch_once_t once;
    unsigned char ntlmv2[16];
    struct ntlm_targetinfo ti;
    static uint8_t zeros[16] = { 0 };

    KCM_LOG_REQUEST(context, client, opcode);

    dispatch_once(&once, ^{
	setup_ntlm_notification();
    });

    /*
     * Only do NTLMv2
     */

    krb5_data_zero(&cb);
    krb5_data_zero(&type1data);
    krb5_data_zero(&type2data);
    memset(&tidata, 0, sizeof(tidata));
    memset(&type2, 0, sizeof(type2));
    memset(&type3, 0, sizeof(type3));
    sessionkey.data = NULL;
    sessionkey.length = 0;
    
    HEIMDAL_MUTEX_lock(&cred_mutex);

    ret = krb5_ret_stringz(request, &user);
    if (ret)
	goto error;

    ret = krb5_ret_stringz(request, &domain);
    if (ret)
	goto error;

    kcm_log(10, "NTLM AUTH with cred %s\\%s", domain, user);

    c = find_ntlm_cred(KCM_NTLM_CRED, user, domain, client);
    if (c == NULL) {
	ret = EINVAL;
	goto error;
    }

    ret = krb5_ret_data(request, &type2data);
    if (ret)
	goto error;

    ret = krb5_ret_data(request, &cb);
    if (ret)
	goto error;

    ret = krb5_ret_data(request, &type1data);
    if (ret)
	goto error;

    ret = krb5_ret_stringz(request, &targetname);
    if (ret)
	goto error;

    ret = krb5_ret_uint32(request, &type1flags);
    if (ret)
	goto error;

    ndata.data = type2data.data;
    ndata.length = type2data.length;

    ret = heim_ntlm_decode_type2(&ndata, &type2);
    if (ret)
	goto error;

    if (!disable_ntlm_reflection_detection) {
	kcm_log(10, "checking for ntlm mirror attack");
	ret = check_ntlm_challage(type2.challenge);
	if (ret) {
	    kcm_log(0, "ntlm mirror attack detected");
	    goto error;
	}
    }

    /* if service name or case matching with domain, let pick the domain */
    if (ntlm_domain_is_hostname(c->domain) || strcasecmp(domain, type2.targetname) == 0) {
	free(domain);
	domain = type2.targetname;
	if (domain == NULL) {
	    ret = ENOMEM;
	    goto error;
	}
    } else {
	free(domain);
	domain = c->domain;
    }

    type3.username = c->user;
    type3.flags = type2.flags;
    /* only allow what we negotiated ourself */
    type3.flags &= type1flags;
    type3.targetname = domain;
    type3.ws = copy_netbios_name();
    if (type3.ws == NULL) {
	ret = ENOMEM;
	goto error;
    }

    /* verify infotarget */

    ret = heim_ntlm_decode_targetinfo(&type2.targetinfo, 1, &ti);
    if (ret)
	goto error;
	
    if (ti.avflags & NTLM_TI_AV_FLAG_GUEST)
	flags |= KCM_NTLM_FLAG_AV_GUEST;

    if (ti.channel_bindings.data)
	free(ti.channel_bindings.data);
    if (ti.targetname)
	free(ti.targetname);

    /* 
     * We are going to use MIC, tell server so it can reject the
     * authenticate if the mic is missing.
     */
    ti.avflags |= NTLM_TI_AV_FLAG_MIC;
    ti.targetname = targetname;

    if (cb.length == 0) {
	ti.channel_bindings.data = zeros;
	ti.channel_bindings.length = sizeof(zeros);
    } else {
	kcm_log(10, "using channelbindings of size %lu", (unsigned long)cb.length);
	ti.channel_bindings.data = cb.data;
	ti.channel_bindings.length = cb.length;
    }

    ret = heim_ntlm_encode_targetinfo(&ti, TRUE, &tidata);

    ti.targetname = NULL;
    ti.channel_bindings.data = NULL;
    ti.channel_bindings.length = 0;

    heim_ntlm_free_targetinfo(&ti);
    if (ret)
	goto error;

    /*
     * Prefer NTLM_NEG_EXTENDED_SESSION over NTLM_NEG_LM_KEY as
     * decribed in 2.2.2.5.
     */

    if (type3.flags & NTLM_NEG_NTLM2_SESSION)
	type3.flags &= ~NTLM_NEG_LM_KEY;

    if ((type3.flags & NTLM_NEG_LM_KEY) && 
	gss_mo_get(GSS_NTLM_MECHANISM, GSS_C_NTLM_SUPPORT_LM2, NULL)) {
	ret = heim_ntlm_calculate_lm2(c->nthash.data,
				      c->nthash.length,
				      type3.username,
				      domain,
				      type2.challenge,
				      ntlmv2,
				      &type3.lm);
    } else {
	type3.lm.data = malloc(24);
	if (type3.lm.data == NULL) {
	    ret = ENOMEM;
	} else {
	    type3.lm.length = 24;
	    memset(type3.lm.data, 0, type3.lm.length);
	}
    }
    if (ret)
	goto error;

    ret = heim_ntlm_calculate_ntlm2(c->nthash.data,
				    c->nthash.length,
				    type3.username,
				    domain,
				    type2.challenge,
				    &tidata,
				    ntlmv2,
				    &type3.ntlm);
    if (ret)
	goto error;
	
    if (type3.flags & NTLM_NEG_KEYEX) {
	ret = heim_ntlm_build_ntlm2_master(ntlmv2, sizeof(ntlmv2),
					   &type3.ntlm,
					   &sessionkey,
					   &type3.sessionkey);
    } else {
	ret = heim_ntlm_v2_base_session(ntlmv2, sizeof(ntlmv2), &type3.ntlm, &sessionkey);
    }

    if (ret)
	goto error;

    ret = heim_ntlm_encode_type3(&type3, &ndata, &mic_offset);
    if (ret)
	goto error;
    if (ndata.length < CC_MD5_DIGEST_LENGTH) {
	ret = EINVAL;
	goto error;
    }
	
    if (mic_offset && mic_offset < ndata.length - CC_MD5_DIGEST_LENGTH) {
	CCHmacContext mic;
	uint8_t *p = (uint8_t *)ndata.data + mic_offset;
	CCHmacInit(&mic, kCCHmacAlgMD5, sessionkey.data, sessionkey.length);
	CCHmacUpdate(&mic, type1data.data, type1data.length);
	CCHmacUpdate(&mic, type2data.data, type2data.length);
	CCHmacUpdate(&mic, ndata.data, ndata.length);
	CCHmacFinal(&mic, p);
    }

    tempdata.data = ndata.data;
    tempdata.length = ndata.length;
    ret = krb5_store_data(response, tempdata);
    heim_ntlm_free_buf(&ndata);

    if (ret) goto error;

    ret = krb5_store_int32(response, flags);
    if (ret) goto error;

    tempdata.data = sessionkey.data;
    tempdata.length = sessionkey.length;

    ret = krb5_store_data(response, tempdata);
    if (ret) goto error;
    ret = krb5_store_string(response, c->user);
    if (ret) goto error;
    ret = krb5_store_string(response, domain);
    if (ret) goto error;
    ret = krb5_store_uint32(response, type3.flags);
    if (ret) goto error;

    heim_ntlm_unparse_flags(type3.flags, flagname, sizeof(flagname));

    kcm_log(0, "ntlm v2 request processed for %s\\%s flags: %s",
	    domain, c->user, flagname);

 error:
    HEIMDAL_MUTEX_unlock(&cred_mutex);

    memset(ntlmv2, 0, sizeof(ntlmv2));
    krb5_data_free(&cb);
    krb5_data_free(&type1data);
    krb5_data_free(&type2data);
    if (type3.lm.data)
	free(type3.lm.data);
    if (type3.ntlm.data)
	free(type3.ntlm.data);
    if (type3.sessionkey.data)
	free(type3.sessionkey.data);
    if (type3.ws)
	free(type3.ws);
    if (targetname)
	free(targetname);
    heim_ntlm_free_type2(&type2);
    heim_ntlm_free_buf(&sessionkey);
    heim_ntlm_free_buf(&tidata);
    free(user);

    return ret;
#else
    return EINVAL;
#endif
}


/*
 * { "GET_NTLM_UUID_LIST",	NULL }
 *
 * reply:
 *   1 user domain uuid
 *   0 [ end of list ]
 */

static krb5_error_code
kcm_op_get_ntlm_user_list(krb5_context context,
			  kcm_client *client,
			  kcm_operation opcode,
			  krb5_storage *request,
			  krb5_storage *response)
{
    struct kcm_ntlm_cred *c;
    krb5_error_code ret;
    ssize_t sret;

    KCM_LOG_REQUEST(context, client, opcode);

    HEIMDAL_MUTEX_lock(&cred_mutex);

    for (c = ntlm_head; c != NULL; c = c->next) {
	if (c->type != KCM_NTLM_CRED || !kcm_is_same_session(client, c->uid, c->session))
	    continue;

	ret = krb5_store_uint32(response, 1);
	if (ret)
	    goto out;
	ret = krb5_store_stringz(response, c->user);
	if (ret)
	    goto out;
	ret = krb5_store_stringz(response, c->domain);
	if (ret)
	    goto out;
	sret = krb5_storage_write(response, c->uuid, sizeof(c->uuid));
	if (sret != sizeof(c->uuid)) {
	    ret = ENOMEM;
	    goto out;
	}
    }
    ret = krb5_store_uint32(response, 0);
 out:
    HEIMDAL_MUTEX_unlock(&cred_mutex);
    return ret;
}

static krb5_error_code
kcm_op_add_scram_cred(krb5_context context,
		     kcm_client *client,
		     kcm_operation opcode,
		     krb5_storage *request,
		     krb5_storage *response)
{
    struct kcm_ntlm_cred *cred, *c;
    krb5_error_code ret;

    KCM_LOG_REQUEST(context, client, opcode);

    cred = create_cred(KCM_SCRAM_CRED);
    if (cred == NULL)
	return ENOMEM;
	
    ret = krb5_ret_stringz(request, &cred->user);
    if (ret)
	goto error;

    ret = krb5_ret_stringz(request, &cred->u.password);
    if (ret)
	goto error;

    HEIMDAL_MUTEX_lock(&cred_mutex);

    /* search for dups */
    c = find_ntlm_cred(KCM_SCRAM_CRED, cred->user, NULL, client);
    if (c) {
	char *pw = c->u.password;
	c->u.password = cred->u.password;
	cred->u.password = pw;
	free_cred(cred);
	cred = c;
    } else {
	cred->next = ntlm_head;
	ntlm_head = cred;
    }

    cred->uid = client->uid;
    cred->session = client->session;

    /* write response */
    (void)krb5_storage_write(response, cred->uuid, sizeof(cred->uuid));


    HEIMDAL_MUTEX_unlock(&cred_mutex);
    kcm_data_changed = 1;

    return 0;

 error:
    free_cred(cred);

    return ret;
}

static krb5_error_code
kcm_op_have_scram_cred(krb5_context context,
		       kcm_client *client,
		       kcm_operation opcode,
		       krb5_storage *request,
		       krb5_storage *response)
{
    struct kcm_ntlm_cred *c;
    char *user = NULL;
    krb5_error_code ret;

    KCM_LOG_REQUEST(context, client, opcode);

    ret = krb5_ret_stringz(request, &user);
    if (ret)
	return ret;

    HEIMDAL_MUTEX_lock(&cred_mutex);

    c = find_ntlm_cred(KCM_SCRAM_CRED, user, NULL, client);
    if (c == NULL)
	ret = ENOENT;

    if (c)
      (void)krb5_storage_write(response, c->uuid, sizeof(c->uuid));

    HEIMDAL_MUTEX_unlock(&cred_mutex);

    free(user);

    return ret;
}

static krb5_error_code
kcm_op_del_scram_cred(krb5_context context,
		     kcm_client *client,
		     kcm_operation opcode,
		     krb5_storage *request,
		     krb5_storage *response)
{
    struct kcm_ntlm_cred **cp, *c;
    char *user = NULL;
    krb5_error_code ret;

    KCM_LOG_REQUEST(context, client, opcode);

    ret = krb5_ret_stringz(request, &user);
    if (ret)
	return ret;

    HEIMDAL_MUTEX_lock(&cred_mutex);

    for (cp = &ntlm_head; *cp != NULL; cp = &(*cp)->next) {
	if ((*cp)->type == KCM_SCRAM_CRED && strcasecmp(user, (*cp)->user) == 0 &&
	    kcm_is_same_session(client, (*cp)->uid, (*cp)->session))
	{
	    c = *cp;
	    *cp = c->next;

	    free_cred(c);
	    kcm_data_changed = 1;
	    break;
	}
    }

    HEIMDAL_MUTEX_unlock(&cred_mutex);

    free(user);

    return ret;
}

/*
 * IN:
 *   clientname: stringz
 *   iterations: uint32_t
 *   salt: krb5_data
 *   c1: krb5_data
 *   s1: krb5_data
 *   c2noproof: krb5_data
 */

static krb5_error_code
kcm_op_do_scram(krb5_context context,
		kcm_client *client,
		kcm_operation opcode,
		krb5_storage *request,
		krb5_storage *response)
{
#ifdef ENABLE_SCRAM
    heim_scram_data proof, server, client_key, stored, server_key, session_key;
    heim_scram_method method = HEIM_SCRAM_DIGEST_SHA1;
    krb5_data salt, c1, s1, c2noproof;
    struct kcm_ntlm_cred *c;
    krb5_error_code ret;
    uint32_t iterations;
    unsigned char *p, *q;
    char *user = NULL;
    size_t n;

    KCM_LOG_REQUEST(context, client, opcode);

    memset(&proof, 0, sizeof(proof));
    memset(&server, 0, sizeof(server));
    memset(&client_key, 0, sizeof(client_key));
    memset(&stored, 0, sizeof(stored));
    memset(&server_key, 0, sizeof(server_key));
    memset(&session_key, 0, sizeof(session_key));
    krb5_data_zero(&salt);
    krb5_data_zero(&c1);
    krb5_data_zero(&s1);
    krb5_data_zero(&c2noproof);
	
    HEIMDAL_MUTEX_lock(&cred_mutex);

    ret = krb5_ret_stringz(request, &user);
    if (ret)
	goto out;
    
    c = find_ntlm_cred(KCM_SCRAM_CRED, user, NULL, client);
    if (c == NULL) {
	ret = ENOENT;
	goto out;
    }

    ret = krb5_ret_uint32(request, &iterations);
    if (ret)
	goto out;
    
    ret = krb5_ret_data(request, &salt);
    if (ret)
	goto out;
    
    ret = krb5_ret_data(request, &c1);
    if (ret)
	goto out;
    
    ret = krb5_ret_data(request, &s1);
    if (ret)
	goto out;
    
    ret = krb5_ret_data(request, &c2noproof);
    if (ret)
	goto out;
    
    ret = heim_scram_stored_key(method, c->u.password, iterations, &salt,
				&client_key, &stored, &server_key);
    if (ret)
	goto out;
    
    ret = heim_scram_generate(method, &stored, &server_key,
			      &c1, &s1, &c2noproof, &proof, &server);
    if (ret)
	goto out;
    
    
    ret = heim_scram_session_key(method, &stored, &client_key,
				 &c1, &s1, &c2noproof,
				 &session_key);
    if (ret)
	goto out;
    
    /*
     * Now client_key XOR proof
     */
    p = proof.data;
    q = client_key.data;
    
    for (n = 0 ; n < client_key.length; n++)
	p[n] = p[n] ^ q[n];
    
    ret = krb5_store_data(response, proof);
    if (ret)
	goto out;
    ret = krb5_store_data(response, server);
    if (ret)
	goto out;
    ret = krb5_store_data(response, session_key);
    if (ret)
	goto out;
    
out:
    HEIMDAL_MUTEX_unlock(&cred_mutex);
    if (user)
	free(user);

    krb5_data_free(&salt);
    krb5_data_free(&c1);
    krb5_data_free(&s1);
    krb5_data_free(&c2noproof);

    heim_scram_data_free(&proof);
    heim_scram_data_free(&server);
    heim_scram_data_free(&client_key);
    heim_scram_data_free(&stored);
    heim_scram_data_free(&server_key);
    heim_scram_data_free(&session_key);
	
    return ret;
#else
    return EINVAL;
#endif
}

static krb5_error_code
kcm_op_get_scram_user_list(krb5_context context,
			   kcm_client *client,
			   kcm_operation opcode,
			   krb5_storage *request,
			   krb5_storage *response)
{
    struct kcm_ntlm_cred *c;
    krb5_error_code ret;
    ssize_t sret;

    KCM_LOG_REQUEST(context, client, opcode);

    for (c = ntlm_head; c != NULL; c = c->next) {
	if (c->type != KCM_SCRAM_CRED || !kcm_is_same_session(client, c->uid, c->session))
	    continue;

	ret = krb5_store_uint32(response, 1);
	if (ret)
	    return ret;
	ret = krb5_store_stringz(response, c->user);
	if (ret)
	    return ret;

	sret = krb5_storage_write(response, c->uuid, sizeof(c->uuid));
	if (sret != sizeof(c->uuid)) {
	    ret = ENOMEM;
	    return ret;
	}
    }
    return krb5_store_uint32(response, 0);
}

static krb5_error_code
kcm_op_retain_cred(krb5_context context,
		   kcm_client *client,
		   kcm_operation opcode,
		   krb5_storage *request,
		   krb5_storage *response)
{
    struct kcm_ntlm_cred *c;
    kcmuuid_t uuid;
    ssize_t sret;
    
    KCM_LOG_REQUEST(context, client, opcode);

    sret = krb5_storage_read(request, &uuid, sizeof(uuid));
    if (sret != sizeof(uuid)) {
	krb5_clear_error_message(context);
	return KRB5_CC_IO;
    }
    
    for (c = ntlm_head; c != NULL; c = c->next) {
	if (!kcm_is_same_session(client, c->uid, c->session))
	    continue;
	
	if (memcmp(uuid, c->uuid, sizeof(c->uuid)) == 0) {
	    c->refcount++;
	    kcm_data_changed = 1;
	    return 0;
	}
    }

    return 0;
}

static krb5_error_code
kcm_op_release_cred(krb5_context context,
		    kcm_client *client,
		    kcm_operation opcode,
		    krb5_storage *request,
		    krb5_storage *response)
{
    struct kcm_ntlm_cred **cp;
    kcmuuid_t uuid;
    ssize_t sret;
    
    KCM_LOG_REQUEST(context, client, opcode);

    sret = krb5_storage_read(request, &uuid, sizeof(uuid));
    if (sret != sizeof(uuid)) {
	krb5_clear_error_message(context);
	return KRB5_CC_IO;
    }
    
    for (cp = &ntlm_head; *cp != NULL; cp = &(*cp)->next) {
	struct kcm_ntlm_cred *c = *cp;

	if (!kcm_is_same_session(client, c->uid, c->session))
	    continue;
	
	if (memcmp(uuid, c->uuid, sizeof(uuid)) == 0) {
	    c->refcount--;
	    if (c->refcount < 1) {
		*cp = c->next;
		free_cred(c);
	    }
	    kcm_data_changed = 1;
	    return 0;
	}
    }
    return 0;
}

static krb5_error_code
kcm_op_cred_label_get(krb5_context context,
		      kcm_client *client,
		      kcm_operation opcode,
		      krb5_storage *request,
		      krb5_storage *response)
{
    struct kcm_ntlm_cred *c;
    krb5_error_code ret;
    heim_string_t s;
    char *label;
    kcmuuid_t uuid;
    ssize_t sret;
    
    KCM_LOG_REQUEST(context, client, opcode);

    sret = krb5_storage_read(request, &uuid, sizeof(uuid));
    if (sret != sizeof(uuid)) {
	krb5_clear_error_message(context);
	return KRB5_CC_IO;
    }
    
    ret = krb5_ret_stringz(request, &label);
    if (ret)
	return ret;

    s = heim_string_create(label);
    free(label);

    for (c = ntlm_head; c != NULL; c = c->next) {
	if (!kcm_is_same_session(client, c->uid, c->session))
	    continue;
	
	if (memcmp(uuid, c->uuid, sizeof(c->uuid)) == 0) {
	    heim_data_t d;

	    d = heim_dict_copy_value(c->labels, s);
	    if (d) {
		krb5_data data;
		data.length = heim_data_get_length(d);
		data.data = (void *)heim_data_get_bytes(d);

		krb5_store_data(response, data);
		heim_release(d);
		break;
	    }
	}
    }
    heim_release(s);

    if (c == NULL)
	return ENOENT;

    return 0;
}

static krb5_error_code
kcm_op_cred_label_set(krb5_context context,
		      kcm_client *client,
		      kcm_operation opcode,
		      krb5_storage *request,
		      krb5_storage *response)
{
    struct kcm_ntlm_cred *c;
    kcmuuid_t uuid;
    krb5_data data;
    char *label = NULL;
    ssize_t sret;
    
    KCM_LOG_REQUEST(context, client, opcode);

    sret = krb5_storage_read(request, &uuid, sizeof(uuid));
    if (sret != sizeof(uuid)) {
	krb5_clear_error_message(context);
	return KRB5_CC_IO;
    }
    
    krb5_ret_stringz(request, &label);
    krb5_ret_data(request, &data);

    HEIMDAL_MUTEX_lock(&cred_mutex);

    for (c = ntlm_head; c != NULL; c = c->next) {

	if (!kcm_is_same_session(client, c->uid, c->session))
	    continue;
	
	if (memcmp(uuid, c->uuid, sizeof(uuid)) == 0) {
	    heim_string_t s;

	    s = heim_string_create(label);

	    if (data.length) {
		heim_data_t d;

		d = heim_data_create(data.data, data.length);

		heim_dict_set_value(c->labels, s, d);
		heim_release(d);
	    } else {
		heim_dict_delete_key(c->labels, s);
	    }
	    kcm_data_changed = 1;
	    heim_release(s);
	    break;
	}
    }

    HEIMDAL_MUTEX_unlock(&cred_mutex);

    krb5_data_free(&data);
    free(label);

    if (c == NULL)
	return ENOENT;

    return 0;
}



/*
 *
 */

static struct kcm_op kcm_ops[] = {
    { "NOOP", 			kcm_op_noop },
    { "GET_NAME",		kcm_op_get_name },
    { "RESOLVE",		kcm_op_noop },
    { "GEN_NEW", 		kcm_op_gen_new },
    { "INITIALIZE",		kcm_op_initialize },
    { "DESTROY",		kcm_op_destroy },
    { "STORE",			kcm_op_store },
    { "RETRIEVE",		kcm_op_retrieve },
    { "GET_PRINCIPAL",		kcm_op_get_principal },
    { "GET_CRED_UUID_LIST",	kcm_op_get_cred_uuid_list },
    { "GET_CRED_BY_UUID",	kcm_op_get_cred_by_uuid },
    { "REMOVE_CRED",		kcm_op_remove_cred },
    { "SET_FLAGS",		kcm_op_set_flags },
    { "CHOWN",			kcm_op_chown },
    { "CHMOD",			kcm_op_chmod },
    { "GET_INITIAL_TICKET",	kcm_op_get_initial_ticket },
    { "GET_TICKET",		kcm_op_get_ticket },
    { "MOVE_CACHE",		kcm_op_move_cache },
    { "GET_CACHE_UUID_LIST",	kcm_op_get_cache_uuid_list },
    { "GET_CACHE_BY_UUID",	kcm_op_get_cache_by_uuid },
    { "GET_DEFAULT_CACHE",      kcm_op_get_default_cache },
    { "SET_DEFAULT_CACHE",      kcm_op_set_default_cache },
    { "GET_KDC_OFFSET",      	kcm_op_get_kdc_offset },
    { "SET_KDC_OFFSET",      	kcm_op_set_kdc_offset },
    { "RETAIN_KCRED",		kcm_op_retain_kcred },
    { "RELEASE_KCRED",		kcm_op_release_kcred },
    { "GET_UUID",		kcm_op_get_uuid },
    { "ADD_NTLM_CRED",		kcm_op_add_ntlm_cred },
    { "HAVE_NTLM_CRED",		kcm_op_have_ntlm_cred },
    { "SET_NTLM_CHALLEGE",	kcm_op_add_ntlm_challenge },
    { "DO_NTLM_AUTH",		kcm_op_do_ntlm },
    { "SET_NTLM_USER_LIST",	kcm_op_get_ntlm_user_list },
    { "ADD_SCRAM_CRED",		kcm_op_add_scram_cred },
    { "HAVE_SCRAM_CRED",	kcm_op_have_scram_cred },
    { "DEL_SCRAM_CRED",		kcm_op_del_scram_cred },
    { "DO_SCRAM_AUTH",		kcm_op_do_scram },
    { "GET_SCRAM_USER_LIST",	kcm_op_get_scram_user_list },
    { "DEL_CRED",		kcm_op_del_cred },
    { "RETAIN_CRED",		kcm_op_retain_cred },
    { "RELEASE_CRED",		kcm_op_release_cred },
    { "CRED_LABEL_GET",		kcm_op_cred_label_get },
    { "CRED_LABEL_SET",		kcm_op_cred_label_set },
    { "CHECK_NTLM_CHALLAGE",	kcm_op_check_ntlm_challenge },
    { "GET_CACHE_PRINCIPAL_LIST",kcm_op_get_cache_principal_list },
};


const char *
kcm_op2string(kcm_operation opcode)
{
    if (opcode >= sizeof(kcm_ops)/sizeof(kcm_ops[0]))
	return "Unknown operation";

    return kcm_ops[opcode].name;
}

krb5_error_code
kcm_dispatch(krb5_context context,
	     kcm_client *client,
	     krb5_data *req_data,
	     krb5_data *resp_data)
{
    krb5_error_code ret;
    kcm_method method;
    krb5_storage *req_sp = NULL;
    krb5_storage *resp_sp = NULL;
    uint16_t opcode;

    resp_sp = krb5_storage_emem();
    if (resp_sp == NULL) {
	return ENOMEM;
    }

    if (client->pid == -1) {
	kcm_log(0, "Client had invalid process number");
	ret = KRB5_FCC_INTERNAL;
	goto out;
    }

    req_sp = krb5_storage_from_data(req_data);
    if (req_sp == NULL) {
	kcm_log(0, "Process %d: failed to initialize storage from data",
		client->pid);
	ret = KRB5_CC_IO;
	goto out;
    }

    ret = krb5_ret_uint16(req_sp, &opcode);
    if (ret) {
	kcm_log(0, "Process %d: didn't send a message", client->pid);
	goto out;
    }

    if (opcode >= sizeof(kcm_ops)/sizeof(kcm_ops[0])) {
	kcm_log(0, "Process %d: invalid operation code %d",
		client->pid, opcode);
	ret = KRB5_FCC_INTERNAL;
	goto out;
    }
    method = kcm_ops[opcode].method;
    if (method == NULL) {
	kcm_log(0, "Process %d: operation code %s not implemented",
		client->pid, kcm_op2string(opcode));
	ret = KRB5_FCC_INTERNAL;
	goto out;
    }

    /* seek past place for status code */
    krb5_storage_seek(resp_sp, 4, SEEK_SET);

    ret = (*method)(context, client, opcode, req_sp, resp_sp);

out:
    if (req_sp != NULL) {
	krb5_storage_free(req_sp);
    }

    krb5_storage_seek(resp_sp, 0, SEEK_SET);
    krb5_store_int32(resp_sp, ret);

    ret = krb5_storage_to_data(resp_sp, resp_data);
    krb5_storage_free(resp_sp);

    return ret;
}

