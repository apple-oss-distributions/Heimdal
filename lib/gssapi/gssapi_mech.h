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
 *	$FreeBSD: src/lib/libgssapi/mech_switch.h,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */

#ifndef GSSAPI_MECH_H
#define GSSAPI_MECH_H 1

#include <gssapi.h>

struct _gss_name;
struct _gss_cred;

typedef OM_uint32 _gss_acquire_cred_t
	      (OM_uint32 *,            /* minor_status */
	       const gss_name_t,       /* desired_name */
	       OM_uint32,              /* time_req */
	       const gss_OID_set,      /* desired_mechs */
	       gss_cred_usage_t,       /* cred_usage */
	       gss_cred_id_t *,        /* output_cred_handle */
	       gss_OID_set *,          /* actual_mechs */
	       OM_uint32 *             /* time_rec */
	      );

typedef OM_uint32 _gss_release_cred_t
	      (OM_uint32 *,            /* minor_status */
	       gss_cred_id_t *         /* cred_handle */
	      );

typedef OM_uint32 _gss_init_sec_context_t
	      (OM_uint32 *,            /* minor_status */
	       const gss_cred_id_t,    /* initiator_cred_handle */
	       gss_ctx_id_t *,         /* context_handle */
	       const gss_name_t,       /* target_name */
	       const gss_OID,          /* mech_type */
	       OM_uint32,              /* req_flags */
	       OM_uint32,              /* time_req */
	       const gss_channel_bindings_t,
				       /* input_chan_bindings */
	       const gss_buffer_t,     /* input_token */
	       gss_OID *,              /* actual_mech_type */
	       gss_buffer_t,           /* output_token */
	       OM_uint32 *,            /* ret_flags */
	       OM_uint32 *             /* time_rec */
	      );

typedef OM_uint32 _gss_accept_sec_context_t
	      (OM_uint32 *,            /* minor_status */
	       gss_ctx_id_t *,         /* context_handle */
	       const gss_cred_id_t,    /* acceptor_cred_handle */
	       const gss_buffer_t,     /* input_token_buffer */
	       const gss_channel_bindings_t,
				       /* input_chan_bindings */
	       gss_name_t *,           /* src_name */
	       gss_OID *,              /* mech_type */
	       gss_buffer_t,           /* output_token */
	       OM_uint32 *,            /* ret_flags */
	       OM_uint32 *,            /* time_rec */
	       gss_cred_id_t *         /* delegated_cred_handle */
	      );

typedef OM_uint32 _gss_process_context_token_t
	      (OM_uint32 *,            /* minor_status */
	       const gss_ctx_id_t,     /* context_handle */
	       const gss_buffer_t      /* token_buffer */
	      );

typedef OM_uint32 _gss_delete_sec_context_t
	      (OM_uint32 *,            /* minor_status */
	       gss_ctx_id_t *,         /* context_handle */
	       gss_buffer_t            /* output_token */
	      );

typedef OM_uint32 _gss_context_time_t
	      (OM_uint32 *,            /* minor_status */
	       const gss_ctx_id_t,     /* context_handle */
	       OM_uint32 *             /* time_rec */
	      );

typedef OM_uint32 _gss_get_mic_t
	      (OM_uint32 *,            /* minor_status */
	       const gss_ctx_id_t,     /* context_handle */
	       gss_qop_t,              /* qop_req */
	       const gss_buffer_t,     /* message_buffer */
	       gss_buffer_t            /* message_token */
	      );

typedef OM_uint32 _gss_verify_mic_t
	      (OM_uint32 *,            /* minor_status */
	       const gss_ctx_id_t,     /* context_handle */
	       const gss_buffer_t,     /* message_buffer */
	       const gss_buffer_t,     /* token_buffer */
	       gss_qop_t *             /* qop_state */
	      );

typedef OM_uint32 _gss_wrap_t
	      (OM_uint32 *,            /* minor_status */
	       const gss_ctx_id_t,     /* context_handle */
	       int,                    /* conf_req_flag */
	       gss_qop_t,              /* qop_req */
	       const gss_buffer_t,     /* input_message_buffer */
	       int *,                  /* conf_state */
	       gss_buffer_t            /* output_message_buffer */
	      );

typedef OM_uint32 _gss_unwrap_t
	      (OM_uint32 *,            /* minor_status */
	       const gss_ctx_id_t,     /* context_handle */
	       const gss_buffer_t,     /* input_message_buffer */
	       gss_buffer_t,           /* output_message_buffer */
	       int *,                  /* conf_state */
	       gss_qop_t *             /* qop_state */
	      );

typedef OM_uint32 _gss_display_status_t
	      (OM_uint32 *,            /* minor_status */
	       OM_uint32,              /* status_value */
	       int,                    /* status_type */
	       const gss_OID,          /* mech_type */
	       OM_uint32 *,            /* message_context */
	       gss_buffer_t            /* status_string */
	      );

typedef OM_uint32 _gss_indicate_mechs_t
	      (OM_uint32 *,            /* minor_status */
	       gss_OID_set *           /* mech_set */
	      );

typedef OM_uint32 _gss_compare_name_t
	      (OM_uint32 *,            /* minor_status */
	       const gss_name_t,       /* name1 */
	       const gss_name_t,       /* name2 */
	       int *                   /* name_equal */
	      );

typedef OM_uint32 _gss_display_name_t
	      (OM_uint32 *,            /* minor_status */
	       const gss_name_t,       /* input_name */
	       gss_buffer_t,           /* output_name_buffer */
	       gss_OID *               /* output_name_type */
	      );

typedef OM_uint32 _gss_import_name_t
	      (OM_uint32 *,            /* minor_status */
	       const gss_buffer_t,     /* input_name_buffer */
	       const gss_OID,          /* input_name_type */
	       gss_name_t *            /* output_name */
	      );

typedef OM_uint32 _gss_export_name_t
	      (OM_uint32 *,            /* minor_status */
	       const gss_name_t,       /* input_name */
	       gss_buffer_t            /* exported_name */
	      );

typedef OM_uint32 _gss_release_name_t
	      (OM_uint32 *,            /* minor_status */
	       gss_name_t *            /* input_name */
	      );

typedef OM_uint32 _gss_inquire_cred_t
	      (OM_uint32 *,            /* minor_status */
	       const gss_cred_id_t,    /* cred_handle */
	       gss_name_t *,           /* name */
	       OM_uint32 *,            /* lifetime */
	       gss_cred_usage_t *,     /* cred_usage */
	       gss_OID_set *           /* mechanisms */
	      );

typedef OM_uint32 _gss_inquire_context_t
	      (OM_uint32 *,            /* minor_status */
	       const gss_ctx_id_t,     /* context_handle */
	       gss_name_t *,           /* src_name */
	       gss_name_t *,           /* targ_name */
	       OM_uint32 *,            /* lifetime_rec */
	       gss_OID *,              /* mech_type */
	       OM_uint32 *,            /* ctx_flags */
	       int *,                  /* locally_initiated */
	       int *                   /* open */
	      );

typedef OM_uint32 _gss_wrap_size_limit_t
	      (OM_uint32 *,            /* minor_status */
	       const gss_ctx_id_t,     /* context_handle */
	       int,                    /* conf_req_flag */
	       gss_qop_t,              /* qop_req */
	       OM_uint32,              /* req_output_size */
	       OM_uint32 *             /* max_input_size */
	      );

typedef OM_uint32 _gss_add_cred_t (
	       OM_uint32 *,            /* minor_status */
	       const gss_cred_id_t,    /* input_cred_handle */
	       const gss_name_t,       /* desired_name */
	       const gss_OID,          /* desired_mech */
	       gss_cred_usage_t,       /* cred_usage */
	       OM_uint32,              /* initiator_time_req */
	       OM_uint32,              /* acceptor_time_req */
	       gss_cred_id_t *,        /* output_cred_handle */
	       gss_OID_set *,          /* actual_mechs */
	       OM_uint32 *,            /* initiator_time_rec */
	       OM_uint32 *             /* acceptor_time_rec */
	      );

typedef OM_uint32 _gss_inquire_cred_by_mech_t (
	       OM_uint32 *,            /* minor_status */
	       const gss_cred_id_t,    /* cred_handle */
	       const gss_OID,          /* mech_type */
	       gss_name_t *,           /* name */
	       OM_uint32 *,            /* initiator_lifetime */
	       OM_uint32 *,            /* acceptor_lifetime */
	       gss_cred_usage_t *      /* cred_usage */
	      );

typedef OM_uint32 _gss_export_sec_context_t (
	       OM_uint32 *,            /* minor_status */
	       gss_ctx_id_t *,         /* context_handle */
	       gss_buffer_t            /* interprocess_token */
	      );

typedef OM_uint32 _gss_import_sec_context_t (
	       OM_uint32 *,            /* minor_status */
	       const gss_buffer_t,     /* interprocess_token */
	       gss_ctx_id_t *          /* context_handle */
	      );

typedef OM_uint32 _gss_inquire_names_for_mech_t (
	       OM_uint32 *,            /* minor_status */
	       const gss_OID,          /* mechanism */
	       gss_OID_set *           /* name_types */
	      );

typedef OM_uint32 _gss_inquire_mechs_for_name_t (
	       OM_uint32 *,            /* minor_status */
	       const gss_name_t,       /* input_name */
	       gss_OID_set *           /* mech_types */
	      );

typedef OM_uint32 _gss_canonicalize_name_t (
	       OM_uint32 *,            /* minor_status */
	       const gss_name_t,       /* input_name */
	       const gss_OID,          /* mech_type */
	       gss_name_t *            /* output_name */
	      );

typedef OM_uint32 _gss_duplicate_name_t (
	       OM_uint32 *,            /* minor_status */
	       const gss_name_t,       /* src_name */
	       gss_name_t *            /* dest_name */
	      );

typedef OM_uint32 _gss_inquire_sec_context_by_oid (
	       OM_uint32 *minor_status,
	       const gss_ctx_id_t context_handle,
	       const gss_OID desired_object,
	       gss_buffer_set_t *data_set
	      );

typedef OM_uint32 _gss_inquire_cred_by_oid (
	       OM_uint32 *minor_status,
	       const gss_cred_id_t cred,
	       const gss_OID desired_object,
	       gss_buffer_set_t *data_set
	      );

typedef OM_uint32 _gss_set_sec_context_option (
	       OM_uint32 *minor_status,
	       gss_ctx_id_t *cred_handle,
	       const gss_OID desired_object,
	       const gss_buffer_t value
 	      );

typedef OM_uint32 _gss_set_cred_option (
	       OM_uint32 *minor_status,
	       gss_cred_id_t *cred_handle,
	       const gss_OID desired_object,
	       const gss_buffer_t value
 	      );


typedef OM_uint32 _gss_pseudo_random(
    	       OM_uint32 *minor_status,
	       gss_ctx_id_t context,
	       int prf_key,
	       const gss_buffer_t prf_in,
	       ssize_t desired_output_len,
	       gss_buffer_t prf_out
              );

typedef OM_uint32
_gss_wrap_iov_t(OM_uint32 *minor_status,
		gss_ctx_id_t  context_handle,
		int conf_req_flag,
		gss_qop_t qop_req,
		int * conf_state,
		gss_iov_buffer_desc *iov,
		int iov_count);

typedef OM_uint32
_gss_unwrap_iov_t(OM_uint32 *minor_status,
		  gss_ctx_id_t context_handle,
		  int *conf_state,
		  gss_qop_t *qop_state,
		  gss_iov_buffer_desc *iov,
		  int iov_count);

typedef OM_uint32
_gss_wrap_iov_length_t(OM_uint32 * minor_status,
		       gss_ctx_id_t context_handle,
		       int conf_req_flag,
		       gss_qop_t qop_req,
		       int *conf_state,
		       gss_iov_buffer_desc *iov,
		       int iov_count);

typedef OM_uint32
_gss_store_cred_t(OM_uint32         *minor_status,
		  gss_cred_id_t     input_cred_handle,
		  gss_cred_usage_t  cred_usage,
		  const gss_OID     desired_mech,
		  OM_uint32         overwrite_cred,
		  OM_uint32         default_cred,
		  gss_OID_set       *elements_stored,
		  gss_cred_usage_t  *cred_usage_stored);

typedef OM_uint32
_gss_export_cred_t(OM_uint32 *minor_status,
		   gss_cred_id_t cred_handle,
		   gss_buffer_t cred_token);

typedef OM_uint32
_gss_import_cred_t(OM_uint32 * minor_status,
		   gss_buffer_t cred_token,
		   gss_cred_id_t * cred_handle);

typedef OM_uint32
_gss_acquire_cred_ex_t(gss_status_id_t /* status */,
		       const gss_name_t /* desired_name */,
		       OM_uint32 /* flags */,
		       OM_uint32 /* time_req */,
		       gss_cred_usage_t /* cred_usage */,
		       gss_auth_identity_t /* identity */,
		       void * /* ctx */,
		       void (* /*complete */)(void *, OM_uint32, gss_status_id_t, gss_cred_id_t, OM_uint32));

typedef void
_gss_iter_creds_t(OM_uint32 /* flags */,
		  void * /* userctx */,
		  void (* /*cred_iter */ )(void *, gss_OID, gss_cred_id_t));

typedef OM_uint32
_gss_destroy_cred_t(OM_uint32 * /* minor_status */,
		    gss_cred_id_t */* cred */);

typedef OM_uint32
_gss_cred_hold_t(OM_uint32 * /* minor_status */,
		 gss_cred_id_t /* cred */);

typedef OM_uint32
_gss_cred_unhold_t(OM_uint32 * /* minor_status */,
		   gss_cred_id_t /* cred */);

typedef OM_uint32
_gss_cred_label_set_t(OM_uint32 * /* minor_status */,
		      gss_cred_id_t /* cred */,
		      const char * /* label */,
		      gss_buffer_t /* value */);

typedef OM_uint32
_gss_cred_label_get_t(OM_uint32 * /* minor_status */,
		      gss_cred_id_t /* cred */,
		      const char * /* label */,
		      gss_buffer_t /* value */);


typedef struct gss_mo_desc_struct gss_mo_desc;

struct gss_mo_desc_struct {
    gss_OID option;
    const char *name;
    void *ctx;
    int (*get)(gss_OID, gss_mo_desc *, gss_buffer_t);
    int (*set)(gss_OID, gss_mo_desc *, int, gss_buffer_t);
};


#define GMI_VERSION 4

/* gm_flags */
#define GM_USE_MG_CRED      	1	/* uses mech glue credentials */


typedef struct gssapi_mech_interface_desc {
	unsigned			gm_version;
	const char			*gm_name;
	gss_OID_desc			gm_mech_oid;
        unsigned			gm_flags;
	_gss_acquire_cred_t		*gm_acquire_cred;
	_gss_release_cred_t		*gm_release_cred;
	_gss_init_sec_context_t		*gm_init_sec_context;
	_gss_accept_sec_context_t	*gm_accept_sec_context;
	_gss_process_context_token_t	*gm_process_context_token;
	_gss_delete_sec_context_t	*gm_delete_sec_context;
	_gss_context_time_t		*gm_context_time;
	_gss_get_mic_t			*gm_get_mic;
	_gss_verify_mic_t		*gm_verify_mic;
	_gss_wrap_t			*gm_wrap;
	_gss_unwrap_t			*gm_unwrap;
	_gss_display_status_t		*gm_display_status;
	_gss_indicate_mechs_t		*gm_indicate_mechs;
	_gss_compare_name_t		*gm_compare_name;
	_gss_display_name_t		*gm_display_name;
	_gss_import_name_t		*gm_import_name;
	_gss_export_name_t		*gm_export_name;
	_gss_release_name_t		*gm_release_name;
	_gss_inquire_cred_t		*gm_inquire_cred;
	_gss_inquire_context_t		*gm_inquire_context;
	_gss_wrap_size_limit_t		*gm_wrap_size_limit;
	_gss_add_cred_t			*gm_add_cred;
	_gss_inquire_cred_by_mech_t	*gm_inquire_cred_by_mech;
	_gss_export_sec_context_t	*gm_export_sec_context;
	_gss_import_sec_context_t	*gm_import_sec_context;
	_gss_inquire_names_for_mech_t	*gm_inquire_names_for_mech;
	_gss_inquire_mechs_for_name_t	*gm_inquire_mechs_for_name;
	_gss_canonicalize_name_t	*gm_canonicalize_name;
	_gss_duplicate_name_t		*gm_duplicate_name;
	_gss_inquire_sec_context_by_oid	*gm_inquire_sec_context_by_oid;
	_gss_inquire_cred_by_oid	*gm_inquire_cred_by_oid;
	_gss_set_sec_context_option	*gm_set_sec_context_option;
	_gss_set_cred_option		*gm_set_cred_option;
	_gss_pseudo_random		*gm_pseudo_random;
	_gss_wrap_iov_t			*gm_wrap_iov;
	_gss_unwrap_iov_t		*gm_unwrap_iov;
	_gss_wrap_iov_length_t		*gm_wrap_iov_length;
	_gss_store_cred_t		*gm_store_cred;
	_gss_export_cred_t		*gm_export_cred;
	_gss_import_cred_t		*gm_import_cred;
	_gss_acquire_cred_ex_t		*gm_acquire_cred_ex;
	_gss_iter_creds_t		*gm_iter_creds;
	_gss_destroy_cred_t		*gm_destroy_cred;
	_gss_cred_hold_t		*gm_cred_hold;
	_gss_cred_unhold_t		*gm_cred_unhold;
	_gss_cred_label_get_t		*gm_cred_label_get;
	_gss_cred_label_set_t		*gm_cred_label_set;
        gss_mo_desc			*gm_mo;
        size_t				 gm_mo_num;
} gssapi_mech_interface_desc, *gssapi_mech_interface;

gssapi_mech_interface
__gss_get_mechanism(gss_OID /* oid */);

gssapi_mech_interface __gss_spnego_initialize(void);
gssapi_mech_interface __gss_krb5_initialize(void);
gssapi_mech_interface __gss_pku2u_initialize(void);
gssapi_mech_interface __gss_iakerb_initialize(void);
gssapi_mech_interface __gss_ntlm_initialize(void);
gssapi_mech_interface __gss_scram_initialize(void);
gssapi_mech_interface __gss_netlogon_initialize(void);

void		gss_mg_collect_error(gss_OID, OM_uint32, OM_uint32);
OM_uint32	gss_mg_export_name(OM_uint32 *, const gss_OID,
				   const void *, size_t, gss_buffer_t);
OM_uint32	gss_mg_set_error_string(gss_OID mech, OM_uint32 maj, OM_uint32 min, const char *fmt, ...)
    HEIMDAL_PRINTF_ATTRIBUTE((printf, 4, 5));

int		_gss_mg_log_level(int);
void		_gss_mg_log(int, const char *, ...)
    HEIMDAL_PRINTF_ATTRIBUTE((printf, 2, 3));
void		_gss_mg_log_name(int, struct _gss_name *, gss_OID, const char *, ...)
    HEIMDAL_PRINTF_ATTRIBUTE((printf, 4, 5));
void		_gss_mg_log_cred(int level, struct _gss_cred *name, const char *fmt, ...)
    HEIMDAL_PRINTF_ATTRIBUTE((printf, 3, 4));



struct _gss_name_type {
    gss_OID	gnt_name_type;
    OM_uint32	(*gnt_parse)(OM_uint32 *, const gss_OID, const gss_buffer_t,
			     const gss_OID, gss_name_t *);
};


OM_uint32
_gss_mech_import_name(OM_uint32 *, const gss_OID,
    struct _gss_name_type *, const gss_buffer_t, const gss_OID, gss_name_t *);

OM_uint32
_gss_mech_inquire_names_for_mech(OM_uint32 *,
    struct _gss_name_type *, gss_OID_set *);

gss_iov_buffer_desc *
_gss_mg_find_buffer(gss_iov_buffer_desc *, int, OM_uint32);

OM_uint32
_gss_mg_allocate_buffer(OM_uint32 *, gss_iov_buffer_desc *, size_t);

OM_uint32
gss_mg_validate_cb(OM_uint32 *, const gss_channel_bindings_t,
		   const uint8_t [16], gss_buffer_t);

OM_uint32 gss_mg_gen_cb(OM_uint32 *, const gss_channel_bindings_t,
			uint8_t [16], gss_buffer_t);

void _gss_mg_encode_le_uint32(uint32_t, uint8_t *);
void _gss_mg_decode_le_uint32(const void *, uint32_t *);
void _gss_mg_encode_be_uint32(uint32_t, uint8_t *);
void _gss_mg_decode_be_uint32(const void *, uint32_t *);

int _gss_mo_get_option_1(gss_OID, gss_mo_desc *, gss_buffer_t);
int _gss_mo_get_option_0(gss_OID, gss_mo_desc *, gss_buffer_t);

#endif /* GSSAPI_MECH_H */
