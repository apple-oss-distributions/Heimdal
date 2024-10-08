/*
 * Copyright (c) 2003 - 2007 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
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
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#include "krb5_locl.h"
#include <getarg.h>
#include <err.h>
#import "heimcred.h"
#import "common.h"

#ifdef __APPLE_PRIVATE__
#include <dispatch/dispatch.h>
#endif

static int debug_flag	= 0;
static int version_flag = 0;
static int help_flag	= 0;

#ifdef KRB5_USE_PATH_TOKENS
#define TEST_CC_NAME "%{TEMP}/krb5-cc-test-foo"
#else
#define TEST_CC_NAME "/tmp/krb5-cc-test-foo"
#endif

static void
test_default_name(krb5_context context)
{
    krb5_error_code ret;
    const char *p, *test_cc_name = TEST_CC_NAME;
    char *p1, *p2, *p3;

    p = krb5_cc_default_name(context);
    if (p == NULL)
	krb5_errx (context, 1, "krb5_cc_default_name 1 failed");
    p1 = estrdup(p);

    ret = krb5_cc_set_default_name(context, NULL);
    if (ret)
	krb5_errx (context, 1, "krb5_cc_set_default_name failed");

    p = krb5_cc_default_name(context);
    if (p == NULL)
	krb5_errx (context, 1, "krb5_cc_default_name 2 failed");
    p2 = estrdup(p);

    if (strcmp(p1, p2) != 0)
	krb5_errx (context, 1, "krb5_cc_default_name no longer same");

    ret = krb5_cc_set_default_name(context, test_cc_name);
    if (ret)
	krb5_errx (context, 1, "krb5_cc_set_default_name 1 failed");

    p = krb5_cc_default_name(context);
    if (p == NULL)
	krb5_errx (context, 1, "krb5_cc_default_name 2 failed");
    p3 = estrdup(p);

#ifndef KRB5_USE_PATH_TOKENS
    /* If we are using path tokens, we don't expect the p3 and
       test_cc_name to match since p3 is going to have expanded
       tokens. */
    if (strcmp(p3, test_cc_name) != 0)
	krb5_errx (context, 1, "krb5_cc_set_default_name 1 failed");
#endif

    free(p1);
    free(p2);
    free(p3);
}

/*
 * Check that a closed cc still keeps it data and that it's no longer
 * there when it's destroyed.
 */

static void
test_mcache(krb5_context context)
{
    krb5_error_code ret;
    krb5_ccache id, id2;
    const char *nc, *tc;
    char *c;
    krb5_principal p, p2;

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_new_unique(context, krb5_cc_type_memory, NULL, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique");

    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    nc = krb5_cc_get_name(context, id);
    if (nc == NULL)
	krb5_errx(context, 1, "krb5_cc_get_name");

    tc = krb5_cc_get_type(context, id);
    if (tc == NULL)
	krb5_errx(context, 1, "krb5_cc_get_name");

    if (asprintf(&c, "%s:%s", tc, nc) < 0 || c == NULL)
	errx(1, "malloc");

    krb5_cc_close(context, id);

    ret = krb5_cc_resolve(context, c, &id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve");

    ret = krb5_cc_get_principal(context, id2, &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal");

    if (krb5_principal_compare(context, p, p2) == FALSE)
	krb5_errx(context, 1, "p != p2");

    krb5_cc_destroy(context, id2);
    krb5_free_principal(context, p);
    krb5_free_principal(context, p2);

    ret = krb5_cc_resolve(context, c, &id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve");

    ret = krb5_cc_get_principal(context, id2, &p2);
    if (ret == 0)
	krb5_errx(context, 1, "krb5_cc_get_principal");

    krb5_cc_destroy(context, id2);
    free(c);
}

/*
 * Test that init works on a destroyed cc.
 */

static void
test_init_vs_destroy(krb5_context context, const char *type)
{
    krb5_error_code ret;
    krb5_ccache id, id2;
    krb5_principal p, p2;
    char *n = NULL;

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_new_unique(context, type, NULL, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique: %s", type);

    if (asprintf(&n, "%s:%s",
		 krb5_cc_get_type(context, id),
		 krb5_cc_get_name(context, id)) < 0 || n == NULL)
	errx(1, "malloc");


    ret = krb5_cc_resolve(context, n, &id2);
    free(n);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve");

    krb5_cc_destroy(context, id);

    ret = krb5_cc_initialize(context, id2, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    ret = krb5_cc_get_principal(context, id2, &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal");

    krb5_cc_destroy(context, id2);
    krb5_free_principal(context, p);
    krb5_free_principal(context, p2);
}

static void
test_default_init(krb5_context context, const char *type)
{
    krb5_error_code ret;
    krb5_ccache id, id2;
    krb5_principal p, p2;

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_default(context, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_default: %s", type);

    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    ret = krb5_cc_get_principal(context, id, &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal");

    krb5_cc_destroy(context, id);

    //run it again to make sure it starts empty
    ret = krb5_cc_default(context, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_default 2: %s", type);

    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize 2");

    krb5_cc_destroy(context, id);

    ret = krb5_cc_new_unique(context, type, NULL, &id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique: %s", type);

    ret = krb5_cc_initialize(context, id2, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    krb5_free_principal(context, p2);
    ret = krb5_cc_get_principal(context, id2, &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal");

    krb5_cc_destroy(context, id2);
    krb5_free_principal(context, p);
    krb5_free_principal(context, p2);
}

static void
test_default_iter(void)
{
    krb5_cc_cursor cursor;
    krb5_error_code ret;
    krb5_ccache id;
    krb5_creds creds;
    krb5_context context;

    if (krb5_init_context (&context) != 0)
	errx(1, "krb5_context");

    ret = krb5_cc_default (context, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_default");

    ret = krb5_cc_start_seq_get(context, id, &cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_start_seq_get");

    while ((ret = krb5_cc_next_cred(context, id, &cursor, &creds)) == 0){
	char *principal;

	krb5_unparse_name(context, creds.server, &principal);
	printf("principal: %s\\n", principal);
	free(principal);
	krb5_free_cred_contents (context, &creds);
    }
    ret = krb5_cc_end_seq_get(context, id, &cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_end_seq_get");

    krb5_cc_close(context, id);

    krb5_free_context(context);
}

static void
test_cache_entry_iter(krb5_context context, const char *type)
{
    krb5_error_code ret;
    krb5_ccache id;
    krb5_principal p;
    krb5_creds cred;

    /*
     test iterating on a default cache that is empty

     test again after entries are added to it

     */

    //create a new empty cache
    ret = krb5_cc_new_unique(context, type, NULL, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_gen_new: %s", type);

    //set the default cache name
    ret = krb5_cc_set_default_name(context, krb5_cc_get_name(context, id));

    //iterate on the cache
    test_default_iter();

    //add entries to the cache
    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    /* */
    memset(&cred, 0, sizeof(cred));
    cred.times.endtime = time(NULL) + 10;
    ret = krb5_parse_name(context, "krbtgt/SU.SE@SU.SE", &cred.server);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");
    ret = krb5_parse_name(context, "lha@SU.SE", &cred.client);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_store_cred(context, id, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred");

    //iterate again
    test_default_iter();

    ret = krb5_cc_remove_cred(context, id, 0, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_remove_cred");

    ret = krb5_cc_destroy(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy");

    ret = krb5_cc_set_default_name(context, NULL);
    if (ret)
	krb5_errx (context, 1, "krb5_cc_set_default_name failed");

    krb5_free_principal(context, p);
    krb5_free_cred_contents(context, &cred);
}

static void
test_cache_remove(krb5_context context, const char *type)
{
    krb5_error_code ret;
    krb5_ccache id;
    krb5_principal p;
    krb5_creds cred;

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_new_unique(context, type, NULL, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_gen_new: %s", type);

    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    /* */
    memset(&cred, 0, sizeof(cred));
    cred.times.endtime = time(NULL) + 10;
    ret = krb5_parse_name(context, "krbtgt/SU.SE@SU.SE", &cred.server);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");
    ret = krb5_parse_name(context, "lha@SU.SE", &cred.client);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_store_cred(context, id, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred");

    ret = krb5_cc_remove_cred(context, id, 0, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_remove_cred");

    ret = krb5_cc_destroy(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy");

    krb5_free_principal(context, p);
    krb5_free_cred_contents(context, &cred);
}

static void
test_mcc_default(void)
{
    krb5_context context;
    krb5_error_code ret;
    krb5_ccache id, id2;
    int i;

    for (i = 0; i < 10; i++) {

	ret = krb5_init_context(&context);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_init_context");

	ret = krb5_cc_set_default_name(context, "MEMORY:foo");
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_set_default_name");

	ret = krb5_cc_default(context, &id);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_default");

	ret = krb5_cc_default(context, &id2);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_default");

	ret = krb5_cc_close(context, id);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_close");

	ret = krb5_cc_close(context, id2);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_close");

	krb5_free_context(context);
    }
}

struct {
    char *str;
    int fail;
    char *res;
} cc_names[] = {
#ifdef KRB5_USE_PATH_TOKENS
#ifdef _WIN32
    { "%{APPDATA}", 0 },
    { "%{COMMON_APPDATA}", 0},
    { "%{LOCAL_APPDATA}", 0},
    { "%{SYSTEM}", 0},
    { "%{WINDOWS}", 0},
    { "%{USERCONFIG}", 0},
    { "%{COMMONCONFIG}", 0},
#else
    { "%{LIBDIR}", 0},
    { "%{BINDIR}", 0},
    { "%{LIBEXEC}", 0},
    { "%{SBINDIR}", 0},
#endif
#if __APPLE__
    { "%{ApplicationResources}", 1}, /* only for .app's */
#endif
    { "%{USERID}", 0},
    { "%{uid}", 0},
    { "%{TEMP}", 0},
#endif
    { "foo", 0, "foo" },
    { "foo%}", 0, "foo%}" },
    { "%{uid}", 0 },
    { "foo%{null}", 0, "foo" },
    { "foo%{null}bar", 0, "foobar" },
    { "%{", 1 },
    { "%{foo %{", 1 },
    { "%{{", 1 },
    { "%{{}", 1 },
    { "%{nulll}", 1 },
    { "%{does not exist}", 1 },
    { "%{}", 1 }
};

static void
test_def_cc_name(krb5_context context)
{
    krb5_error_code ret;
    char *str;
    size_t i;

    for (i = 0; i < sizeof(cc_names)/sizeof(cc_names[0]); i++) {
	ret = _krb5_expand_default_cc_name(context, cc_names[i].str, &str);
	if (ret) {
	    if (cc_names[i].fail == 0)
		krb5_errx(context, 1, "test %d \"%s\" failed",
			  (int)i, cc_names[i].str);
	} else {
	    if (cc_names[i].fail)
		krb5_errx(context, 1, "test %d \"%s\" was successful",
			  (int)i, cc_names[i].str);
	    if (cc_names[i].res && strcmp(cc_names[i].res, str) != 0)
		krb5_errx(context, 1, "test %d %s != %s",
			  (int)i, cc_names[i].res, str);
	    if (debug_flag)
		printf("%s => %s\n", cc_names[i].str, str);
	    free(str);
	}
    }
}

static void
test_cache_find(krb5_context context, const char *principal, int find)
{
    krb5_principal client;
    krb5_error_code ret;
    krb5_ccache id = NULL;

    ret = krb5_parse_name(context, principal, &client);
    if (ret)
	krb5_err(context, 1, ret, "parse_name for %s failed", principal);

    ret = krb5_cc_cache_match(context, client, &id);
    if (ret && find)
	krb5_err(context, 1, ret, "cc_cache_match for %s failed", principal);
    if (ret == 0 && !find)
	krb5_err(context, 1, ret, "cc_cache_match for %s found", principal);

    if (id)
	krb5_cc_close(context, id);
    krb5_free_principal(context, client);
}


static void
test_cache_iter(krb5_context context, const char *type, int destroy, int do_nothing)
{
    krb5_cc_cache_cursor cursor;
    krb5_error_code ret;
    krb5_ccache id;

    ret = krb5_cc_cache_get_first (context, type, &cursor);
    if (ret == KRB5_CC_NOSUPP)
	return;
    else if (ret)
	krb5_err(context, 1, ret, "krb5_cc_cache_get_first(%s)", type);


    while ((ret = krb5_cc_cache_next (context, cursor, &id)) == 0) {

	if (do_nothing) {
	    //this is used to test cursor cleanup
	    break;
	}

	krb5_principal principal;
	char *name;

	if (debug_flag)
	    printf("name: %s\n", krb5_cc_get_name(context, id));
	ret = krb5_cc_get_principal(context, id, &principal);
	if (ret == 0) {
	    ret = krb5_unparse_name(context, principal, &name);
	    if (ret == 0) {
		if (debug_flag)
		    printf("\tprincipal: %s\n", name);
		free(name);
	    }
	    krb5_free_principal(context, principal);
	}
	if (destroy)
	    krb5_cc_destroy(context, id);
	else
	    krb5_cc_close(context, id);
    }
    if (ret != KRB5_CC_END && !do_nothing)
	krb5_err(context, 1, ret, "krb5_cc_cache_next returned not expected error");

    krb5_cc_cache_end_seq_get(context, cursor);
}

static void
test_cache_iter_all(krb5_context context)
{
    krb5_cccol_cursor cursor;
    krb5_error_code ret;
    krb5_ccache id;

    ret = krb5_cccol_cursor_new (context, &cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cccol_cursor_new");


    while ((ret = krb5_cccol_cursor_next (context, cursor, &id)) == 0 && id != NULL) {
	krb5_principal principal;
	char *name;

	if (debug_flag)
	    printf("name: %s\n", krb5_cc_get_name(context, id));
	ret = krb5_cc_get_principal(context, id, &principal);
	if (ret == 0) {
	    ret = krb5_unparse_name(context, principal, &name);
	    if (ret == 0) {
		if (debug_flag)
		    printf("\tprincipal: %s\n", name);
		free(name);
	    }
	    krb5_free_principal(context, principal);
	}
	krb5_cc_close(context, id);
    }
    if (ret != KRB5_CC_END)
	krb5_err(context, 1, ret, "krb5_cccol_cursor_next returned not expected error");

    krb5_cccol_cursor_free(context, &cursor);
}


static void
test_copy(krb5_context context, const char *from, const char *to)
{
    krb5_log(context, context->debug_dest, 20, "test_copy: %s, %s", from, to);
    krb5_ccache fromid, toid;
    krb5_error_code ret;
    krb5_principal p, p2;

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_new_unique(context, from, NULL, &fromid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique: %s", from);

    ret = krb5_cc_initialize(context, fromid, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    ret = krb5_cc_new_unique(context, to, NULL, &toid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_gen_new: %s", to);

    ret = krb5_cc_copy_cache(context, fromid, toid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_copy_cache");

    ret = krb5_cc_get_principal(context, toid, &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal");

    if (krb5_principal_compare(context, p, p2) == FALSE)
	krb5_errx(context, 1, "p != p2");

    krb5_free_principal(context, p);
    krb5_free_principal(context, p2);

    krb5_cc_destroy(context, fromid);
    krb5_cc_destroy(context, toid);
}


//this test will copy a cred from the supplied cache type to an xcache cache that does not exist yet
static void
test_copy_to_new_xcache(krb5_context context, const char *from)
{
    krb5_log(context, context->debug_dest, 20, "test_copy_to_new_xcache: %s", from);
    krb5_ccache fromid, toid;
    krb5_error_code ret;
    krb5_principal p, p2;
    krb5_creds cred;

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_new_unique(context, from, NULL, &fromid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique: %s", from);

    ret = krb5_cc_initialize(context, fromid, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    //store a fake cred in from
    memset(&cred, 0, sizeof(cred));
    cred.times.endtime = time(NULL) + 10;
    ret = krb5_parse_name(context, "krbtgt/SU.SE@SU.SE", &cred.server);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_parse_name");
    }

    ret = krb5_parse_name(context, "lha@SU.SE", &cred.client);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_parse_name");
    }

    ret = krb5_cc_store_cred(context, fromid, &cred);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_store_cred");
    }
    krb5_free_cred_contents (context, &cred);

    ret = krb5_cc_resolve(context, "XCACHE:B8708B61-CABF-44FE-A0C4-AB8A80A43014", &toid);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_resolve");
    }

    //copy it
    ret = krb5_cc_copy_cache(context, fromid, toid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_copy_cache");

    //close the cache and reload it to not use cached values
    krb5_cc_close(context, toid);
    ret = krb5_cc_resolve(context, "XCACHE:B8708B61-CABF-44FE-A0C4-AB8A80A43014", &toid);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_resolve again");
    }

    ret = krb5_cc_get_principal(context, toid, &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal");

    if (krb5_principal_compare(context, p, p2) == FALSE)
	krb5_errx(context, 1, "p != p2");

    //the destination cache should have a cred that matches the source cred
    krb5_cc_cursor cursor;
    ret = krb5_cc_start_seq_get(context, toid, &cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_start_seq_get");

    while ((ret = krb5_cc_next_cred(context, toid, &cursor, &cred)) == 0){
	if (krb5_principal_compare(context, p, cred.client) == FALSE) {
	    krb5_errx(context, 1, "p != cred.client");
	}

	krb5_free_cred_contents (context, &cred);
    }
    ret = krb5_cc_end_seq_get(context, toid, &cursor);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_end_seq_get");
    }

    krb5_free_principal(context, p);
    krb5_free_principal(context, p2);

    krb5_cc_destroy(context, fromid);
    krb5_cc_destroy(context, toid);
}

static void
test_move_to_memory(krb5_context context, const char *from, const char *to)
{
    krb5_log(context, context->debug_dest, 20, "test_move_to_memory: %s, %s", from, to);
    krb5_ccache fromid, toid;
    krb5_error_code ret;
    krb5_principal p, p2;
    krb5_creds cred;

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_new_unique(context, from, NULL, &fromid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique: %s", from);

    ret = krb5_cc_initialize(context, fromid, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    //store a fake cred in from
    memset(&cred, 0, sizeof(cred));
    cred.times.endtime = time(NULL) + 10;
    ret = krb5_parse_name(context, "krbtgt/SU.SE@SU.SE", &cred.server);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_parse_name");
    }

    ret = krb5_parse_name(context, "lha@SU.SE", &cred.client);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_parse_name");
    }

    ret = krb5_cc_store_cred(context, fromid, &cred);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_store_cred");
    }
    krb5_free_cred_contents (context, &cred);

    ret = krb5_cc_resolve(context, to, &toid);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_resolve");
    }

    //move it
    ret = krb5_cc_move(context, fromid, toid);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_copy_cache");
    } else {
	fromid = NULL;
    }

    //close the cache and reload it to not use cached values
    krb5_cc_close(context, toid);
    ret = krb5_cc_resolve(context, to, &toid);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_resolve again");
    }

    ret = krb5_cc_get_principal(context, toid, &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal");

    if (krb5_principal_compare(context, p, p2) == FALSE)
	krb5_errx(context, 1, "p != p2");

    //the destination cache should have a cred that matches the source cred
    krb5_cc_cursor cursor;
    ret = krb5_cc_start_seq_get(context, toid, &cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_start_seq_get");

    while ((ret = krb5_cc_next_cred(context, toid, &cursor, &cred)) == 0){
	if (krb5_principal_compare(context, p, cred.client) == FALSE) {
	    krb5_errx(context, 1, "p != cred.client");
	}

	krb5_free_cred_contents (context, &cred);
    }
    ret = krb5_cc_end_seq_get(context, toid, &cursor);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_end_seq_get");
    }

    krb5_free_principal(context, p);
    krb5_free_principal(context, p2);

    if (fromid) {
	krb5_cc_destroy(context, fromid);
    }
    krb5_cc_destroy(context, toid);
}

static void
test_move(krb5_context context, const char *type)
{
    krb5_log(context, context->debug_dest, 20, "test_move: %s", type);
    const krb5_cc_ops *ops;
    krb5_ccache fromid, toid;
    krb5_error_code ret;
    krb5_principal p, p2;

    ops = krb5_cc_get_prefix_ops(context, type);
    if (ops == NULL)
	return;

    ret = krb5_cc_new_unique(context, type, NULL, &fromid);
    if (ret == KRB5_CC_NOSUPP)
	return;
    else if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique: %s", type);

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_initialize(context, fromid, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    ret = krb5_cc_new_unique(context, type, NULL, &toid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique");

    ret = krb5_cc_initialize(context, toid, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    ret = krb5_cc_move(context, fromid, toid);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_move: %s", type);
    } else {
	fromid = NULL;
    }

    ret = krb5_cc_get_principal(context, toid, &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal");

    if (krb5_principal_compare(context, p, p2) == FALSE)
	krb5_errx(context, 1, "p != p2");

    krb5_free_principal(context, p);
    krb5_free_principal(context, p2);

    krb5_cc_destroy(context, toid);
    if (fromid!=NULL) {
	krb5_cc_close(context, fromid);
    }

}

static void
test_cache_iter_all_destroy(krb5_context context)
{
    krb5_cccol_cursor cursor;
    krb5_error_code ret;
    krb5_ccache id;

    ret = krb5_cccol_cursor_new (context, &cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cccol_cursor_new");


    while ((ret = krb5_cccol_cursor_next (context, cursor, &id)) == 0 && id != NULL) {
	if (debug_flag)
	    printf("name: %s\n", krb5_cc_get_name(context, id));

	ret = krb5_cc_destroy(context, id);
    }
    if (ret != KRB5_CC_END)
	krb5_err(context, 1, ret, "krb5_cccol_cursor_next returned not expected error");

    krb5_cccol_cursor_free(context, &cursor);
}

static void
test_prefix_ops(krb5_context context, const char *name, const krb5_cc_ops *ops)
{
    const krb5_cc_ops *o;

    o = krb5_cc_get_prefix_ops(context, name);
    if (o == NULL)
	krb5_errx(context, 1, "found no match for prefix '%s'", name);
    if (strcmp(o->prefix, ops->prefix) != 0)
	krb5_errx(context, 1, "ops for prefix '%s' is not "
		  "the expected %s != %s", name, o->prefix, ops->prefix);
}

static void
test_cc_config(krb5_context context)
{
    krb5_error_code ret;
    krb5_principal p;
    krb5_ccache id;
    unsigned int i;

    ret = krb5_cc_new_unique(context, "MEMORY", "bar", &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique");

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    for (i = 0; i < 1000; i++) {
	krb5_data data, data2;
	krb5_data_zero(&data);
	krb5_data_zero(&data2);
	const char *name = "foo";
	krb5_principal p1 = NULL;

	if (i & 1)
	    p1 = p;

	data.data = rk_UNCONST(name);
	data.length = strlen(name);

	ret = krb5_cc_set_config(context, id, p1, "FriendlyName", &data);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_set_config: add");

	ret = krb5_cc_get_config(context, id, p1, "FriendlyName", &data2);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_get_config: first");
	krb5_data_free(&data2);

	ret = krb5_cc_set_config(context, id, p1, "FriendlyName", &data);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_set_config: add -second");

	ret = krb5_cc_get_config(context, id, p1, "FriendlyName", &data2);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_get_config: second");
	krb5_data_free(&data2);

	ret = krb5_cc_set_config(context, id, p1, "FriendlyName", NULL);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_set_config: delete");

	ret = krb5_cc_get_config(context, id, p1, "FriendlyName", &data2);
	if (ret == 0)
	    krb5_errx(context, 1, "krb5_cc_get_config: non-existant");
	krb5_data_free(&data2);
    }
    krb5_free_principal(context, p);
    krb5_cc_destroy(context, id);
}

static void
test_cc_config_threaded(krb5_context context, uint count, const char *type, const char *cachename, bool destroy)
{
    krb5_log(context, context->debug_dest, 20, "test_cc_config_threaded: %s, %s", type, cachename);
    krb5_error_code ret;
    krb5_principal p = NULL;
    krb5_ccache id = NULL;
    unsigned int i;

    if (cachename) {
	char *cname;
	asprintf(&cname, "%s:%s",type, cachename);
	ret = krb5_cc_resolve(context, cname, &id);
	free(cname);
	if (!ret) {
	    ret = krb5_cc_get_principal(context, id, &p);
	    if (ret) {

		ret = krb5_parse_name(context, "lha@SU.SE", &p);
		if (ret)
		    krb5_err(context, 1, ret, "krb5_parse_name");
		
		ret = krb5_cc_initialize(context, id, p);
		if (ret)
		    krb5_err(context, 1, ret, "krb5_cc_initialize");
	    }
	}
    }
    if (id==NULL) {
	ret = krb5_cc_new_unique(context, type, cachename, &id);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_new_unique");

	ret = krb5_parse_name(context, "lha@SU.SE", &p);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_parse_name");

	ret = krb5_cc_initialize(context, id, p);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_initialize");
    }

    for (i = 0; i < count; i++) {
	krb5_data data, data2, pwdata;
	const char *name = "foo";
	const char *password = "foobar";
	krb5_principal p1 = NULL;

	if (i & 1)
	    p1 = p;

	data.data = rk_UNCONST(name);
	data.length = strlen(name);

	pwdata.data = rk_UNCONST(password);
	pwdata.length = strlen(password);

	ret = krb5_cc_set_config(context, id, p1, "FriendlyName", &data);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_set_config: add threaded");

	ret = krb5_cc_set_config(context, id, NULL, "password", &pwdata);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_set_config: password");

	ret = krb5_cc_set_kdc_offset(context, id, 5);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_set_kdc_offset: failed");

	ret = krb5_cc_get_config(context, id, p1, "FriendlyName", &data2);
	if (ret && ret != KRB5_CC_NOTFOUND)
	    krb5_errx(context, 1, "krb5_cc_get_config: first threaded");
	krb5_data_free(&data2);

	ret = krb5_cc_get_config(context, id, NULL, "password", &data2);
	// this should always fail from this test app
	if (ret == 0 && id->ops != &krb5_mcc_ops) {
	    krb5_errx(context, 1, "krb5_cc_get_config: password, should not work");
	}
	krb5_data_free(&data2);

	krb5_deltat offset;
	ret = krb5_cc_get_kdc_offset(context, id, &offset);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_get_kdc_offset: failed");

	ret = krb5_cc_set_config(context, id, p1, "FriendlyName", &data);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_set_config: add second threaded");

	ret = krb5_cc_get_config(context, id, p1, "FriendlyName", &data2);
	if (ret && ret != KRB5_CC_NOTFOUND)
	    krb5_errx(context, 1, "krb5_cc_get_config: second threaded");
	krb5_data_free(&data2);

	ret = krb5_cc_set_config(context, id, p1, "FriendlyName", NULL);
	if (ret && ret != KRB5_CC_NOTFOUND)
	    krb5_errx(context, 1, "krb5_cc_set_config: delete threaded");

    }

    if (destroy && !cachename)
	krb5_cc_destroy(context, id);
    else
	krb5_cc_close(context, id);
    krb5_free_principal(context, p);
}

static void
test_label(krb5_context context, const char *type)
{
    krb5_log(context, context->debug_dest, 20, "test_label: %s", type);
    krb5_error_code ret;
    krb5_ccache id, id2;
    krb5_principal p;
    krb5_creds cred;

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_parse_name");
    }

    //create a cache, add a fake cred to it
    ret = krb5_cc_new_unique(context, type, NULL, &id);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_gen_new: %s", type);
    }

    ret = krb5_cc_initialize(context, id, p);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_initialize");
    }

    /* */
    memset(&cred, 0, sizeof(cred));
    cred.times.endtime = time(NULL) + 10;
    ret = krb5_parse_name(context, "krbtgt/SU.SE@SU.SE", &cred.server);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_parse_name");
    }

    ret = krb5_parse_name(context, "lha@SU.SE", &cred.client);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_parse_name");
    }

    ret = krb5_cc_store_cred(context, id, &cred);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_store_cred");
    }

    //add a hold and remove a hold
    ret = krb5_cc_hold(context, id);  //count should be 2
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_hold");
    }

    ret = krb5_cc_unhold(context, id); //count should be 1
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_unhold");
    }

    //find the cache
    ret = krb5_cc_cache_match(context, p, &id2);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_unhold: the cache was incorrectly deleted");
    }

    krb5_cc_close(context, id2);
    id2 = NULL;

    ret = krb5_cc_unhold(context, id); //count should be 0, now the cache should be deleted
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_unhold");
    }

    //find the cache again
    ret = krb5_cc_cache_match(context, p, &id2);
    if (ret != KRB5_CC_NOTFOUND) {
	krb5_err(context, 1, ret, "krb5_cc_unhold: the cache should have been deleted");
    }

    //cleanup
    ret = krb5_cc_destroy(context, id);
    if (ret) {
	krb5_err(context, 1, ret, "krb5_cc_destroy");
    }

    krb5_free_principal(context, p);
    krb5_free_cred_contents(context, &cred);
}

#ifdef HAVE_DISPATCH_DISPATCH_H

static void
test_threaded(krb5_context context, const char *type)
{
    krb5_log(context, context->debug_dest, 20, "test_threaded: %s", type);
    dispatch_semaphore_t sema;
    dispatch_queue_t q;
    dispatch_group_t group;
    time_t old;

    /* clean up old caches first */
    test_cache_iter(context, type, 1, 0);

    sema = dispatch_semaphore_create(10);

    q = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);

    old = time(NULL);

    group = dispatch_group_create();
    if (group == NULL) abort();

    size_t number = 100;

    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

    if (debug_flag)
	printf("time: %d\n", (int)(time(NULL) - old));

    dispatch_group_async(group, q, ^{
	    dispatch_group_t inner = dispatch_group_create();
	    if (inner == NULL) abort();

	    dispatch_group_async(inner, q, ^{
		    dispatch_apply(number, q, ^(size_t num) {
			    krb5_error_code ret;
			    krb5_context c;
			    ret = krb5_init_context(&c);
			    if (ret)
			       err(1, "krb5_init_context failed with: %d", ret);

			    test_move(c, type);
			    krb5_free_context(c);
			});
		});
	    dispatch_group_async(inner, q, ^{
		    dispatch_apply(number, q, ^(size_t num) {
			    krb5_error_code ret;
			    krb5_context c;
			    ret = krb5_init_context(&c);
			    if (ret)
				err(1, "krb5_init_context failed with: %d", ret);

			    test_move(c, type);
			    krb5_free_context(c);
			});
		});
	    dispatch_group_async(inner, q, ^{
		    dispatch_apply(number / 10, q, ^(size_t num) {
			    krb5_error_code ret;
			    krb5_context c;
			    ret = krb5_init_context(&c);
			    if (ret)
				err(1, "krb5_init_context failed with: %d", ret);

			    test_cache_iter(c, type, 0, 0);
			    krb5_free_context(c);
			});
		});
	    dispatch_group_async(inner, q, ^{
		    dispatch_apply(number / 10, q, ^(size_t num) {
			    krb5_error_code ret;
			    krb5_context c;
			    ret = krb5_init_context(&c);
			    if (ret)
				err(1, "krb5_init_context failed with: %d", ret);
			    test_cache_iter_all(c);
			    krb5_free_context(c);
			});
		});

	    dispatch_group_wait(inner, DISPATCH_TIME_FOREVER);
	    dispatch_release(inner);
	    dispatch_semaphore_signal(sema);
	});

    dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
    dispatch_release(group);
    dispatch_release(sema);
}

static void
test_threaded_config(krb5_context context, int config_iters, bool destroy_cache, const char *type, const char *name)
{
    krb5_log(context, context->debug_dest, 20, "test_threaded_config: %s, %s", type, name);
    dispatch_semaphore_t sema;
    dispatch_queue_t q;
    dispatch_group_t group;
    time_t old;

    /* clean up old caches first */

    test_cache_iter(context, type, 1, 0);

    sema = dispatch_semaphore_create(10);

    q = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);

    old = time(NULL);

    group = dispatch_group_create();
    if (group == NULL) abort();

    size_t number = 100;

    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

    if (debug_flag)
	printf("time: %d\n", (int)(time(NULL) - old));

    //create the cache the first time to prevent threading issues with resolving it.
    test_cc_config_threaded(context, 1, type, name, false);

    dispatch_group_async(group, q, ^{
	dispatch_group_t inner = dispatch_group_create();
	if (inner == NULL) abort();

	dispatch_group_async(inner, q, ^{
	    dispatch_apply(number, q, ^(size_t num) {
		krb5_error_code ret;
		krb5_context c;
		ret = krb5_init_context(&c);
		if (ret)
		    err(1, "krb5_init_context failed with: %d", ret);

		test_move(c, type);
		test_cc_config_threaded(c, config_iters, type, name, destroy_cache);
		krb5_free_context(c);
	    });
	});
	dispatch_group_async(inner, q, ^{
	    dispatch_apply(number, q, ^(size_t num) {
		krb5_error_code ret;
		krb5_context c;
		ret = krb5_init_context(&c);
		if (ret)
		    err(1, "krb5_init_context failed with: %d", ret);
		test_cc_config_threaded(c, config_iters, type, name, destroy_cache);
		test_move(c, type);
		krb5_free_context(c);
	    });
	});
	dispatch_group_async(inner, q, ^{
	    dispatch_apply(number / 10, q, ^(size_t num) {
		krb5_error_code ret;
		krb5_context c;
		ret = krb5_init_context(&c);
		if (ret)
		    err(1, "krb5_init_context failed with: %d", ret);

		test_cache_iter(c, type, 0, 0);
		krb5_free_context(c);
	    });
	});
	dispatch_group_async(inner, q, ^{
	    dispatch_apply(number / 10, q, ^(size_t num) {
		krb5_error_code ret;
		krb5_context c;
		ret = krb5_init_context(&c);
		if (ret)
		    err(1, "krb5_init_context failed with: %d", ret);

		test_cache_iter_all(c);
		krb5_free_context(c);
	    });
	});

	dispatch_group_wait(inner, DISPATCH_TIME_FOREVER);
	dispatch_release(inner);
	dispatch_semaphore_signal(sema);
    });
  
    dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
    dispatch_release(group);
    dispatch_release(sema);
}

#endif

static struct getargs args[] = {
    {"debug",	'd',	arg_flag,	&debug_flag,
     "turn on debuggin", NULL },
    {"version",	0,	arg_flag,	&version_flag,
     "print version", NULL },
    {"help",	0,	arg_flag,	&help_flag,
     NULL, NULL }
};

static void
usage (int ret)
{
    arg_printusage (args, sizeof(args)/sizeof(*args), NULL, "hostname ...");
    exit (ret);
}

int
main(int argc, char **argv)
{
    krb5_context context;
    krb5_error_code ret;
    int optidx = 0;
    krb5_ccache id1, id2, id3, id4;

    setprogname(argv[0]);

    if(getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optidx))
	usage(1);

    if (help_flag)
	usage (0);

    if(version_flag){
	print_version(NULL);
	exit(0);
    }

    ret = krb5_init_context(&context);
    if (ret)
	errx (1, "krb5_init_context failed: %d", ret);

    _HeimCredResetLocalCache();

    test_cache_iter_all_destroy(context);  //destroy all caches before starting tests.

    test_cache_entry_iter(context, "API");

    test_cache_remove(context, krb5_cc_type_file);
    test_cache_remove(context, krb5_cc_type_memory);
#ifdef HAVE_SCC
    test_cache_remove(context, krb5_cc_type_scc);
#endif

    test_default_name(context);
    test_mcache(context);
    test_init_vs_destroy(context, krb5_cc_type_memory);
    test_init_vs_destroy(context, krb5_cc_type_file);
    test_init_vs_destroy(context, krb5_cc_type_api);
    _HeimCredResetLocalCache();
    test_default_init(context, krb5_cc_type_memory);
    test_default_init(context, krb5_cc_type_file);
    test_default_init(context, krb5_cc_type_api);
    _HeimCredResetLocalCache();
#if 0
    test_init_vs_destroy(context, krb5_cc_type_api);
#endif
#ifdef HAVE_SCC
    test_init_vs_destroy(context, krb5_cc_type_scc);
#endif
    test_mcc_default();
    test_def_cc_name(context);

    test_cache_iter_all(context);

    test_cache_iter(context, krb5_cc_type_memory, 0, 0);
    {
	krb5_principal p;
	krb5_cc_new_unique(context, krb5_cc_type_memory, "bar", &id1);
	krb5_cc_new_unique(context, krb5_cc_type_memory, "baz", &id2);
	krb5_parse_name(context, "lha@SU.SE", &p);
	krb5_cc_initialize(context, id1, p);
	krb5_cc_initialize(context, id1, p);
	krb5_cc_initialize(context, id1, p);
	krb5_cc_initialize(context, id1, p);
	krb5_cc_initialize(context, id1, p);
	krb5_cc_initialize(context, id1, p);
	krb5_free_principal(context, p);
    }

    test_cache_find(context, "lha@SU.SE", 1);
    test_cache_find(context, "hulabundulahotentot@SU.SE", 0);

    krb5_cc_new_unique(context, krb5_cc_type_memory, NULL, &id3);
    krb5_cc_new_unique(context, krb5_cc_type_memory, NULL, &id4);

    test_cache_iter(context, krb5_cc_type_memory, 0, 1);
    test_cache_iter(context, krb5_cc_type_memory, 0, 0);
    test_cache_iter(context, krb5_cc_type_memory, 1, 0);
    test_cache_iter(context, krb5_cc_type_memory, 0, 0);
    test_cache_iter(context, krb5_cc_type_file, 0, 0);
    test_cache_iter(context, krb5_cc_type_api, 0, 0);
#ifdef HAVE_SCC
    test_cache_iter(context, krb5_cc_type_scc, 0);
    test_cache_iter(context, krb5_cc_type_scc, 1);
#endif
#ifdef HAVE_KCC
    test_cache_iter(context, krb5_cc_type_kcc, 0);
    test_cache_iter(context, krb5_cc_type_kcc, 1);
#endif

    test_copy(context, krb5_cc_type_file, krb5_cc_type_file);
    test_copy(context, krb5_cc_type_memory, krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_file, krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_memory, krb5_cc_type_file);
    _HeimCredResetLocalCache();
    test_copy(context, krb5_cc_type_file, "XCACHE");
    _HeimCredResetLocalCache();
    test_copy(context, krb5_cc_type_memory, "XCACHE");
    _HeimCredResetLocalCache();
    test_copy_to_new_xcache(context, krb5_cc_type_file);
    _HeimCredResetLocalCache();
    test_copy_to_new_xcache(context, krb5_cc_type_memory);
    _HeimCredResetLocalCache();
    test_move_to_memory(context, "MEMORY:foo", "MEMORY:bar");
#ifdef HAVE_SCC
    test_copy(context, krb5_cc_type_scc, krb5_cc_type_file);
    test_copy(context, krb5_cc_type_file, krb5_cc_type_scc);
    test_copy(context, krb5_cc_type_scc, krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_memory, krb5_cc_type_scc);
#endif
#ifdef HAVE_KCC
    test_copy(context, krb5_cc_type_kcc, krb5_cc_type_file);
    test_copy(context, krb5_cc_type_file, krb5_cc_type_kcc);
    test_copy(context, krb5_cc_type_kcc, krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_memory, krb5_cc_type_kcc);
#endif
    test_move(context, krb5_cc_type_file);
    test_move(context, krb5_cc_type_memory);
#if HAVE_KCM || ENABLE_KCM_COMPAT
    test_move(context, krb5_cc_type_kcm);
#endif
#ifdef HAVE_SCC
    test_move(context, krb5_cc_type_scc);
#endif

    test_prefix_ops(context, "FILE:/tmp/foo", &krb5_fcc_ops);
    test_prefix_ops(context, "FILE", &krb5_fcc_ops);
    test_prefix_ops(context, "MEMORY", &krb5_mcc_ops);
    test_prefix_ops(context, "MEMORY:foo", &krb5_mcc_ops);
    test_prefix_ops(context, "/tmp/kaka", &krb5_fcc_ops);
#ifdef HAVE_SCC
    test_prefix_ops(context, "SCC:", &krb5_scc_ops);
    test_prefix_ops(context, "SCC:foo", &krb5_scc_ops);
#endif
#ifdef HAVE_KCC
    test_prefix_ops(context, "KCC:", &krb5_kcc_ops);
    test_prefix_ops(context, "KCC:foo", &krb5_kcc_ops);
#endif
#ifdef HAVE_XCC
    _HeimCredResetLocalCache();
    test_prefix_ops(context, "XCACHE:", &krb5_xcc_ops);
    _HeimCredResetLocalCache();
    test_prefix_ops(context, "XCACHE:68ADE5C1-C1FF-4088-8AA2-8AF815CDCC5A", &krb5_xcc_ops);
    _HeimCredResetLocalCache();
    test_default_init(context, "XCACHE");
    _HeimCredResetLocalCache();
    test_default_init(context, "XCACHE");
    _HeimCredResetLocalCache();
    test_move(context, "XCACHE");
    _HeimCredResetLocalCache();
    test_cache_iter(context, "XCACHE", 0, 0);
#endif

    krb5_cc_destroy(context, id1);
    krb5_cc_destroy(context, id2);

    test_cc_config(context);

    test_label(context, "XCACHE");

#ifdef HAVE_DISPATCH_DISPATCH_H
    krb5_log(context, context->debug_dest, 20, "threaded API cache tests");

    test_threaded(context, "API");

#if HAVE_KCM || ENABLE_KCM_COMPAT
    krb5_log(context, context->debug_dest, 20, "threaded KCM cache tests");
    test_label(context, "KCM");

    test_threaded(context, "KCM");

    //clear the cache, if it exists
    krb5_cc_resolve(context, "KCM:lha@SU.SE", &id1);
    if (id1) krb5_cc_destroy(context, id1);
    else krb5_cc_close(context, id1);

    //stress test multiple threads hitting multiple caches
    test_threaded_config(context, 20, 1, "KCM", NULL);

    //clear the cache, if it exists
    krb5_cc_resolve(context, "KCM:lha@SU.SE", &id1);
    if (id1) krb5_cc_destroy(context, id1);
    else krb5_cc_close(context, id1);

    //stress test multiple threads hitting the same cache
    test_threaded_config(context, 20, 0, "KCM", "lha@SU.SE");
    krb5_log(context, context->debug_dest, 20, "threaded XCACHE cache tests");
#endif
    //clear the cache, if it exists
    krb5_cc_resolve(context, "XCACHE:68ADE5C1-C1FF-4088-8AA2-8AF815CDCC5A", &id1);
    if (id1) krb5_cc_destroy(context, id1);
    else krb5_cc_close(context, id1);

    //stress test the xcache for loading and saving config
    test_cc_config_threaded(context, 100, "XCACHE", "68ADE5C1-C1FF-4088-8AA2-8AF815CDCC5A", 1);

    //clear the cache, if it exists
    krb5_cc_resolve(context, "XCACHE:68ADE5C1-C1FF-4088-8AA2-8AF815CDCC5A", &id1);
    if (id1) krb5_cc_destroy(context, id1);
    else krb5_cc_close(context, id1);

    //stress test multiple threads hiting the same cache
    test_threaded_config(context, 4, 1, "XCACHE", "68ADE5C1-C1FF-4088-8AA2-8AF815CDCC5A");

    krb5_cc_resolve(context, "XCACHE:68ADE5C1-C1FF-4088-8AA2-8AF815CDCC5A", &id1);
    if (id1) krb5_cc_destroy(context, id1);
    else krb5_cc_close(context, id1);

    krb5_log(context, context->debug_dest, 20, "threaded memory cache tests");

    test_threaded(context, "MEMORY");
    
    //stress test multiple threads hitting multiple memory caches
    test_threaded_config(context, 20, 1, "MEMORY", NULL);
    
    //stress test multiple threads hitting the same memory cache
    test_threaded_config(context, 20, 0, "MEMORY", "bar");

#endif

    krb5_free_context(context);

    return 0;
}
