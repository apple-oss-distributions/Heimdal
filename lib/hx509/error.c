/*
 * Copyright (c) 2006 - 2007 Kungliga Tekniska Högskolan
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

#include "hx_locl.h"

/**
 * @page page_error Hx509 error reporting functions
 *
 * See the library functions here: @ref hx509_error
 */

struct hx509_error_data {
    hx509_error next;
    int code;
    char *msg;
};

/**
 * Resets the error strings the hx509 context.
 *
 * @param context A hx509 context.
 *
 * @ingroup hx509_error
 */

void
hx509_clear_error_string(hx509_context context)
{
    if (context) {
	heim_release(context->error);
	context->error = NULL;
    }
}

/**
 * Add an error message to the hx509 context.
 *
 * @param context A hx509 context.
 * @param flags
 * - HX509_ERROR_APPEND appends the error string to the old messages
     (code is updated).
 * @param code error code related to error message
 * @param fmt error message format
 * @param ap arguments to error message format
 *
 * @ingroup hx509_error
 */

void
hx509_set_error_stringv(hx509_context context, int flags, int code,
			const char *fmt, va_list ap)
{
    heim_error_t msg;

    if (context == NULL)
	return;

    msg = heim_error_createv(code, fmt, ap);
    if (msg) {
	if (flags & HX509_ERROR_APPEND)
	    heim_error_append(msg, context->error);
	heim_release(context->error);
    }
    context->error = msg;
}

/**
 * See hx509_set_error_stringv().
 *
 * @param context A hx509 context.
 * @param flags
 * - HX509_ERROR_APPEND appends the error string to the old messages
     (code is updated).
 * @param code error code related to error message
 * @param fmt error message format
 * @param ... arguments to error message format
 *
 * @ingroup hx509_error
 */

void
hx509_set_error_string(hx509_context context, int flags, int code,
		       const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    hx509_set_error_stringv(context, flags, code, fmt, ap);
    va_end(ap);
}

/**
 * Get an error string from context associated with error_code.
 *
 * @param context A hx509 context.
 * @param error_code Get error message for this error code.
 *
 * @return error string, free with hx509_free_error_string().
 *
 * @ingroup hx509_error
 */

char *
hx509_get_error_string(hx509_context context, int error_code)
{
    heim_error_t msg = context->error;
    heim_string_t s;
    char *str = NULL;
    const char *cstr;

    if (msg == NULL || heim_error_get_code(msg) != error_code) {
	char buf[256];

	cstr = com_right_r(context->et_list, error_code, buf, sizeof(buf));
	if (cstr)
	    return strdup(cstr);
	cstr = strerror(error_code);
	if (cstr)
	    return strdup(cstr);
	if (asprintf(&str, "<unknown error: %d>", error_code) == -1)
	    return NULL;
	return str;
    }

    s = heim_error_copy_string(msg);
    if (s) {
	cstr = heim_string_get_utf8(s);
	if (cstr)
	    str = strdup(cstr);
	heim_release(s);
    }
    return str;
}

/**
 * Free error string returned by hx509_get_error_string().
 *
 * @param str error string to free.
 *
 * @ingroup hx509_error
 */

void
hx509_free_error_string(char *str)
{
    free(str);
}

/**
 * Print error message and fatally exit from error code
 *
 * @param context A hx509 context.
 * @param exit_code exit() code from process.
 * @param error_code Error code for the reason to exit.
 * @param fmt format string with the exit message.
 * @param ... argument to format string.
 *
 * @ingroup hx509_error
 */

void
hx509_err(hx509_context context, int exit_code,
	  int error_code, const char *fmt, ...)
{
    va_list ap;
    const char *msg;
    char *str;

    va_start(ap, fmt);
    vasprintf(&str, fmt, ap);
    va_end(ap);
    msg = hx509_get_error_string(context, error_code);
    if (msg == NULL)
	msg = "no error";

    errx(exit_code, "%s: %s", str, msg);
}