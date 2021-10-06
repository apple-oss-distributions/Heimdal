/*
 * Copyright (c) 2010 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2010 Apple Inc. All rights reserved.
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

#ifndef HEIM_BASE_H
#define HEIM_BASE_H 1

#include <sys/types.h>
#include <krb5-types.h>
#include <stdarg.h>
#include <stdbool.h>

typedef void * heim_object_t;
typedef unsigned int heim_tid_t;
typedef heim_object_t heim_bool_t;
typedef heim_object_t heim_null_t;
typedef struct heim_error * heim_error_t;
#define HEIM_BASE_ONCE_INIT 0
typedef long heim_base_once_t; /* XXX arch dependant */

#if !defined(__has_extension)
#define __has_extension(x) 0
#endif

#define HEIM_REQUIRE_GNUC(m,n,p) \
    (((__GNUC__ * 10000) + (__GNUC_MINOR__ * 100) + __GNUC_PATCHLEVEL__) >= \
     (((m) * 10000) + ((n) * 100) + (p)))


#if __has_extension(__builtin_expect) || HEIM_REQUIRE_GNUC(3,0,0)
#define heim_builtin_expect(_op,_res) __builtin_expect(_op,_res)
#else
#define heim_builtin_expect(_op,_res) (_op)
#endif

void *	heim_retain(heim_object_t);
void	heim_release(heim_object_t);

void	heim_show(heim_object_t);

/*
 *
 */

typedef void (*heim_type_dealloc)(void *);

heim_object_t
heim_uniq_alloc(size_t size, const char *name, heim_type_dealloc dealloc);

/*
 *
 */

heim_tid_t
heim_get_tid(heim_object_t object);

int
heim_cmp(heim_object_t a, heim_object_t b);

unsigned long
heim_get_hash(heim_object_t ptr);

void
heim_base_once_f(heim_base_once_t *, void *, void (*)(void *));

void
heim_abort(const char *fmt, ...)
    HEIMDAL_NORETURN_ATTRIBUTE
    HEIMDAL_PRINTF_ATTRIBUTE((printf, 1, 2));

void
heim_abortv(const char *fmt, va_list ap)
    HEIMDAL_NORETURN_ATTRIBUTE
    HEIMDAL_PRINTF_ATTRIBUTE((printf, 1, 0));

#define heim_assert(e,t) \
    (__builtin_expect(!(e), 0) ? heim_abort(t ":" #e) : (void)0)

void
heim_warn_blocking(const char *apiname, heim_base_once_t *once);

#define HEIM_WARN_BLOCKING(name, var) \
{ static heim_base_once_t var = HEIM_BASE_ONCE_INIT; heim_warn_blocking(name, &var); }

/*
 *
 */

heim_null_t
heim_null_create(void);

heim_bool_t
heim_bool_create(int);

int
heim_bool_val(heim_bool_t);

/*
 * Data
 */

typedef struct heim_data_data *heim_data_t;

heim_data_t heim_data_create(void *, size_t);
heim_tid_t heim_data_get_type_id(void);
const void *
	heim_data_get_bytes(heim_data_t);
size_t	heim_data_get_length(heim_data_t);

/*
 * Array
 */

typedef struct heim_array_data *heim_array_t;

heim_array_t heim_array_create(void);
heim_tid_t heim_array_get_type_id(void);

typedef void (*heim_array_iterator_f_t)(heim_object_t, int *, void *);

int	heim_array_append_value(heim_array_t, heim_object_t);
void	heim_array_iterate_f(heim_array_t, void *, heim_array_iterator_f_t);
#ifdef __BLOCKS__
typedef void (^heim_array_iterator_t)(heim_object_t, int *);
void	heim_array_iterate(heim_array_t, heim_array_iterator_t);
#endif
size_t	heim_array_get_length(heim_array_t);
heim_object_t
	heim_array_copy_value(heim_array_t, size_t);
void	heim_array_delete_value(heim_array_t, size_t);
#ifdef __BLOCKS__
void	heim_array_filter(heim_array_t, int (^)(heim_object_t));
#endif

int	heim_array_contains_value(heim_array_t array, heim_object_t value);

/*
 * Dict
 */

typedef struct heim_dict_data *heim_dict_t;

heim_dict_t heim_dict_create(size_t size);
heim_tid_t heim_dict_get_type_id(void);

typedef void (*heim_dict_iterator_f_t)(heim_object_t, heim_object_t, void *);

int	heim_dict_set_value(heim_dict_t, heim_object_t, heim_object_t);
void	heim_dict_iterate_f(heim_dict_t, void *, heim_dict_iterator_f_t);
#ifdef __BLOCKS__
void	heim_dict_iterate(heim_dict_t, void (^)(heim_object_t, heim_object_t));
#endif

heim_object_t
	heim_dict_copy_value(heim_dict_t, heim_object_t);
void	heim_dict_delete_key(heim_dict_t, heim_object_t);

/*
 * String
 */

typedef struct heim_string_data *heim_string_t;

heim_string_t	heim_string_create(const char *);
heim_string_t	heim_string_create_with_format(const char *, ...)
    HEIMDAL_PRINTF_ATTRIBUTE((printf, 1, 2));
heim_string_t	heim_string_create_with_bytes(const void *data, size_t len);
heim_tid_t	heim_string_get_type_id(void);
char *		heim_string_copy_utf8(heim_string_t);
heim_data_t	heim_string_copy_utf16(heim_string_t);

/*
 * Number
 */

typedef struct heim_number_data *heim_number_t;

heim_number_t heim_number_create(int);
heim_tid_t heim_number_get_type_id(void);
int heim_number_get_int(heim_number_t);

/*
 *
 */

typedef struct heim_auto_release * heim_auto_release_t;

heim_auto_release_t heim_auto_release_create(void);
void heim_auto_release_drain(heim_auto_release_t);
void heim_auto_release(heim_object_t);

/*
 * JSON
 */
typedef enum heim_json_flags {
	HEIM_JSON_F_NO_C_NULL = 1,
	HEIM_JSON_F_STRICT_STRINGS = 2,
	HEIM_JSON_F_NO_DATA = 4,
	HEIM_JSON_F_NO_DATA_DICT = 8,
	HEIM_JSON_F_STRICT_DICT = 16,
	HEIM_JSON_F_STRICT = 31,
	HEIM_JSON_F_CNULL2JSNULL = 32,
	HEIM_JSON_F_TRY_DECODE_DATA = 64,
	HEIM_JSON_F_ONE_LINE = 128
} heim_json_flags_t;

heim_object_t heim_json_create(const char *, size_t, heim_json_flags_t,
			       heim_error_t *);
heim_object_t heim_json_create_with_bytes(const void *, size_t, size_t,
					  heim_json_flags_t,
					  heim_error_t *);
heim_string_t heim_json_copy_serialize(heim_object_t, heim_json_flags_t,
				       heim_error_t *);
/*
 *
 */

heim_error_t	heim_error_create(int, const char *, ...)
    HEIMDAL_PRINTF_ATTRIBUTE((printf, 2, 3));

heim_error_t	heim_error_createv(int, const char *, va_list)
    HEIMDAL_PRINTF_ATTRIBUTE((printf, 2, 0));

heim_error_t	heim_error_create_enomem(void);

heim_string_t heim_error_copy_string(heim_error_t);
int heim_error_get_code(heim_error_t);

heim_error_t
heim_error_append(heim_error_t, heim_error_t);

/*
 *
 */

typedef struct heim_queue *heim_queue_t;
typedef struct heim_queue_attr *heim_queue_attr_t;

heim_queue_t	heim_queue_create(const char *, heim_queue_attr_t);
void		heim_queue_release(heim_queue_t);
void		heim_async_f(heim_queue_t, void *, void (*)(void *));

typedef struct heim_sema_t *heim_sema_t;

heim_sema_t	heim_sema_create(long count);
void		heim_sema_signal(heim_sema_t);
long		heim_sema_wait(heim_sema_t, time_t t);


#endif /* HEIM_BASE_H */
