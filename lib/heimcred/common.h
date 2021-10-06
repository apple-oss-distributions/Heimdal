/*-
 * Copyright (c) 2013 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2013 Apple Inc. All rights reserved.
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
 */
#include <CoreFoundation/CoreFoundation.h>
#include <CoreFoundation/CFRuntime.h>
#include <xpc/xpc.h>
#import "config.h"

#if HEIMCRED_SERVER
#import <heim-ipc.h>
#import "heim_threads.h"

typedef enum {
    CRED_STATUS_ACQUIRE_INITIAL = -1,
    CRED_STATUS_ACQUIRE_START = 0,
    CRED_STATUS_ACQUIRE_STOPPED = 1,
    CRED_STATUS_ACQUIRE_FAILED = 2,
    CRED_STATUS_ACQUIRE_SUCCESS = 3
} cred_acquire_status;

#endif

#include "heimcred.h"

#define CFRELEASE_NULL(x) do { if (x!=NULL) { CFRelease(x); x = NULL; } } while(0)

struct HeimMech;

struct HeimCred_s {
    CFRuntimeBase runtime;
    CFUUIDRef uuid;
    CFDictionaryRef attributes;
#if HEIMCRED_SERVER
    struct HeimMech *mech;
    
    HEIMDAL_MUTEX event_mutex;  //mutex for events, times, and statuses
    time_t renew_time;		//the next attempt to renew a renewable ticket
    heim_event_t renew_event;	//the event for renewal
    time_t next_acquire_time;  	//run time for next acquire attempt to get a new credential
    time_t expire;		//the time when the cred expires
    heim_event_t expire_event;	//the event for refreshing the cred
    cred_acquire_status acquire_status;	//the refresh status
    uid_t session;		//the session id for events;
#endif
};

typedef struct {
    dispatch_queue_t queue;
    CFTypeID haid;
#if HEIMCRED_SERVER
    CFSetRef connections;
    CFMutableDictionaryRef sessions;
    CFMutableDictionaryRef mechanisms;
    CFMutableDictionaryRef schemas;
    CFMutableDictionaryRef globalSchema;
    pid_t session;
#else
    CFMutableDictionaryRef items;
    xpc_connection_t conn;
#endif
    bool needFlush;
    bool flushPending;
} HeimCredContext;

extern HeimCredContext HeimCredCTX;

void
_HeimCredInitCommon(void);

HeimCredRef
HeimCredCreateItem(CFUUIDRef uuid) CF_RETURNS_RETAINED;

CFTypeID
HeimCredGetTypeID(void);

CFUUIDRef
HeimCredCopyUUID(xpc_object_t object, const char *key);

CFTypeRef
HeimCredMessageCopyAttributes(xpc_object_t object, const char *key, CFTypeID type);

void
HeimCredMessageSetAttributes(xpc_object_t object, const char *key, CFTypeRef attrs);

void
HeimCredSetUUID(xpc_object_t object, const char *key, CFUUIDRef uuid);

#define HEIMCRED_CONST(_t,_c) extern const char * _c##xpc
#include "heimcred-const.h"
#undef HEIMCRED_CONST
