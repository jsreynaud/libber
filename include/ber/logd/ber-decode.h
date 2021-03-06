#ifndef BER_LOGD_DECODE_H
#define BER_LOGD_DECODE_H

/*
 * Copyright (c) Abraham vd Merwe <abz@blio.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of other contributors
 *	  may be used to endorse or promote products derived from this software
 *	  without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef BER_LOGD_H
#error "Don't include this file directly. Include logd/ber.h instead"
#endif  /* #ifndef BER_LOGD_H */

/*
 * 1. You have to initialize ber_t (buf, offset, size) before calling
 *    any of the functions below.
 *
 * 2. All of the functions below return 0 if successful, -1 if some
 *    error occurred. Call abz_get_error() to retrieve the error
 *    message.
 *
 * 3. Even though the size and offset field are unsigned 32-bit
 *    integers, the size of the buffer should not exceed
 *    2147483647 bytes (maximum 32-bit signed integer value)
 *
 * 4. The functions decode the buffer from front to back. Although
 *    the buffer data and the size of the buffer won't be changed,
 *    the offset is updated to where data was decoded.
 *
 * 5. Remember to free the memory allocated by ber_decode_octet_string()
 *    and ber_decode_oid() for returned values.
 *
 * 6. In the case of the functions where memory is allocated (i.e.
 *    ber_decode_octet_string() and ber_decode_oid()), the variables
 *    are guaranteed to be NULL if the function fails.
 *
 * 7. IP addresses are stored in network byte order.
 */

extern int ber_decode_get_message (ber_t *d);
extern int ber_decode_put_message (ber_t *d);
extern int ber_decode_auth (ber_t *d);
extern int ber_decode_reset (ber_t *d);
extern int ber_decode_set_level (ber_t *d);

#endif	/* #ifndef BER_LOGD_DECODE_H */
