/*
 * BLAKE implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 *
 * Modified for more speed by BlueDragon747 for the Blakecoin project
 */

#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>

#include "sph/sph_blake.h"
#include "algorithm/blake256.h"

/*
* Encode a length len/4 vector of (uint32_t) into a length len vector of
* (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
*/
static inline void
be32enc_vect(uint32_t *dst, const uint32_t *src, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		dst[i] = htobe32(src[i]);
}

static const uint32_t diff1targ_blake256 = 0x000000ff;

inline void blakehash(void *state, const void *input)
{
	sph_blake256_context     ctx_blake;
	sph_blake256_init(&ctx_blake);
	sph_blake256(&ctx_blake, input, 80);
	sph_blake256_close(&ctx_blake, state);
}

void blake_regenhash(struct work *work)
{
	uint32_t data[20];
	uint32_t *nonce = (uint32_t *)(work->data + 76);
	uint32_t *ohash = (uint32_t *)(work->hash);

	be32enc_vect(data, (const uint32_t *)work->data, 19);
	data[19] = htobe32(*nonce);
        
	applog(LOG_DEBUG, "timestamp %d", data[17]);
        
    applog(LOG_DEBUG, "Dat0: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
    	   data[ 0], data[ 1], data[ 2], data[ 3], data[ 4], data[ 5], data[ 6], data[ 7], data[ 8], data[ 9],
           data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19]);
    
	if (work->pool->algorithm.type == ALGO_BLAKE)
		blake256_rounds = 14;
	else if (work->pool->algorithm.type == ALGO_BLAKECOIN || work->pool->algorithm.type == ALGO_VANILLA)
		blake256_rounds =  8;

	blakehash(ohash, data);
}

/* Used externally as confirmation of correct OCL code */
int blake_test(unsigned char *pdata, const unsigned char *ptarget, uint32_t nonce)
{
	uint32_t tmp_hash7, Htarg = le32toh(((const uint32_t *)ptarget)[7]);
	uint32_t data[20], ohash[8];

	be32enc_vect(data, (const uint32_t *)pdata, 19);
	data[19] = htobe32(nonce);
    
	applog(LOG_DEBUG, "Dat0: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
		   data[ 0], data[ 1], data[ 2], data[ 3], data[ 4], data[ 5], data[ 6], data[ 7], data[ 8], data[ 9],
		   data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19]);
    
    sph_blake256_context     ctx_blake;
	sph_blake256_init(&ctx_blake);
	sph_blake256(&ctx_blake, (unsigned char *)data, 80);
	sph_blake256_close(&ctx_blake, (unsigned char *)ohash);

	flip32(ohash, ohash); // Not needed for scrypt-chacha - mikaelh
    uint32_t *o = ohash;
	applog(LOG_DEBUG, "Nonce: %x, Output buffe0: %x %x %x %x %x %x %x %x", nonce, o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]);
    
	tmp_hash7 = be32toh(ohash[7]);

	applog(LOG_DEBUG, "Nonce %x harget %08lx diff1 %08lx hash %08lx",
                                nonce,
				(long unsigned int)Htarg,
				(long unsigned int)diff1targ_blake256,
				(long unsigned int)tmp_hash7);
	if (tmp_hash7 > diff1targ_blake256)
		return -1;
	if (tmp_hash7 > Htarg)
		return 0;
	return 1;
}

bool scanhash_blake(struct thr_info *thr, const unsigned char __maybe_unused *pmidstate,
	unsigned char *pdata, unsigned char __maybe_unused *phash1,
	unsigned char __maybe_unused *phash, const unsigned char *ptarget,
	uint32_t max_nonce, uint32_t *last_nonce, uint32_t n)
{
	uint32_t *nonce = (uint32_t *)(pdata + 76);
	uint32_t data[20];
	uint32_t tmp_hash7;
	uint32_t Htarg = le32toh(((const uint32_t *)ptarget)[7]);
	bool ret = false;

	be32enc_vect(data, (const uint32_t *)pdata, 19);

	while (1) {
		uint32_t ostate[8];

		*nonce = ++n;
		data[19] = (n);
		blakehash(ostate, data);
		tmp_hash7 = (ostate[7]);

		applog(LOG_INFO, "data7 %08lx",
			(long unsigned int)data[7]);

		if (unlikely(tmp_hash7 <= Htarg)) {
			((uint32_t *)pdata)[19] = htobe32(n);
			*last_nonce = n;
			ret = true;
			break;
		}

		if (unlikely((n >= max_nonce) || thr->work_restart)) {
			*last_nonce = n;
			break;
		}
	}

	return ret;
}
