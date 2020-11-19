/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _RTE_MEMCMP_X86_64_H_
#define _RTE_MEMCMP_X86_64_H_

/**
 * @file
 *
 * Functions for SSE/AVX/AVX2 implementation of memcmp().
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include <rte_vect.h>
#include <rte_branch_prediction.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Compare bytes between two locations. The locations must not overlap.
 *
 * @param src_1
 *   Pointer to the first source of the data.
 * @param src_2
 *   Pointer to the second source of the data.
 * @param n
 *   Number of bytes to compare.
 * @return
 *   zero if src_1 equal src_2
 *   -ve if src_1 less than src_2
 *   +ve if src_1 greater than src_2
 */
static inline int
rte_memcmp(const void *src_1, const void *src,
		size_t n) __attribute__((always_inline));

/**
 * Find the first different byte for comparison.
 */
static inline int
rte_cmpffdb(const uint8_t *x, const uint8_t *y, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (x[i] != y[i])
			return x[i] - y[i];
	return 0;
}

/**
 * Compare 0 to 15 bytes between two locations.
 * Locations should not overlap.
 */
static inline int
rte_memcmp_regular(const uint8_t *src_1u, const uint8_t *src_2u, size_t n)
{
	int ret = 1;

	/**
	 * Compare less than 16 bytes
	 */
	if (n & 0x01) {
		ret = (*(const uint8_t *)src_1u ==
			*(const uint8_t *)src_2u);

		if ((ret != 1))
			goto exit_1;

		n -= 0x1;
		src_1u += 0x1;
		src_2u += 0x1;
	}

	if (n & 0x02) {
		ret = (*(const uint16_t *)src_1u ==
			*(const uint16_t *)src_2u);

		if ((ret != 1))
			goto exit_2;

		n -= 0x2;
		src_1u += 0x2;
		src_2u += 0x2;
	}

	if (n & 0x04) {
		ret = (*(const uint32_t *)src_1u ==
			*(const uint32_t *)src_2u);

		if ((ret != 1))
			goto exit_4;

		n -= 0x4;
		src_1u += 0x4;
		src_2u += 0x4;
	}

	if (n & 0x08) {
		ret = (*(const uint64_t *)src_1u ==
			*(const uint64_t *)src_2u);

		if ((ret != 1))
			goto exit_8;

		n -= 0x8;
		src_1u += 0x8;
		src_2u += 0x8;
	}

	return !ret;

exit_1:
	return rte_cmpffdb(src_1u, src_2u, 1);
exit_2:
	return rte_cmpffdb(src_1u, src_2u, 2);
exit_4:
	return rte_cmpffdb(src_1u, src_2u, 4);
exit_8:
	return rte_cmpffdb(src_1u, src_2u, 8);
}

/**
 * Compare 16 bytes between two locations.
 * locations should not overlap.
 */
static inline int
rte_cmp16(const void *src_1, const void *src_2)
{
	__m128i xmm0, xmm1, xmm2;

	xmm0 = _mm_lddqu_si128((const __m128i *)src_1);
	xmm1 = _mm_lddqu_si128((const __m128i *)src_2);

	xmm2 = _mm_xor_si128(xmm0, xmm1);

	if (unlikely(!_mm_testz_si128(xmm2, xmm2))) {
		__m128i idx =
			_mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);

		/*
		 * Reverse byte order
		 */
		xmm0 = _mm_shuffle_epi8(xmm0, idx);
		xmm1 = _mm_shuffle_epi8(xmm1, idx);

		/*
		* Compare unsigned bytes with instructions for signed bytes
		*/
		xmm0 = _mm_xor_si128(xmm0, _mm_set1_epi8(0x80));
		xmm1 = _mm_xor_si128(xmm1, _mm_set1_epi8(0x80));

		return _mm_movemask_epi8(xmm0 > xmm1) - _mm_movemask_epi8(xmm1 > xmm0);
	}

	return 0;
}

/**
 * AVX2 implementation below
 */
#ifdef RTE_MACHINE_CPUFLAG_AVX2

static inline int
rte_cmp32(const void *src_1, const void *src_2)
{
	__m256i    ff = _mm256_set1_epi32(-1);
	__m256i    idx = _mm256_setr_epi8(
			15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
			15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
	__m256i    sign = _mm256_set1_epi32(0x80000000);
	__m256i    mm11, mm21;
	__m256i    eq, gt0, gt1;

	mm11 = _mm256_lddqu_si256((const __m256i *)src_1);
	mm21 = _mm256_lddqu_si256((const __m256i *)src_2);

	eq = _mm256_cmpeq_epi32(mm11, mm21);
	/* Not equal */
	if (!_mm256_testc_si256(eq, ff)) {
		mm11 = _mm256_shuffle_epi8(mm11, idx);
		mm21 = _mm256_shuffle_epi8(mm21, idx);

		mm11 = _mm256_xor_si256(mm11, sign);
		mm21 = _mm256_xor_si256(mm21, sign);
		mm11 = _mm256_permute2f128_si256(mm11, mm11, 0x01);
		mm21 = _mm256_permute2f128_si256(mm21, mm21, 0x01);

		gt0 = _mm256_cmpgt_epi32(mm11, mm21);
		gt1 = _mm256_cmpgt_epi32(mm21, mm11);
		return _mm256_movemask_ps(_mm256_castsi256_ps(gt0)) - _mm256_movemask_ps(_mm256_castsi256_ps(gt1));
	}

	return 0;
}

/**
 * Compare 48 bytes between two locations.
 * Locations should not overlap.
 */
static inline int
rte_cmp48(const void *src_1, const void *src_2)
{
	int ret;

	ret = rte_cmp32((const uint8_t *)src_1 + 0 * 32,
			(const uint8_t *)src_2 + 0 * 32);

	if (unlikely(ret != 0))
		return ret;

	ret = rte_cmp16((const uint8_t *)src_1 + 1 * 32,
			(const uint8_t *)src_2 + 1 * 32);
	return ret;
}

/**
 * Compare 64 bytes between two locations.
 * Locations should not overlap.
 */
static inline int
rte_cmp64(const void *src_1, const void *src_2)
{
	const __m256i *src1 = (const __m256i *)src_1;
	const __m256i *src2 = (const __m256i *)src_2;

	__m256i mm11 = _mm256_lddqu_si256(src1);
	__m256i mm12 = _mm256_lddqu_si256(src1 + 1);
	__m256i mm21 = _mm256_lddqu_si256(src2);
	__m256i mm22 = _mm256_lddqu_si256(src2 + 1);

	__m256i mm1 = _mm256_xor_si256(mm11, mm21);
	__m256i mm2 = _mm256_xor_si256(mm12, mm22);
	__m256i mm = _mm256_or_si256(mm1, mm2);

	if (unlikely(!_mm256_testz_si256(mm, mm))) {

		__m256i idx = _mm256_setr_epi8(
				15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
				15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
		__m256i sign = _mm256_set1_epi32(0x80000000);
		__m256i gt0, gt1;

		/*
		 * Find out which of the two 32-byte blocks
		 * are different.
		 */
		if (_mm256_testz_si256(mm1, mm1)) {
			mm11 = mm12;
			mm21 = mm22;
			mm1 = mm2;
		}

		mm11 = _mm256_shuffle_epi8(mm11, idx);
		mm21 = _mm256_shuffle_epi8(mm21, idx);

		mm11 = _mm256_xor_si256(mm11, sign);
		mm21 = _mm256_xor_si256(mm21, sign);
		mm11 = _mm256_permute2f128_si256(mm11, mm11, 0x01);
		mm21 = _mm256_permute2f128_si256(mm21, mm21, 0x01);

		gt0 = _mm256_cmpgt_epi32(mm11, mm21);
		gt1 = _mm256_cmpgt_epi32(mm21, mm11);
		return _mm256_movemask_ps(_mm256_castsi256_ps(gt0)) - _mm256_movemask_ps(_mm256_castsi256_ps(gt1));
	}

	return 0;
}

/**
 * Compare 128 bytes between two locations.
 * Locations should not overlap.
 */
static inline int
rte_cmp128(const void *src_1, const void *src_2)
{
	int ret;

	ret = rte_cmp64((const uint8_t *)src_1 + 0 * 64,
			(const uint8_t *)src_2 + 0 * 64);

	if (unlikely(ret != 0))
		return ret;

	return rte_cmp64((const uint8_t *)src_1 + 1 * 64,
			(const uint8_t *)src_2 + 1 * 64);
}

/**
 * Compare 256 bytes between two locations.
 * Locations should not overlap.
 */
static inline int
rte_cmp256(const void *src_1, const void *src_2)
{
	int ret;

	ret = rte_cmp64((const uint8_t *)src_1 + 0 * 64,
			(const uint8_t *)src_2 + 0 * 64);

	if (unlikely(ret != 0))
		return ret;

	ret = rte_cmp64((const uint8_t *)src_1 + 1 * 64,
			(const uint8_t *)src_2 + 1 * 64);

	if (unlikely(ret != 0))
		return ret;

	ret = rte_cmp64((const uint8_t *)src_1 + 2 * 64,
			(const uint8_t *)src_2 + 2 * 64);

	if (unlikely(ret != 0))
		return ret;

	return rte_cmp64((const uint8_t *)src_1 + 3 * 64,
			(const uint8_t *)src_2 + 3 * 64);
}

/**
 * Compare bytes between two locations. The locations must not overlap.
 *
 * @param src_1
 *   Pointer to the first source of the data.
 * @param src_2
 *   Pointer to the second source of the data.
 * @param n
 *   Number of bytes to compare.
 * @return
 *   zero if src_1 equal src_2
 *   -ve if src_1 less than src_2
 *   +ve if src_1 greater than src_2
 */
static inline int
rte_memcmp(const void *_src_1, const void *_src_2, size_t n)
{
	const uint8_t *src_1 = (const uint8_t *)_src_1;
	const uint8_t *src_2 = (const uint8_t *)_src_2;
	int ret = 0;

	if (n < 16)
		return rte_memcmp_regular(src_1, src_2, n);

	if (n <= 32) {
		ret = rte_cmp16(src_1, src_2);
		if (unlikely(ret != 0))
			return ret;

		return rte_cmp16(src_1 - 16 + n, src_2 - 16 + n);
	}

	if (n <= 48) {
		ret = rte_cmp32(src_1, src_2);
		if (unlikely(ret != 0))
			return ret;

		return rte_cmp16(src_1 - 16 + n, src_2 - 16 + n);
	}

	if (n <= 64) {
		ret = rte_cmp32(src_1, src_2);
		if (unlikely(ret != 0))
			return ret;

		ret = rte_cmp16(src_1 + 32, src_2 + 32);

		if (unlikely(ret != 0))
			return ret;

		return rte_cmp16(src_1 - 16 + n, src_2 - 16 + n);
	}

CMP_BLOCK_LESS_THAN_512:
	if (n <= 512) {
		if (n >= 256) {
			ret = rte_cmp256(src_1, src_2);
			if (unlikely(ret != 0))
				return ret;
			src_1 = src_1 + 256;
			src_2 = src_2 + 256;
			n -= 256;
		}
		if (n >= 128) {
			ret = rte_cmp128(src_1, src_2);
			if (unlikely(ret != 0))
				return ret;
			src_1 = src_1 + 128;
			src_2 = src_2 + 128;
			n -= 128;
		}
		if (n >= 64) {
			n -= 64;
			ret = rte_cmp64(src_1, src_2);
			if (unlikely(ret != 0))
				return ret;
			src_1 = src_1 + 64;
			src_2 = src_2 + 64;
		}
		if (n > 32) {
			ret = rte_cmp32(src_1, src_2);
			if (unlikely(ret != 0))
				return ret;
			ret = rte_cmp32(src_1 - 32 + n, src_2 - 32 + n);
			return ret;
		}
		if (n > 0)
			ret = rte_cmp32(src_1 - 32 + n, src_2 - 32 + n);

		return ret;
	}

	while (n > 512) {
		ret = rte_cmp256(src_1 + 0 * 256, src_2 + 0 * 256);
		if (unlikely(ret != 0))
			return ret;

		ret = rte_cmp256(src_1 + 1 * 256, src_2 + 1 * 256);
		if (unlikely(ret != 0))
			return ret;

		src_1 = src_1 + 512;
		src_2 = src_2 + 512;
		n -= 512;
	}
	goto CMP_BLOCK_LESS_THAN_512;
}

#else /* RTE_MACHINE_CPUFLAG_AVX2 */

/**
 * Compare 32 bytes between two locations.
 * Locations should not overlap.
 */
static inline int
rte_cmp32(const void *src_1, const void *src_2)
{
	const __m128i *src1 = (const __m128i *)src_1;
	const __m128i *src2 = (const __m128i *)src_2;

	__m128i mm11 = _mm_lddqu_si128(src1);
	__m128i mm12 = _mm_lddqu_si128(src1 + 1);
	__m128i mm21 = _mm_lddqu_si128(src2);
	__m128i mm22 = _mm_lddqu_si128(src2 + 1);

	__m128i mm1 = _mm_xor_si128(mm11, mm21);
	__m128i mm2 = _mm_xor_si128(mm12, mm22);
	__m128i mm = _mm_or_si128(mm1, mm2);

	if (unlikely(!_mm_testz_si128(mm, mm))) {

		__m128i idx =
			_mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
		/*
		 * Find out which of the two 16-byte blocks
		 * are different.
		 */
		if (_mm_testz_si128(mm1, mm1)) {
			mm11 = mm12;
			mm21 = mm22;
			mm1 = mm2;
		}

		/*
		 * Reverse byte order.
		 */
		mm11 = _mm_shuffle_epi8(mm11, idx);
		mm21 = _mm_shuffle_epi8(mm21, idx);

		/*
		 * Compare unsigned bytes with instructions for
		 * signed bytes.
		 */
		mm11 = _mm_xor_si128(mm11, _mm_set1_epi8(0x80));
		mm21 = _mm_xor_si128(mm21, _mm_set1_epi8(0x80));

		return _mm_movemask_epi8(mm11 > mm21) -
				_mm_movemask_epi8(mm21 > mm11);
	}

	return 0;
}

/**
 * Compare 48 bytes between two locations.
 * Locations should not overlap.
 */
static inline int
rte_cmp48(const void *src_1, const void *src_2)
{
	int ret;

	ret = rte_cmp16((const uint8_t *)src_1 + 0 * 16,
			(const uint8_t *)src_2 + 0 * 16);

	if (unlikely(ret != 0))
		return ret;

	ret = rte_cmp16((const uint8_t *)src_1 + 1 * 16,
			(const uint8_t *)src_2 + 1 * 16);

	if (unlikely(ret != 0))
		return ret;

	return rte_cmp16((const uint8_t *)src_1 + 2 * 16,
			(const uint8_t *)src_2 + 2 * 16);
}

/**
 * Compare 64 bytes between two locations.
 * Locations should not overlap.
 */
static inline int
rte_cmp64(const void *src_1, const void *src_2)
{
	int ret;

	ret = rte_cmp16((const uint8_t *)src_1 + 0 * 16,
			(const uint8_t *)src_2 + 0 * 16);

	if (unlikely(ret != 0))
		return ret;

	ret = rte_cmp16((const uint8_t *)src_1 + 1 * 16,
			(const uint8_t *)src_2 + 1 * 16);

	if (unlikely(ret != 0))
		return ret;

	ret = rte_cmp16((const uint8_t *)src_1 + 2 * 16,
			(const uint8_t *)src_2 + 2 * 16);

	if (unlikely(ret != 0))
		return ret;

	return rte_cmp16((const uint8_t *)src_1 + 3 * 16,
			(const uint8_t *)src_2 + 3 * 16);
}

/**
 * Compare 128 bytes or its multiple between two locations.
 * Locations should not overlap.
 */
static inline int
rte_cmp128(const void *src_1, const void *src_2)
{
	int ret;

	ret = rte_cmp32((const uint8_t *)src_1 + 0 * 32,
			(const uint8_t *)src_2 + 0 * 32);

	if (unlikely(ret != 0))
		return ret;

	ret = rte_cmp32((const uint8_t *)src_1 + 1 * 32,
			(const uint8_t *)src_2 + 1 * 32);

	if (unlikely(ret != 0))
		return ret;

	ret = rte_cmp32((const uint8_t *)src_1 + 2 * 32,
			(const uint8_t *)src_2 + 2 * 32);

	if (unlikely(ret != 0))
		return ret;

	return rte_cmp32((const uint8_t *)src_1 + 3 * 32,
			(const uint8_t *)src_2 + 3 * 32);
}

/**
 * Compare 256 bytes between two locations.
 * Locations should not overlap.
 */
static inline int
rte_cmp256(const void *src_1, const void *src_2)
{
	int ret;

	ret = rte_cmp32((const uint8_t *)src_1 + 0 * 32,
			(const uint8_t *)src_2 + 0 * 32);

	if (unlikely(ret != 0))
		return ret;

	ret = rte_cmp32((const uint8_t *)src_1 + 1 * 32,
			(const uint8_t *)src_2 + 1 * 32);

	if (unlikely(ret != 0))
		return ret;

	ret = rte_cmp32((const uint8_t *)src_1 + 2 * 32,
			(const uint8_t *)src_2 + 2 * 32);

	if (unlikely(ret != 0))
		return ret;

	ret = rte_cmp32((const uint8_t *)src_1 + 3 * 32,
			(const uint8_t *)src_2 + 3 * 32);

	if (unlikely(ret != 0))
		return ret;

	ret = rte_cmp32((const uint8_t *)src_1 + 4 * 32,
			(const uint8_t *)src_2 + 4 * 32);

	if (unlikely(ret != 0))
		return ret;

	ret = rte_cmp32((const uint8_t *)src_1 + 5 * 32,
			(const uint8_t *)src_2 + 5 * 32);

	if (unlikely(ret != 0))
		return ret;

	ret = rte_cmp32((const uint8_t *)src_1 + 6 * 32,
			(const uint8_t *)src_2 + 6 * 32);

	if (unlikely(ret != 0))
		return ret;

	return rte_cmp32((const uint8_t *)src_1 + 7 * 32,
			(const uint8_t *)src_2 + 7 * 32);
}

/**
 * Compare bytes between two locations. The locations must not overlap.
 *
 * @param src_1
 *   Pointer to the first source of the data.
 * @param src_2
 *   Pointer to the second source of the data.
 * @param n
 *   Number of bytes to compare.
 * @return
 *   zero if src_1 equal src_2
 *   -ve if src_1 less than src_2
 *   +ve if src_1 greater than src_2
 */
static inline int
rte_memcmp(const void *_src_1, const void *_src_2, size_t n)
{
	const uint8_t *src_1 = (const uint8_t *)_src_1;
	const uint8_t *src_2 = (const uint8_t *)_src_2;
	int ret = 0;

	if (n < 16)
		return rte_memcmp_regular(src_1, src_2, n);

	if (n <= 32) {
		ret = rte_cmp16(src_1, src_2);
		if (unlikely(ret != 0))
			return ret;

		return rte_cmp16(src_1 - 16 + n, src_2 - 16 + n);
	}

	if (n <= 48) {
		ret = rte_cmp32(src_1, src_2);
		if (unlikely(ret != 0))
			return ret;

		return rte_cmp16(src_1 - 16 + n, src_2 - 16 + n);
	}

	if (n <= 64) {
		ret = rte_cmp32(src_1, src_2);
		if (unlikely(ret != 0))
			return ret;

		ret = rte_cmp16(src_1 + 32, src_2 + 32);

		if (unlikely(ret != 0))
			return ret;

		return rte_cmp16(src_1 - 16 + n, src_2 - 16 + n);
	}

	if (n <= 512) {
		if (n >= 256) {
			ret = rte_cmp256(src_1, src_2);
			if (unlikely(ret != 0))
				return ret;

			src_1 = src_1 + 256;
			src_2 = src_2 + 256;
			n -= 256;
		}

CMP_BLOCK_LESS_THAN_256:
		if (n >= 128) {
			ret = rte_cmp128(src_1, src_2);
			if (unlikely(ret != 0))
				return ret;

			src_1 = src_1 + 128;
			src_2 = src_2 + 128;
			n -= 128;
		}

		if (n >= 64) {
			ret = rte_cmp64(src_1, src_2);
			if (unlikely(ret != 0))
				return ret;

			src_1 = src_1 + 64;
			src_2 = src_2 + 64;
			n -= 64;
		}

		if (n >= 32) {
			ret = rte_cmp32(src_1, src_2);
			if (unlikely(ret != 0))
				return ret;
			src_1 = src_1 + 32;
			src_2 = src_2 + 32;
			n -= 32;
		}
		if (n > 16) {
			ret = rte_cmp16(src_1, src_2);
			if (unlikely(ret != 0))
				return ret;
			ret = rte_cmp16(src_1 - 16 + n, src_2 - 16 + n);
			return ret;
		}
		if (n > 0)
			ret = rte_cmp16(src_1 - 16 + n, src_2 - 16 + n);

		return ret;
	}

	for (; n >= 256; n -= 256) {
		ret = rte_cmp256(src_1, src_2);
		if (unlikely(ret != 0))
			return ret;

		src_1 = src_1 + 256;
		src_2 = src_2 + 256;
	}

	goto CMP_BLOCK_LESS_THAN_256;
}

#endif /* RTE_MACHINE_CPUFLAG_AVX2 */


#ifdef __cplusplus
}
#endif

#endif /* _RTE_MEMCMP_X86_64_H_ */