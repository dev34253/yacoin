/* Copyright (c) 2026 The Yacoin developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Second reference for the block-header hash known answers (task P0-19):
 * a driver for the UPSTREAM scrypt-jane, not the copy in src/scrypt-jane.
 *
 *   refhash <Nfactor> <hex input>
 *
 * prints scrypt-jane(password = salt = input, Nfactor, rfactor 0,
 * pfactor 0) as 32 bytes hex, in memory order (header_hash_vectors.py
 * reverses it to uint256::GetHex() order). Build:
 *
 *   git clone https://github.com/floodyberry/scrypt-jane
 *   git -C scrypt-jane checkout 0ab61258544b8a8dae2be7067626660266a815c0
 *   gcc -O3 -DSCRYPT_KECCAK512 -DSCRYPT_CHACHA -Iscrypt-jane \
 *       scrypt-jane/scrypt-jane.c contrib/testing/scrypt_jane_refhash.c \
 *       -o refhash
 *
 * Used by: contrib/testing/header_hash_vectors.py --reference ./refhash
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "scrypt-jane.h"

int main(int argc, char **argv)
{
	unsigned char in[256], out[32];
	size_t n, i;
	int nfactor;

	if (argc != 3 || strlen(argv[2]) % 2 != 0 || strlen(argv[2]) / 2 > sizeof(in)) {
		fprintf(stderr, "usage: %s <Nfactor 0..30> <hex input, at most 256 bytes>\n", argv[0]);
		return 2;
	}
	nfactor = atoi(argv[1]);
	if (nfactor < 0 || nfactor > 30) {
		fprintf(stderr, "Nfactor out of range\n");
		return 2;
	}
	n = strlen(argv[2]) / 2;
	for (i = 0; i < n; i++) {
		if (sscanf(argv[2] + 2 * i, "%2hhx", &in[i]) != 1) {
			fprintf(stderr, "bad hex\n");
			return 2;
		}
	}
	scrypt(in, n, in, n, (unsigned char)nfactor, 0, 0, out, sizeof(out));
	for (i = 0; i < sizeof(out); i++)
		printf("%02x", out[i]);
	printf("\n");
	return 0;
}
