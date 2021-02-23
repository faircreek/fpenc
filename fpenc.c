/***************************************************************************
                                                                           *
                                                                           *
* fpenc is free software: you can                 *
  redistribute it and/or modify it under the terms of the                  *
  GNU Affero General Public License as published by the                    *
  Free Software Foundation, either version 3 of the License,               *
  or (at your option) any later version.                                   *
                                                                           *
* fpenc is distributed in the hope                *
  that it will be useful, but WITHOUT ANY WARRANTY; without even the       *
  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. *
  See the GNU Affero General Public License for more details.              *
                                                                           *
                                                                           *
***************************************************************************/

#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include "miracl.h"

#define UINT32 mr_unsign32	/* 32-bit unsigned type */
#define W 8			/* recommended number of rounds */
#define BLOCK_SIZE 16		/* 16 Byte Blocks - AES */
#define ENCRYPT 0
#define DECRYPT 1



int main(int argc, char *argv[])
{
	int i, radix, array;
	aes a;
	bool decrypt = false;
	bool encrypt = false;
	bool generate = false;
	bool verbose = false;
	bool aes_set  = false;
	bool aok = false;
	UINT32 TL, TR = 0 ;
	int tweak;
	int sw;
	char *passphrase = NULL;
	char *salt = NULL;
	char *raw = NULL;
	char *ahex = NULL;
	char *p;
        unsigned char *result, *r;
        unsigned int c;
	int cnt;
	static unsigned char aes_key[32];
	char data[256];
	char data2[256];

	while ((sw = getopt(argc, argv, "degvp:s:r:t:a:")) != -1) {
		switch (sw) {
		case 'd':
			decrypt = true;
			break;
		case 'e':
			encrypt = true;
			break;
		case 'g':
			generate = true;
			break;
		case 'v':
			verbose = true;
			break;
		case 'p':
			passphrase = optarg;
			break;
		case 's':
			salt = optarg;
			break;
		case 'r':
			raw = optarg;
			break;
		case 't':
			tweak = atoi(optarg);
			if ( tweak >= UINT32_MAX) {
				fprintf(stderr,"Usage: tweak too large, max is %d\n", (int)UINT32_MAX);
				return EXIT_FAILURE;
			}
			TR = (UINT32)tweak;
			break;
		case 'a':
			ahex = optarg;
			aes_set = true;
			break;
		default:
			fprintf(stderr,
				"Usage: %s -p <passphrase> -s <salt> -t <tweak> -b <block-size>\n",
				argv[0]);
			return EXIT_FAILURE;
		}
	}

	if ((passphrase != NULL) && (salt != NULL) && generate)
		aok=true;
	
	if ((aes_set | ((passphrase != NULL) && (salt != NULL))) && (decrypt | encrypt) &&  (raw != NULL))
		aok=true;


	if (aok != true){
		fprintf(stderr,
			"Usage Error See code for help :) %s\n",
			argv[0]);
		return EXIT_FAILURE;
	}




	if (aes_set) {

		cnt = (strlen(ahex) + 1) / 2; 
		result = (unsigned char *)malloc(cnt);
		for (p = ahex, r = result; *p; p += 2) {
	    		if (sscanf(p, "%02X", (unsigned int *)&c) != 1) {
				*r++ = '\0';
	        		break; 
	    		}
	    		*r++ = c;
		}
		if (verbose) {
			printf("Using supplied AES_KEY\n");	
	        	printf("Hexphrase : ");
	        	print_hex((char*)result, strlen(result));
			printf("\n");
		}
		strcpy(aes_key, result);
		/* free(result);*/

	} else {

		if (verbose) {
			printf("Using generated AES_KEY\n");
			printf("Passphrase: %s (", passphrase);
			print_hex(passphrase, strlen(passphrase));
			printf(")\n");
			printf("Salt      : %s (", salt);
			print_hex(salt, strlen(salt));
			printf(")\n");
		}
	
		if (PKCS5_PBKDF2_HMAC_SHA1
		    (passphrase, strlen(passphrase), (unsigned char *)salt,
		     strlen(salt), 1000, 256, aes_key) != 1) {
			fprintf(stderr, "Generating PBKDF2 AES key has been failed.\n");
			return EXIT_FAILURE;
		}
		if(generate){
			if (verbose)
				printf("\n256 bit aes key= ");
			for (i = 0; i < 32; i++)
				printf("%02x", (unsigned char)aes_key[i]);
			printf("\n");
			return 0;
		}

	}



	radix = 10;
	TL = 0xD8E7920A;
	if (TR != 0 && verbose) 
		printf("TR %d\n", (int)TR);
	if ( TR == 0 ) {
		TR = 0xFA330A73;	/* random tweaks */
	}

	if(verbose) {
		printf("AES Key   : ");
		print_hex((char *)aes_key, 32);
		printf("\n");
		printf("RAW Data  : ");
		print_hex(raw, strlen(raw));
		printf("\n");
		printf("String    : %s\n", raw);
		if (aes_set)
			printf("Ahex      : %s\n", ahex);

	}	

	aes_init(&a, MR_ECB, 32, (char *)aes_key, NULL);


	/* Make our string to decrypt or encrypt into a interger array */
	strcpy(data, raw);
	array = strlen(raw);
	for (i = 0; i < array; i++) {
		data2[0] = raw[i];
		data2[1] = '\0';
		data[i] = atoi(data2);
	}




	/* Encrypt/decrypt int array */

	
	if(verbose){
		printf("Input=\n");
		for (i = 0; i < array; i++)
			printf("%d", data[i]);
		printf("\n");
	}


	if(encrypt){
		FPE_encrypt(radix, &a, TL, TR, data, array);
		if(verbose)
			printf("Encrypted=\n");
		for (i = 0; i < array; i++)
			printf("%d", data[i]);
		printf("\n");
	}

	if(decrypt){
		FPE_decrypt(radix, &a, TL, TR, data, array);
		if(verbose)
			printf("Decrypted=\n");
		for (i = 0; i < array; i++)
			printf("%d", data[i]);
		printf("\n");
	}

	return 0;
}
