#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include "aes.h"
#include "aes_omac.h"

#include "mt19937.h"
#include "types.h"

unsigned char patch_magic[4] =  { 0x1B, 0x2D, 0x70, 0x0F };
unsigned char system_magic[4] = { 0x73, 0x79, 0x73, 0x31 };

unsigned char cipher_key[0x10];
unsigned char hasher_key[0x10];
unsigned char seed[0x10];

unsigned char patch_master_key[0x10] = { 0x5E, 0x7C, 0xD1, 0x6A, 0x78, 0x44, 0x39, 0x28, 0x12, 0x06, 0x88, 0xD7, 0x88, 0x34, 0x93, 0xF1 };
unsigned char patch_cipher_xor[0x10] = { 0xD6, 0xDD, 0x7D, 0x29, 0xB4, 0xF5, 0x5B, 0x31, 0x80, 0x91, 0x82, 0x1C, 0xF7, 0xC8, 0x4A, 0x3C };
unsigned char patch_hasher_xor[0x10] = { 0x18, 0x28, 0x37, 0x4D, 0x62, 0x47, 0x74, 0xAF, 0x01, 0x44, 0x53, 0x5D, 0xE5, 0x4F, 0xF1, 0x0F };
unsigned char patch_xorseed[0x10] = { 0x0B, 0x3C, 0x10, 0xFF, 0x47, 0xFC, 0x9D, 0x34, 0x37, 0xCA, 0x80, 0x95, 0x2C, 0xAE, 0x91, 0x70 };

unsigned char patch_master_key_proto[0x10] = { 0x98, 0xAC, 0x53, 0x39, 0x19, 0x01, 0x11, 0x4C, 0x34, 0xD6, 0xC3, 0x40, 0x21, 0x26, 0x03, 0x69 };
unsigned char patch_cipher_xor_proto[0x10] = { 0x54, 0x82, 0xA9, 0x48, 0x6E, 0x9D, 0x02, 0x32, 0xE5, 0x36, 0x7E, 0x59, 0xC9, 0x75, 0x06, 0x6A };
unsigned char patch_hasher_xor_proto[0x10] = { 0xD1, 0x26, 0x94, 0x3C, 0x33, 0x04, 0x27, 0x08, 0x80, 0x0B, 0xE8, 0xA8, 0x9A, 0xED, 0xC9, 0xFF };
unsigned char patch_xorseed_proto[0x10] = { 0x10, 0xA6, 0x65, 0x12, 0x05, 0x46, 0xC3, 0xFD, 0xDC, 0x81, 0xE2, 0x04, 0x50, 0x05, 0x8C, 0x90 };

unsigned char system_master_key[0x10] = { 0x97, 0xDA, 0xAC, 0x1F, 0x96, 0x40, 0xF5, 0x76, 0xA5, 0x3E, 0xCE, 0x93, 0xC9, 0x2B, 0x17, 0xF2 };
unsigned char system_cipher_enc[0x10] = { 0x42, 0x8D, 0x64, 0x3E, 0x54, 0xC7, 0x6B, 0xAE, 0xD8, 0x42, 0x89, 0x07, 0xB1, 0x95, 0x2F, 0xC7 };
unsigned char system_hasher_enc[0x10] = { 0xE6, 0xAF, 0x3D, 0xCE, 0xAA, 0x1F, 0x41, 0x85, 0xD3, 0x44, 0xCB, 0xCE, 0xDC, 0xBC, 0x28, 0x0F };

unsigned char iv[0x10] =      { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char digest[0x10] =  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

typedef struct
{
	unsigned short major_version;
	unsigned short minor_version;
	unsigned short patch;
	unsigned short revision;
} mullion_patch_hdr_t;


typedef struct
{
	unsigned int   magic;
	unsigned short major_version;
	unsigned short minor_version;
	unsigned short rev;
	unsigned short sys_rev;
	unsigned int   table;
	unsigned short datsize;
	unsigned short datsum;
	unsigned short sum;
} sherwood_patch_hdr_t;


void hexdump(const char* name, unsigned char* buf, int len)
{
	int i, j, align = strlen(name) + 1;

	printf("%s ", name);
	for (i = 0; i < len; i++)
	{
		if (i % 16 == 0 && i != 0)
		{
			printf("\n");
			for (j = 0; j < align; j++)
				putchar(' ');
		}
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

void xorbuf(unsigned char* buf1, unsigned char* buf2, int len)
{
	for (int i = 0; i < len; i++)
		buf1[i] = buf1[i] ^ buf2[i];
}

static mt19937_ctxt_t _mt19937_ctxt;
static bool _mt_init = FALSE;

u8 get_rand_byte()
{
	if (_mt_init == FALSE)
	{
		_mt_init = TRUE;
		mt19937_init(&_mt19937_ctxt, (unsigned int)time(NULL));
	}

	return (u8)(mt19937_update(&_mt19937_ctxt) & 0xFF);
}

void fill_rand_bytes(u8* dst, u32 len)
{
	u32 i;

	for (i = 0; i < len; i++)
		dst[i] = get_rand_byte();
}

bool generate_keys(const char* sc_type, const char* fw_type, const char* soft_id)
{
	if (strlen(soft_id) != 4 )
		return false;

	memset(seed, 0, 0x10);
	if (!strcmp(sc_type, "1"))
	{
		printf("sc_type: Mullion\n");
		sprintf((char*)seed, "4:");
		sprintf((char*)seed + 2, "%04d", strtoul(soft_id, NULL, 16));
		sprintf((char*)seed + 6, "__SCEISYS1");
	}
	else if (!strcmp(sc_type, "2"))
	{
		printf("sc_type: Sherwood\n");
		memcpy(seed, soft_id, 4);
		sprintf((char*)seed + 4, "____SCEISYS1");
	}
	else if (!strcmp(sc_type, "3"))
	{
		printf("sc_type is Sherwood Prototype\n");
		memcpy(seed, soft_id, 4);
		sprintf((char*)seed + 4, "____SCEISYS1");

	}
	else
	{
		printf("sc_type is Unknown\n");
		return false;
	}

	if (!strcmp(fw_type, "1"))
	{
		printf("fw_type is Patch\n");
		memcpy(cipher_key, seed, 0x10);
		memcpy(hasher_key, seed, 0x10);
		aes_context aes_ctxt;
		if(!strcmp(sc_type, "3"))
		{
			xorbuf(cipher_key, patch_xorseed_proto, 0x10);
			xorbuf(hasher_key, patch_xorseed_proto, 0x10);
			xorbuf(cipher_key, patch_cipher_xor_proto, 0x10);
			xorbuf(hasher_key, patch_hasher_xor_proto, 0x10);
			aes_setkey_enc(&aes_ctxt, patch_master_key_proto, 128);
		}
		else
		{
			xorbuf(cipher_key, patch_xorseed, 0x10);
			xorbuf(hasher_key, patch_xorseed, 0x10);
			xorbuf(cipher_key, patch_cipher_xor, 0x10);
			xorbuf(hasher_key, patch_hasher_xor, 0x10);
			aes_setkey_enc(&aes_ctxt, patch_master_key, 128);
		}

		aes_crypt_ecb(&aes_ctxt, AES_ENCRYPT, cipher_key, cipher_key);
		aes_crypt_ecb(&aes_ctxt, AES_ENCRYPT, hasher_key, hasher_key);
		hexdump("cipher_key", cipher_key, 0x10);
		hexdump("hasher_key", hasher_key, 0x10);
		return true;
	}
	else if (!strcmp(fw_type, "2"))
	{
		printf("fw_type is System\n");
		aes_context aes_ctxt;
		aes_setkey_dec(&aes_ctxt, system_master_key, 128);
		aes_crypt_ecb(&aes_ctxt, AES_DECRYPT, system_cipher_enc, cipher_key);
		aes_crypt_ecb(&aes_ctxt, AES_DECRYPT, system_hasher_enc, hasher_key);
		hexdump("cipher_key", cipher_key, 0x10);
		hexdump("hasher_key", hasher_key, 0x10);
		return true;
	}
	else
	{
		printf("fw_type is Unknown\n");
		return false;
	}
}

unsigned short get_csum(unsigned char* data, unsigned int size)
{
	if ((data == NULL) || (size == 0))
		return 0;

	unsigned char * ptr;
	unsigned short csum;
	unsigned int i;

	ptr = (unsigned char*)data;
	csum = 0;

	for (i = 0; i < size; ++i)
		csum += ptr[i];

	return csum;
}

bool decrypt(FILE* input, FILE* output, const char* sc_type, const char* fw_type, const char* soft_id)
{
	size_t binary_size, payload_size;
	// Get file size.
	fseek(input, 0, SEEK_END);
	size_t input_size = ftell(input);
	fseek(input, 0, SEEK_SET);

	if (input_size < 0x50)
		return false;

	unsigned char* header = (unsigned char*)malloc(0x40);
	unsigned char* expected = (unsigned char*)malloc(0x10);
	if ((header == NULL) || (expected == NULL))
		return false;

	memset (header, 0, 0x40);
	memset (expected, 0, 0x10);
	fread (header, 1, 0x40, input);
	fseek(input, 0, SEEK_SET);
	
	memcpy(expected, header + 0x14, 0x10);
	memset (header + 0x14, 0, 0x10);
	aes_omac1(digest, header, 0x40, hasher_key, 128);

	if (!memcmp(digest, expected, 0x10))
		printf("header digest  OK\n");
	else
	{
		printf("header digest  NG!\n");
		return false;
	}
	binary_size = *(size_t*)&header[0x28];   //LE
	if (binary_size < 0x40)
		return false;

	payload_size = *(size_t*)&header[0x2C];  //LE
	unsigned char* binary = (unsigned char*)malloc(binary_size);
	if (binary == NULL)
		return false;

	fread(binary, 1, binary_size, input);

	memcpy(expected, binary + 4, 0x10);
	memcpy(iv, header + 0x30, 0x10);

	memcpy(binary + 0x10, binary, 4);
	memset(binary + 0x14, 0, 0x10);
	memset(digest, 0, 0x10);
	aes_omac1(digest, binary + 0x10, payload_size + 0x30, hasher_key, 128);

	if (!memcmp(digest, expected, 0x10))
		printf("payload digest OK\n");
	else
	{
		printf("payload digest NG!\n");
		return false;
	}

	aes_context aes_ctxt;
	aes_setkey_dec(&aes_ctxt, cipher_key, 128);
	aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, payload_size, iv, binary+0x40, binary + 0x40);

	//Parse decrypted patch
	if (!strcmp(fw_type, "1")) //fw_type patch
	{
		printf("patchinfo:\n");
		if (!strcmp(sc_type, "1")) //mullion
		{
			mullion_patch_hdr_t* mln_hdr;
			mln_hdr = (mullion_patch_hdr_t *)(binary + 0x40);
			printf("major:0x%04X\n", mln_hdr->major_version);
			printf("minor:0x%04X\n", mln_hdr->minor_version);
			printf("patch:0x%04X\n", mln_hdr->patch);
			printf("revision:0x%04X\n", mln_hdr->revision);
		}
		else //sherwood
		{
			sherwood_patch_hdr_t* sw_hdr;
			sw_hdr = (sherwood_patch_hdr_t *)(binary + 0x40);
			printf("MAJOR   :0x%04X\n", sw_hdr->major_version);
			printf("MINOR   :0x%04X\n", sw_hdr->minor_version);
			printf("REV     :0x%04X\n", sw_hdr->rev);
			printf("SYS_REV :0x%04X\n", sw_hdr->sys_rev); //must be matched to the soft_id
			printf("TABLE   :0x%08X\n", sw_hdr->table);
			printf("DATSIZ  :0x%04X\n", sw_hdr->datsize);
			printf("DATSUM  :0x%04X\n", sw_hdr->datsum);
			printf("SUM     :0x%04X\n", sw_hdr->sum);

			// check softid
			if ((strtoul(soft_id, NULL, 16)) != sw_hdr->sys_rev)
			{
				printf("SYS_REV NG!\n");
				return false;
			}
			else
				printf("SYS_REV OK\n");

			//validate header checksum
			if(get_csum(binary+ 0x40, 0x14) != sw_hdr->sum)
			{
				printf("SUM     NG!\n");
				return false;
			}
			else
				printf("SUM     OK\n");

			//validate data checksum
			if (get_csum(binary +0x40 +0x16, sw_hdr->datsize) != sw_hdr->datsum)
			{
				printf("DATSUM  NG!\n");
				return false;
			}
			else
				printf("DATSUM  OK\n");
		}
	}

	fwrite(binary + 0x40, 1, payload_size, output);

	free(expected);
	free(binary);
	free(header);
	return true;
}

bool encrypt(FILE* input, FILE* output, const char* sc_type, const char* fw_type, const char* soft_id)
{
	size_t binary_size, payload_size;
	// Get file size.
	fseek(input, 0, SEEK_END);
	size_t input_size = ftell(input);
	fseek(input, 0, SEEK_SET);

	if (input_size < 0x10)
		return false;

	if ((input_size & 0xF) != 0)
		return false;

	payload_size = input_size;
	binary_size = input_size + 0x40;

	unsigned char* binary = (unsigned char*)malloc(binary_size);
	if (binary == NULL)
		return false;

	memset(binary, 0, binary_size);
	fread(binary + 0x40, 1, payload_size, input);

	//parse patch
	if (!strcmp(fw_type, "1")) //fw_type patch
	{
		printf("patchinfo:\n");
		if (!strcmp(sc_type, "1")) //mullion
		{
			mullion_patch_hdr_t* mln_hdr;
			mln_hdr = (mullion_patch_hdr_t*)(binary + 0x40);
			printf("major:0x%04X\n", mln_hdr->major_version);
			printf("minor:0x%04X\n", mln_hdr->minor_version);
			printf("patch:0x%04X\n", mln_hdr->patch);
			printf("revision:0x%04X\n", mln_hdr->revision);
		}
		else //sherwood
		{
			sherwood_patch_hdr_t* sw_hdr;
			sw_hdr = (sherwood_patch_hdr_t*)(binary + 0x40);

			// fix softid and checksums before to encrypt the payload
			sw_hdr->sys_rev = (unsigned short)strtoul(soft_id, NULL, 16);
			sw_hdr->datsum = get_csum(binary + 0x40 + 0x16, sw_hdr->datsize);
			sw_hdr->sum = get_csum(binary + 0x40, 0x14);

			printf("MAJOR   :0x%04X\n", sw_hdr->major_version);
			printf("MINOR   :0x%04X\n", sw_hdr->minor_version);
			printf("REV     :0x%04X\n", sw_hdr->rev);
			printf("SYS_REV :0x%04X\n", sw_hdr->sys_rev); //must be matched to the soft_id
			printf("TABLE   :0x%08X\n", sw_hdr->table);
			printf("DATSIZ  :0x%04X\n", sw_hdr->datsize);
			printf("DATSUM  :0x%04X\n", sw_hdr->datsum);
			printf("SUM     :0x%04X\n", sw_hdr->sum);
		}
	}

	fill_rand_bytes(binary + 0x30, 0x10);
	memcpy(iv, binary + 0x30, 0x10);
	aes_context aes_ctxt;
	aes_setkey_enc(&aes_ctxt, cipher_key, 128);
	aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, payload_size, iv, binary + 0x40, binary + 0x40);

	if (!strcmp(fw_type, "1")) //fw_type patch
		memcpy(binary + 0x10, patch_magic, 4);
	else
		memcpy(binary + 0x10, system_magic, 4);

	*(size_t*)&binary[0x28] = binary_size;
	*(size_t*)&binary[0x2C] = payload_size;
	memset(digest, 0, 0x10);
	aes_omac1(digest, binary + 0x10, payload_size + 0x30, hasher_key, 128);

	if (!strcmp(fw_type, "1")) //fw_type patch
		memcpy(binary, patch_magic, 4);
	else
		memcpy(binary, system_magic, 4);
	
	memcpy(binary + 4, digest, 0x10);
	memset(digest, 0, 0x10);
	aes_omac1(digest, binary, 0x40, hasher_key, 128);
	memcpy(binary + 0x14, digest, 0x10);

	fwrite(binary, 1, binary_size, output);

	free(binary);
	return true;
}

void print_usage()
{
	printf("Usage: ps3_sc_update <mode> <input> <output> <sc_type> <update_type> <soft_id> \n");
	printf("<mode>:   -d - Decryption mode\n");
	printf("          -e - Encryption mode\n");
	printf("<input>:   input file name\n");
	printf("<output>:  output file name\n");
	printf("<sc_type>: 1 - Mullion\n");
	printf("           2 - Sherwood\n");
	printf("           3 - Sherwood Prototype\n");
	printf("<fw_type>: 1 - Patch\n");
	printf("           2 - System\n");
	printf("<soft_id>: 4 hex symbols, 0B8E for example\n");
}

int main(int argc, char** argv)
{
	if (argc < 6)
	{
		print_usage();
		return 0;
	}

	if ((!strcmp(argv[1], "-d")) && (argc == 7))
	{
		const char* input_name = argv[2];
		const char* output_name = argv[3];
		const char* sc_type = argv[4];
		const char* fw_type = argv[5];
		const char* soft_id = argv[6];
		FILE* input = fopen(input_name, "rb");

		if (input == NULL)
		{
			printf("ERROR: Please check the input file!\n");
			return -1;
		}

		if (generate_keys(sc_type, fw_type, soft_id) == false)
			return -1;

		FILE* output = fopen(output_name, "wb+");

		if (decrypt(input, output, sc_type, fw_type, soft_id) == false)
		{
			printf("ERROR: Decrypt failed!\n");
			fclose(input);
			fclose(output);
			remove(output_name);
			return -1;
		}

		printf("SUCCESS!\n");
		return 0;
	}

	if ((!strcmp(argv[1], "-e")) && (argc == 7))
	{
		const char* input_name = argv[2];
		const char* output_name = argv[3];
		const char* sc_type = argv[4];
		const char* fw_type = argv[5];
		const char* soft_id = argv[6];
		FILE* input = fopen(input_name, "rb");
		if (input == NULL)
		{
			printf("ERROR: Please check the input file!\n");
			return -1;
		}

		if (generate_keys(sc_type, fw_type, soft_id) == false)
			return -1;
		
		FILE* output = fopen(output_name, "wb+");

		if (encrypt(input, output, sc_type, fw_type, soft_id) == false)
		{
			printf("ERROR: Encrypt failed!\n");
			fclose(input);
			fclose(output);
			remove(output_name);
			return -1;
		}
		printf("SUCCESS!\n");
		return 0;
	}

	print_usage();

	return 0;
}