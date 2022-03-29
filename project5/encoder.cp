#include "encoder.h"
#include "server.h"
#include "stopwatch.h"
#include <fstream>
#include <iterator>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <bits/stdc++.h>
#include <vector>
#include <memory.h>
#include <cstring>
#include <fstream>
#include <math.h>

#define NUM_PACKETS 8
#define pipe_depth 4
#define DONE_BIT_L (1 << 7)
#define DONE_BIT_H (1 << 15)
#define MAX_CHUNK_NUM 80

//CDC
#define WIN_SIZE 16
#define PRIME 3
#define MODULUS 256
#define TARGET 0

using namespace std;

//SHA
/**************************** DATA TYPES ****************************/
#define SHA256_BLOCK_SIZE 32 // SHA256 outputs a 32 byte digest
#define MAX_DEPTH  (20)
#define ASCII_SIZE (256)
/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE; // 8-bit byte
typedef unsigned int WORD;	// 32-bit word, change to "long" for 16-bit machines

typedef struct
{
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
uint64_t hash_func(unsigned char *input, unsigned int pos);
void cdc(unsigned char *buff, unsigned int buff_size);
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, BYTE hash[]);
int deduplication(unsigned char *buff, int chunk_num);
void LZWencoding(string s1);
void compress(const unsigned char* chunk, int* result, int* R);

/**************************** DATA TYPES ****************************/

BYTE sha256[SHA256_BLOCK_SIZE];
int SHA_Table[MAX_CHUNK_NUM][3];
BYTE SHA_data[MAX_CHUNK_NUM][SHA256_BLOCK_SIZE];

//LZW
unordered_map<string, int> table;
unordered_map<int, int> saved_idx;

//variable
int chunk_num = 0;
int offset = 0;
unsigned char *file;
int chunk_offset = 0;
int total_bytes = 0;

void handle_input(int argc, char *argv[], int *payload_size)
{
	int x;
	extern char *optarg;

	while ((x = getopt(argc, argv, ":c:")) != -1)
	{
		switch (x)
		{
		case 'c':
			*payload_size = atoi(optarg);
			printf("payload_size is set to %d optarg\n", *payload_size);
			break;
		case ':':
			printf("-%c without parameter\n'", optopt);
			break;
		}
	}
}

/*********************************************************************
* Filename:   sha256.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Implementation of the SHA-256 hashing algorithm.
              SHA-256 is one of the three algorithms in the SHA2
              specification. The others, SHA-384 and SHA-512, are not
              offered in this implementation.
              Algorithm specification can be found here:
               * http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf
              This implementation uses little endian byte order.
*********************************************************************/

/*************************** HEADER FILES ***************************/

/****************************** MACROS ******************************/
#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
static const WORD k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/*********************** FUNCTION DEFINITIONS ***********************/
void sha256_transform(SHA256_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for (; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i)
	{
		t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len)
{
	WORD i;

	for (i = 0; i < len; ++i)
	{
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64)
		{
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

void sha256_final(SHA256_CTX *ctx, BYTE hash[])//#include "LZWtree.h"
{
	WORD i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56)
	{
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else
	{
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i)
	{
		hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

uint64_t hash_func(unsigned char *input, unsigned int pos)
{
	uint64_t hash = 0;
	for (int i = 0; i < 16; i++)
	{
		hash += ((input[pos + WIN_SIZE - 1 - i]) * (pow(PRIME, i + 1)));
	}
	return hash;
}

void cdc(unsigned char *buff, unsigned int buff_size)
{
	int First_Index = 0;
	int Last_Index = 0;

	for (unsigned int i = 16; i < (buff_size - 16); i += 1)
	{
		uint64_t hash = hash_func(buff, i);
		if ((hash % MODULUS) == TARGET)
		{
			Last_Index = i;

			if (chunk_num < MAX_CHUNK_NUM)
			{
                		uint32_t cur_chunk_length = Last_Index - First_Index + 1;
				unsigned char cur_chunk[cur_chunk_length], LZWrcode[cur_chunk_length];
				//memcpy(&buff[First_Index], &cur_chunk[0], Last_Index-First_Index+2);
				//cout << cur_chunk << endl;
				int counter = First_Index;
				printf("\n-------------------------------------\n");
				for (int i = 0; i < Last_Index - First_Index + 1; i++)
				{
					cur_chunk[i] = buff[counter];
					cout << buff[counter];
					counter++;
				}
				printf("\n-------------------------------------\n");
				SHA_Table[chunk_num][0] = chunk_num;

				SHA256_CTX ctx;
				sha256_init(&ctx);
				sha256_update(&ctx, cur_chunk, cur_chunk_length);
				sha256_final(&ctx, sha256);

				for (int i = 0; i < SHA256_BLOCK_SIZE; i++)
				{
					SHA_data[chunk_num - chunk_offset][i] = sha256[i];
					//printf("%0x",SHA_data[chunk_num][i]);
				}
				// cout  << endl;

				SHA_Table[chunk_num][1] = Last_Index;
				SHA_Table[chunk_num][2] = First_Index;

				// std::string str(cur_chunk, cur_chunk + Last_Index - First_Index + 1);
				// LZWencoding(str);

				//printf("chunk_num:%d\tidx:%d-%d\n", chunk_num, First_Index, Last_Index);
				//printf("\n======================================\n");
                int chunk_appear = deduplication(buff, chunk_num);
				if (chunk_appear == -1)
				{
                    //header lzw chunk

					//printf("write file with %d\nlen:%d\tfliped:%d\tbyte: %0x, %0x, %0x, %0x\n", bytes_written,cur_chunk_length,fliped_cur_chunk_length, bytes[0],bytes[1],bytes[2],bytes[3]);
					//std::string str(cur_chunk, cur_chunk + sizeof(cur_chunk)/sizeof(cur_chunk[0]));
					//LZWencoding(str);
					int len[1]; len[0] = 0;
					int result1[cur_chunk_length];
					compress(cur_chunk,result1, len);
					//unsigned char bytes[4];
					//uint32_t fliped_saved_size = 4*(saved_idx.size());
					//printf("dict int size %d, dict in byte size %d\n",saved_idx.size(),fliped_saved_size);
					//compress(cur_chunk, END);
                    			//fliped_saved_size = fliped_saved_size << 1;

					FILE *outfd = fopen("output_cpu.bin", "ab");
					//bytes[3] = (fliped_saved_size >> 24);
					///bytes[2] = (fliped_saved_size >> 16);
					//bytes[1] = (fliped_saved_size >> 8);
					//bytes[0] = fliped_saved_size;
                    			//int bytes_written = fwrite(&fliped_saved_size, 4, 1, outfd);
/*
					int get = 0;
					while(get < saved_idx.size()){
						
						uint32_t temp = (uint32_t)saved_idx[get];
						printf("%d\t\t", temp);
						unsigned char bytes[2];
						if(temp > 65535) cout << "EEEEEEEERRRRRRRRORRRRRRRRRRRRRR\n" << endl;
						bytes[0] = (temp >> 8);
						bytes[1] = (temp) ;
						int bytes_written = fwrite(&bytes, 1, 2, outfd);

						total_bytes = bytes_written + total_bytes;
						get++;

					}
*/
				uint32_t Header = (uint32_t) (len[0]*2) << 1; 
				int bytes_written = fwrite((void*) &Header, sizeof(uint32_t), 1, outfd);
				printf("R = %d\n", len[0]);
				int result[len[0]];
				for(int i = 0; i < len[0]; i++){
					unsigned char temp_result[2];
					result[i] = result1[i];
					temp_result[1] = result1[i];
					temp_result[0] = result1[i] >> 8;
					int bytes_written = fwrite(&temp_result, sizeof(unsigned char), 2, outfd); 
					total_bytes = bytes_written + total_bytes;
				}
					cout << endl;
					fclose(outfd);
					saved_idx.clear();
                }else{
					unsigned char bytes[4];
					uint32_t fliped_chunk_appear = chunk_appear;
				    //deduplication header
				    //fliped_chunk_appear = fliped_chunk_appear << 1;
				    //fliped_chunk_appear++;
					bytes[3] = (fliped_chunk_appear >> 24);
					bytes[2] = (fliped_chunk_appear >> 16) ;
					bytes[1] = (fliped_chunk_appear >> 8);
					bytes[0] = fliped_chunk_appear;
					bytes[0] |= 0x01;

                    FILE *outfd = fopen("output_cpu.bin", "ab");
                    int bytes_written = fwrite(&bytes, sizeof(unsigned char), 4, outfd);
                    fclose(outfd);
					total_bytes = bytes_written + total_bytes;
					printf("deduplicate with::::\nbyte: %0x, %0x, %0x, %0x\n", bytes[0],bytes[1],bytes[2],bytes[3]);
                }

				chunk_num++;
				First_Index = Last_Index + 1;
			}
			else
			{
				cout << "out of chunk number" << endl;
			}
		}
	}
}

int deduplication(unsigned char *buff, const int chunk_num)
{

	if (chunk_num != 0)
	{
		for (int i = 0; i < chunk_num; i++)
		{
			int check_sum = 0;
			if (SHA_data[chunk_num - chunk_offset] == NULL || SHA_data[i] == NULL)
				break;
			//cout << "a\t"<< SHA_data[chunk_num][0] << endl << "b\t" << SHA_data[i][0] << endl;
			BYTE a[SHA256_BLOCK_SIZE], b[SHA256_BLOCK_SIZE];
			// printf("compare time:%d", i + 1);
			// printf("\na:\t");
			for (int j = 0; j < SHA256_BLOCK_SIZE; j++)
			{
				a[j] = SHA_data[chunk_num - chunk_offset][j];
				b[j] = SHA_data[i][j];
				if (SHA_data[chunk_num - chunk_offset][j] == SHA_data[i][j])
					check_sum++;
				//printf("%0x", a[j]);
			}
			// printf("\nb:\t");
			// for (int j = 0; j < SHA256_BLOCK_SIZE; j++)
			// {
			// 	printf("%0x", b[j]);
			// }
			// printf("\n++++++++++++++++++++++++++++++++++++\n");
			if (check_sum == SHA256_BLOCK_SIZE)
			{

				//int len = strlen(SHA_Table[0][chunk_num-chunk_offset]);
				//chunk_offset = chunk_offset+1;

				SHA_Table[chunk_num][0] = SHA_Table[i][0];
				SHA_Table[chunk_num][1] = SHA_Table[i][1];
				SHA_Table[chunk_num][2] = SHA_Table[i][2];

				// for (int i = 0; i < SHA256_BLOCK_SIZE; ++i)
				// 	SHA_data[chunk_num][i] = 0x00;
				chunk_offset++;
				// printf("\nchunk_num:%d is exist in\t%d\toffset\t", chunk_num, i);
				// cout << chunk_offset << endl;
				return i;
			}
		}
	}
	return -1;
}

void LZWencoding(string s1)
{
    //cout << "Encoding\n";

    for (int i = 0; i <= 255; i++) {
        string ch = "";
        ch += char(i);
        table[ch] = i;
    }

    string p = "", c = "";
    p += s1[0];
    int code = 256;
	int idx = 0;
    //vector<int> output_code;
    //cout << "String\tOutput_Code\tAddition\n";
    for (int i = 0; i < s1.length(); i++) {
        if (i != s1.length() - 1)
            c += s1[i + 1];
        if (table.find(p + c) != table.end()) {
            p = p + c;
        }
        else {
			saved_idx[idx] = table[p];
			idx++;
            table[p + c] = code;
            code++;
            p = c;
        }
        c = "";
    }
    //cout << p << "\t" << table[p] << endl;
}

void compress(const unsigned char* chunk, int* result, int* R)
{
    string str;
    str.append(reinterpret_cast<const char*>(chunk));
    map<string, int>dictionary;
    int dictionary_size = 256;
    for (int i = 0; i <= dictionary_size; i++) {
        string content = "";
        content += char(i);
        dictionary[content] = i;
    }
  
    string p = "";
    string c = "";
    p += str[0];
    //int R = 0;
    for (int i = 0; i < str.length(); i++) {
        if (i != str.length() - 1)
            c += str[i + 1];
        if (dictionary.find(p + c) != dictionary.end()) {
            p = p + c;
        }
        else {
	    result[R[0]] = dictionary[p];
//	    std::printf("num_char: %s \n", result[R]);
	    dictionary[p + c] = dictionary_size;
            dictionary_size++;
            p = c;
            R[0]++;
        }
        c = "";
    }
	result[R[0]] = dictionary[p];
}

int main(int argc, char *argv[])
{
	stopwatch ethernet_timer;
	stopwatch coarse_gain;
	unsigned char *input[NUM_PACKETS];
	int writer = 0;
	int done = 0;
	int length = 0;
	int count = 0;
	ESE532_Server server;

	// default is 2k
	int payload_size = PAYLOAD_SIZE;

	// set payload_size if decalred through command line
	handle_input(argc, argv, &payload_size);

	file = (unsigned char *)malloc(sizeof(unsigned char) * 70000000);
	if (file == NULL)
	{
		printf("help\n");
	}

	for (int i = 0; i < NUM_PACKETS; i++)
	{
		input[i] = (unsigned char *)malloc(
			sizeof(unsigned char) * (NUM_ELEMENTS + HEADER));
		if (input[i] == NULL)
		{
			std::cout << "aborting " << std::endl;
			return 1;
		}
	}

	server.setup_server(payload_size);

	writer = pipe_depth;
	server.get_packet(input[writer]);

	count++;

	// get packet
	unsigned char *buffer = input[writer];

	// decode
	done = buffer[1] & DONE_BIT_L;
	length = buffer[0] | (buffer[1] << 8);
	length &= ~DONE_BIT_H;
	// printing takes time so be weary of transfer rate
	//printf("length: %d offset %d\n",length,offset);

	// we are just memcpy'ing here, but you should call your
	// top function here.
	memcpy(&file[offset], &buffer[HEADER], length);

	offset += length;
	writer++;

	//last message
	while (!done)
	{
		// reset ring buffer
		if (writer == NUM_PACKETS)
		{
			writer = 0;
		}

		ethernet_timer.start();
		server.get_packet(input[writer]);
		ethernet_timer.stop();

		count++;

		// get packet
		unsigned char *buffer = input[writer];

		// decode
		done = buffer[1] & DONE_BIT_L;
		length = buffer[0] | (buffer[1] << 8);
		length &= ~DONE_BIT_H;
		//printf("length: %d offset %d\n",length,offset);
		memcpy(&file[offset], &buffer[HEADER], length);

		offset += length;
		writer++;
	}

	//================================================================================
	coarse_gain.start();
	cdc(file, 8192);
	std::cout <<"cdc the file with the length of" << length << std::endl;
	coarse_gain.stop();

	std::cout << "--------------- Key Throughputs ---------------" << std::endl;
	float cdc_latency = coarse_gain.latency() / 1000.0;
	float input_throughput = (total_bytes * 8/ 1000000.0) / cdc_latency; // Mb/s
	std::cout << "Encoder Throughput: " << input_throughput << " Mb/s."
			  << " (Latency: " << cdc_latency << "s)." << std::endl;
    //================================================================================
	std::cout << "--------------- Key Throughputs ---------------" << std::endl;
	float eth_latency = ethernet_timer.latency() / 1000.0;
	float eth_input_throughput = (total_bytes * 8/ 1000000.0) / eth_latency; // Mb/s
	std::cout << "Input Throughput to Encoder: " << eth_input_throughput << " Mb/s."
			  << " (Latency: " << cdc_latency << "s)." << std::endl;
	return 0;
}
