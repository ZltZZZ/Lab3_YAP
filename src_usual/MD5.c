#include "MD5.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

typedef unsigned char byte;
typedef unsigned int byte4;

const unsigned long int s[64] = {
	7, 12, 17, 22,   7, 12, 17, 22,   7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,   5,  9, 14, 20,   5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,   4, 11, 16, 23,   4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,   6, 10, 15, 21,   6, 10, 15, 21,  6, 10, 15, 21
};

const unsigned long int K[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/* Преобразование из Big-end в Little-end и наоборот. */
inline unsigned int bswap(unsigned int v)
{
	return (v >> 24) | ((v >> 8) & 0xff00)
		| ((v << 8) & 0xff0000) | (v << 24);
}

inline byte4 rol(byte4 a, int offset)
{
	return a << offset | a >> (32 - offset);
}

void md5_get_hash(unsigned char* buff_in, unsigned char* buff_out) {
	byte4	A0 = INIT_VECTOR_A,
			B0 = INIT_VECTOR_B,
			C0 = INIT_VECTOR_C,
			D0 = INIT_VECTOR_D;
	unsigned long int len_bytes = strlen(buff_in),     // Длина оригинальной входной строки в байтах
					  len_bits = len_bytes * 8,        // Длина оригинальной входной строки в битах
					  new_len_bits = 0,		           // Длина новой строки, после подготовки в битах
					  new_len_bytes = 0;			   // Длина новой строки, после подготовки в байтах
	int N;										       // N из формулы 512 * N + 448
	byte* byte_buff = NULL;						       // Массив байт, содержащий оригинальную строку + выравшивающие биты + 64 бита длины оригинальной строки

	/* 1. Подготовка массива байт. */
	// 1.a. Расчет новой длины после добовления выравнивающих бит по формуле: 512 * N + 448
	N = (((int)len_bits) + 1 - 448) / 512; // + 1 означает, что в конец обязательно добавлен 1 бит (из алгоритма).
	new_len_bits = 512 * N + 448;

	// 1.b. Добавить 64 бита (из алгоритма).
	new_len_bits += 64;

	// 1.c. Выделить и заполнить главный буффер.
	new_len_bytes = new_len_bits / 8;

	byte_buff = (byte*)calloc(new_len_bytes, sizeof(byte));
	if (byte_buff == NULL) {
		printf("calloc fail! (md5)\n");
		return;
	}

	memset(byte_buff, 0x00, sizeof(byte) * new_len_bytes); // Инициализация всеми нулями (тогда не нужно будет вручную ставить нулевые биты в конце
	memcpy(byte_buff, buff_in, sizeof(byte) * len_bytes); // Копирование исходной строки
	byte_buff[len_bytes] = 0x80; // Добавить 1 бит к исходной строке (1000 0000)
	//len_bits = bswap(len_bits); // Тут должно быть преобразование из Big-endian в Little-endian, но оно уже преобразовано, то ли сам виндовс little-endian, то ли memcpy копирует в обратном порядке.
	memcpy(byte_buff + new_len_bytes - 8, &len_bits, sizeof(byte) * 4); // Добавить в конец длину исходной строки в формате 64 бит (little-endian).

	//// ОтладОЧКА
	//for (unsigned long int i = 0; i < new_len_bytes; i++) {
	//	printf("%x ", byte_buff[i]);
	//}
	//printf("\n");

	/* 2. Хеширование. */
	for (unsigned int chunk = 0; chunk < new_len_bytes; chunk += 64) { // Разбиваем строку на блоки по 512 бит = 64 байт
		byte4	A = A0,
				B = B0,
				C = C0,
				D = D0;
		byte4* block = (byte4*)(byte_buff + chunk); // 32-х битный блок (4 байт) из 512 (64 байт) битного чанка.
		for (int i = 0; i < 64; i++) {
			byte4 F;
			unsigned int g; // Номер 32-х битного блока (4 байт) из 512 (64 байт) битного чанка.
			
			if (0 <= i && i <= 15) {
				F = (B & C) | ((~B) & D);	// Функция F
				g = i;
			}
			else if (16 <= i && i <= 31) {
				F = (D & B) | ((~D) & C);	// Функция G
				g = (5 * i + 1) % 16;
			}
			else if (32 <= i && i <= 47) {
				F = B ^ C ^ D;				// Функция H
				g = (3 * i + 5) % 16;
			}
			else { // (48 <= i && i <= 63)
				F = C ^ (B | (~D));			// Функция I
				g = (7 * i) % 16;
			}

			F = F + A + K[i] + block[g];
			A = D;
			D = C;
			C = B;
			byte4 test = rol(F, s[i]);
			B = B + rol(F, s[i]);
		}

		A0 += A;
		B0 += B;
		C0 += C;
		D0 += D;
	}

	/* Запись результата. */
	/*A0 = bswap(A0);
	B0 = bswap(B0);
	C0 = bswap(C0);
	D0 = bswap(D0);*/
	memcpy(buff_out, &A0, sizeof(byte4));
	memcpy(buff_out + 4, &B0, sizeof(byte4));
	memcpy(buff_out + 8, &C0, sizeof(byte4));
	memcpy(buff_out + 12, &D0, sizeof(byte4));
 
	free(byte_buff);
}

void md5_get_hash_salt(unsigned char* buff_in, unsigned char* salt, unsigned char* buff_out) {
	unsigned char* new_buff = NULL;
	size_t in_len = strlen(buff_in), salt_len = strlen(salt);

	new_buff = (unsigned char*)malloc(in_len + salt_len + 1);
	if (new_buff == NULL) {
		printf("malloc fail! (salt)\n");
		return;
	}

	memcpy(new_buff, buff_in, in_len);
	memcpy(new_buff + in_len, salt, salt_len + 1);

	md5_get_hash(new_buff, buff_out);

	free(new_buff);
}

void md5_print(unsigned char* hash) {
	for (int i = 0; i < MD5_HASH_SIZE; i++) {
		printf("%02x", hash[i]);
	}
}