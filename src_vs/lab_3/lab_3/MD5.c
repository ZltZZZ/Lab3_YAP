#include "MD5.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

typedef unsigned char byte;

const unsigned long int s[64] = {
	7, 12, 17, 22,   7, 12, 17, 22,   7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,   5,  9, 14, 20,   5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,   4, 11, 16, 23,   4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

const unsigned long int T[64] = {
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
unsigned int bswap(unsigned int v)
{
	return (v >> 24) | ((v >> 8) & 0xff00)
		| ((v << 8) & 0xff0000) | (v << 24);
}

void get_md5_hash(unsigned char* buff_in, unsigned char* buff_out) {
	unsigned long int A = INIT_VECTOR_A,
					  B = INIT_VECTOR_B,
					  C = INIT_VECTOR_C,
					  D = INIT_VECTOR_D;
	unsigned long int len_bytes = strlen(buff_in),     // Длина оригинальной входной строки в байтах
					  len_bits = len_bytes * 8,        // Длина оригинальной входной строки в битах
					  new_len_bits = 0,		           // Длина новой строки, после подготовки в битах
					  new_len_bytes = 0;			   // Длина новой строки, после подготовки в байтах
	int N;										       // N из формулы 512 * N + 448
	byte* byte_buff = NULL;						       // Массив байт, содержащий оригинальную строку + выравшивающие биты + 64 бита длины оригинальной строки

	/* 1. Подготовка массива байт. */
	// 1.a. Расчет новой длины после добовления выравнивающих бит по формуле: 512 * N + 448
	N = (((int)len_bits) + 1 - 448) / 512; // + 1 означает, что в конец обязательно добавлен 1 бит (из алгоритма).
	if ((((int)len_bits) + 1 - 448) % 512 != 0 || N == 0) {
		N++;
	}
	new_len_bits = 512 * N + 448;

	// 1.b. Добавить 64 бита (из алгоритма).
	new_len_bits += 64;

	// 1.c. Выделить и заполнить главный буффер.
	new_len_bytes = new_len_bits / 8;

	byte_buff = (byte*)calloc(new_len_bytes, sizeof(byte));
	if (byte_buff == NULL) {
		return;
	}

	memset(byte_buff, 0x00, sizeof(byte) * new_len_bytes); // Инициализация всеми нулями (тогда не нужно будет вручную ставить нулевые биты в конце
	memcpy(byte_buff, buff_in, sizeof(byte) * len_bytes); // Копирование исходной строки
	byte_buff[len_bytes] = 0x80; // Добавить 1 бит к исходной строке (1000 0000)
	//len_bits = bswap(len_bits); // Тут должно быть преобразование из Big-endian в Little-endian, но оно уже преобразовано, то ли сам виндовс little-endian, то ли memcpy копирует в обратном порядке.
	memcpy(byte_buff + new_len_bytes - 8, &len_bits, sizeof(byte) * 4); // Добавить в конец длину исходной строки в формате 64 бит (little-endian).

	// ОтладОЧКА
	for (unsigned long int i = 0; i < new_len_bytes; i++) {
		printf("%x ", byte_buff[i]);
	}

	/* 2. Хеширование. */
}