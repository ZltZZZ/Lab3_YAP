#pragma once

// Стандартные значения ветора инициализации.
#define INIT_VECTOR_A 0x67452301
#define INIT_VECTOR_B 0xefcdab89
#define INIT_VECTOR_C 0x98badcfe
#define INIT_VECTOR_D 0x10325476

#define MD5_HASH_SIZE 16

/* Первый аргумент - строка, хеш которой надо получить.
   Второй аргумент - результат хеширования (пока будет так). */
void md5_get_hash(unsigned char* buff_in, unsigned char* buff_out);

/* MD5 + salt. */
void md5_get_hash_salt(unsigned char* buff_in, unsigned char* salt, unsigned char* buff_out);

void md5_print(unsigned char* hash);