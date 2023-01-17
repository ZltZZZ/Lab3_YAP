#define _CRT_SECURE_NO_WARNINGS
#define NOT_FOUND 999999999
#define MAX_PATH_TO_FILE 256
#define MAX_PASS_SIZE 30
#define MAX_PASS_COUNT 10000000
#define MAX_HASH_COUNT 100

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "MD5.h"

void getHashListConfig(unsigned char* hashListOut, unsigned int* hashListSizeOut, FILE* file);
void getPassList(unsigned char* passListOut, unsigned int* passListSizeOut, FILE* file);
void brutUsual(unsigned char* passList, unsigned char* hashList, unsigned int* passListSize, unsigned int* hasListSize, unsigned int* result);
unsigned int getPassListSize(FILE* filePassList);

int main()
{
	FILE* filePassList = NULL;
	FILE* fileConfig = NULL;
	unsigned char* passList = NULL;
	unsigned char* hashList = NULL;
	unsigned int passListSize = 0;
	unsigned int hashListSize = 0;
	unsigned int result[MAX_HASH_COUNT]; for (int i = 0; i < MAX_HASH_COUNT; i++) { result[i] = NOT_FOUND; }
	unsigned char input[MAX_PATH_TO_FILE] = { 0 };
	time_t before = 0, after = 0;

	printf("Enter path to seclist file (type 'def' to use default file): ");
	scanf_s("%s", input, MAX_PATH_TO_FILE);
	if (strcmp((char*)input, "def") == 0) {
		strcpy((char*)input, "10000000.txt");
	}

	fopen_s(&filePassList, (char*)input, "r");
	if (filePassList == NULL) {
		printf("fopen fail 1000000.txt\n");
		return 1;
	}
	fopen_s(&fileConfig, "Config.txt", "r");
	if (fileConfig == NULL) {
		printf("fopen fail Config.txt\n");
		return 1;
	}

	printf("Getting Passwords List from %s pass seclist file... ", input);

	passList = (unsigned char*)calloc(getPassListSize(filePassList), MAX_PASS_SIZE * sizeof(unsigned char));
	if (passList == NULL) {
		exit(-43);
	}
	fseek(filePassList, 0, SEEK_SET);
	getPassList(passList, &passListSize, filePassList);

	printf("OK\n");

	// Массив под хеши паролей, которые идут в конфигурационном файле
	hashList = (unsigned char*)calloc(MAX_HASH_COUNT, MD5_HASH_SIZE * sizeof(unsigned char));
	if (hashList == NULL) {
		exit(-43);
	}

	// Получение списков паролей из файлов
	printf("Getting Hashes from Config file... ");
	getHashListConfig(hashList, &hashListSize, fileConfig);
	printf("OK\n");

	fclose(filePassList);
	fclose(fileConfig);

	// Brutforce md5 hash of passwords
	printf("Starting Brutforce usual\n\n");
	time(&before);
	brutUsual(passList, hashList, &passListSize, &hashListSize, result);
	time(&after);
	printf("Finished!\n\n");

	for (unsigned int i = 0; i < hashListSize; i++) {
		printf("Hash: ");
		md5_print(hashList + i * MD5_HASH_SIZE);

		printf(" Password: ");
		if (result[i] != NOT_FOUND) {
			printf("%s\n", passList + result[i] * MAX_PASS_SIZE);
		}
		else {
			printf("not found\n");
		}
	}

	printf("\nTime: %f sec.\n", difftime(after, before));

	free(passList);
	free(hashList);

    return 0;
}

// Get max 100 pass from Config file
void getHashListConfig(unsigned char* hashListOut, unsigned int* hashListSizeOut, FILE* file) {
	unsigned char pass[MAX_PASS_SIZE];
	unsigned char salt[MAX_PASS_SIZE];
	unsigned char c;

	while (!feof(file))
	{
		c = '\0';
		fscanf(file, "%s", pass); fscanf(file, "%c", &c);
		if (c == ' ') {
			fscanf(file, "%s", salt);
		}
		else
		{
			salt[0] = '\0';
		}

		if (pass[0] != '\0' && pass[0] != '\n' && *hashListSizeOut < 100) {
			md5_get_hash_salt(pass, salt, hashListOut + (*hashListSizeOut)++ * MD5_HASH_SIZE);
		}
	}
}

void getPassList(unsigned char* passListOut, unsigned int* passListSizeOut, FILE* file) {
	for (int i = 0; (!feof(file)); i++) {
		(*passListSizeOut)++;
		fscanf_s(file, "%s", passListOut + i * MAX_PASS_SIZE, 30);
	}
}

int strcmp_my(unsigned char* s1, unsigned char* s2, unsigned int size) {
	unsigned char* s1cpy = s1;
	unsigned char* s2cpy = s2;

	for (; size > 1 && *s1cpy == *s2cpy; ++s1cpy, ++s2cpy, size--);

	if (*s1cpy == *s2cpy) {
		return 0;
	}
	else if (*s1cpy < *s2cpy) return -1;
	else return 1;
}

void brutUsual(unsigned char* passList, unsigned char* hashList, unsigned int* passListSize, unsigned int* hasListSize, unsigned int* result) {
	unsigned char md5_hash[MD5_HASH_SIZE];

	for (unsigned int i = 0; i < *passListSize; i++) {
		md5_get_hash(passList + i * MAX_PASS_SIZE, md5_hash);
		for (unsigned int j = 0; j < *hasListSize; j++) {
			if (strcmp_my(hashList + j * MD5_HASH_SIZE, md5_hash, MD5_HASH_SIZE) == 0) {
				result[j] = i;
				break;
			}
		}
	}
}

unsigned int getPassListSize(FILE* filePassList) {
	unsigned char string[MAX_PASS_SIZE];
	unsigned int size = 0;

	for (int i = 0; (!feof(filePassList)); i++) {
		size++;
		fscanf_s(filePassList, "%s", string, MAX_PASS_SIZE);
	}

	return size;
}