#define MAX_PASS_SIZE 30
#define MAX_PASS_COUNT 10000000
#define MAX_HASH_COUNT 100
#define INIT_VECTOR_A 0x67452301
#define INIT_VECTOR_B 0xefcdab89
#define INIT_VECTOR_C 0x98badcfe
#define INIT_VECTOR_D 0x10325476
#define MD5_HASH_SIZE 16
#define NOT_FOUND 999999999
#define MAX_PATH_TO_FILE 256

#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef unsigned char byte;
typedef unsigned int byte4;

const unsigned long int s[64] = {
	7, 12, 17, 22,   7, 12, 17, 22,   7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,   5,  9, 14, 20,   5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,   4, 11, 16, 23,   4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,   6, 10, 15, 21,   6, 10, 15, 21,  6, 10, 15, 21
};

__device__ unsigned long int dev_s[64] = {
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

__device__ unsigned long int dev_K[64] = {
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

/* Первый аргумент - строка, хеш которой надо получить.
   Второй аргумент - результат хеширования (пока будет так). */
void md5_get_hash(unsigned char* buff_in, unsigned char* buff_out);
/* MD5 + salt. */
void md5_get_hash_salt(unsigned char* buff_in, unsigned char* salt, unsigned char* buff_out);
void md5_print(unsigned char* hash);
__device__ void md5_get_hash_cuda(unsigned char* buff_in, unsigned char* buff_out);

cudaError_t brutWithCuda(unsigned char* passList, unsigned char* hashList, unsigned int* passListSize, unsigned int* hashListSize, unsigned int* result);
void getHashListConfig(unsigned char* hashListOut, unsigned int* hashListSizeOut, FILE* file);
void getPassList(unsigned char* passListOut, unsigned int* passListSizeOut, FILE* file);

__device__ int memcmp_cuda(unsigned char* s1, unsigned char* s2, unsigned int size) {
	unsigned char* s1cpy = s1;
	unsigned char* s2cpy = s2;

	for (; size > 1 && *s1cpy == *s2cpy; ++s1cpy, ++s2cpy, size--);

	if (*s1cpy == *s2cpy) {
		return 0;
	}
	else if (*s1cpy < *s2cpy) return -1;
	else return 1;
}

__global__ void brutKernel(unsigned char* passList, unsigned char* hashList, unsigned int* passListSize, unsigned int* hasListSize, unsigned int* result)
{
	unsigned int bid = blockIdx.x;
	unsigned int tid = threadIdx.x;
	unsigned int i = bid * blockDim.x + tid;
    unsigned char md5_hash[MD5_HASH_SIZE];
    
    if (i < 0 || i >= *passListSize) {
        return;
    }
	
    md5_get_hash_cuda(passList + i * MAX_PASS_SIZE, md5_hash);
    for (unsigned int j = 0; j < *hasListSize; j++) {
        if (memcmp_cuda(hashList + j * MD5_HASH_SIZE, md5_hash, MD5_HASH_SIZE) == 0) {
			result[j] = i;
            break;
        }
    }
} 

int main()
{
	cudaError_t cudaStatus;
    FILE* filePassList = NULL;
    FILE* fileConfig = NULL;
	unsigned char* passList = NULL;
	unsigned char* hashList = NULL;
    unsigned int passListSize = 0;
    unsigned int hashListSize = 0;
	unsigned int result[MAX_HASH_COUNT]; for (int i = 0; i < MAX_HASH_COUNT; i++) {result[i] = NOT_FOUND;}
	unsigned char input[MAX_PATH_TO_FILE];
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

	// Выделение памяти под массивы
    // Список паролей из секлиста
	passList = (unsigned char*)calloc(MAX_PASS_COUNT, MAX_PASS_SIZE * sizeof(unsigned char));
	if (passList == NULL) {
		exit(-43);
	}

	// Массив под хеши паролей, которые идут в конфигурационном файле
	hashList = (unsigned char*)calloc(MAX_HASH_COUNT, MD5_HASH_SIZE * sizeof(unsigned char));
	if (hashList == NULL) {
		exit(-43);
	}  

	// Получение списков паролей из файлов
	printf("Getting Hashes from Config file... ");
	getHashListConfig(hashList, &hashListSize, fileConfig);
	printf("OK\n");
	printf("Getting Passwords List from %s pass seclist file... ", input);
	getPassList(passList, &passListSize, filePassList);
	printf("OK\n");

    fclose(filePassList);
	fclose(fileConfig);

	// Brutforce md5 hash of passwords in parallel
	printf("Starting Brutforce with CUDA\n\n");
	time(&before);
	cudaStatus = brutWithCuda(passList, hashList, &passListSize, &hashListSize, result);
	time(&after);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "addWithCuda failed!");
		return 1;
	}
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

    // cudaDeviceReset must be called before exiting in order for profiling and
    // tracing tools such as Nsight and Visual Profiler to show complete traces.
    cudaStatus = cudaDeviceReset();
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaDeviceReset failed!");
        return 1;
    }

    return 0;
}

 //Helper function for using CUDA.
cudaError_t brutWithCuda(unsigned char* passList, unsigned char* hashList, unsigned int* passListSize, unsigned int* hashListSize, unsigned int* result)
{
	unsigned char* dev_passList = 0;
	unsigned char* dev_hashList = 0;
	unsigned int* dev_passListSize = 0;
	unsigned int* dev_hasListsize = 0;
	unsigned int* dev_result = 0;

    cudaError_t cudaStatus;
	int n_blocks = (MAX_PASS_COUNT + 255) / 256;
	int threads_per_block = 256;
	dim3 grid(n_blocks, 1, 1);
	dim3 threads(threads_per_block, 1, 1);

    // Choose which GPU to run on, change this on a multi-GPU system.
    cudaStatus = cudaSetDevice(0);
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaSetDevice failed!  Do you have a CUDA-capable GPU installed?");
        goto Error;
    }

    // Allocate GPU buffers for three vectors (two input, one output)  
	// Память под результат
	cudaStatus = cudaMalloc((void**)&dev_result, MAX_HASH_COUNT * sizeof(unsigned int));
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMalloc failed!");
		goto Error;
	}
	cudaStatus = cudaMemcpy(dev_result, result, MAX_HASH_COUNT * sizeof(unsigned int), cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMalloc failed!");
		goto Error;
	}
	
	// Память под секлист
    cudaStatus = cudaMalloc((void**)&dev_passList, MAX_PASS_COUNT * MAX_PASS_SIZE * sizeof(unsigned char));
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaMalloc failed!");
        goto Error;
    }
	cudaStatus = cudaMemcpy(dev_passList, passList, MAX_PASS_COUNT * MAX_PASS_SIZE * sizeof(unsigned char), cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMalloc failed!");
		goto Error;
	}

	// Память под хэши из конфига
	cudaStatus = cudaMalloc((void**)&dev_hashList, MAX_HASH_COUNT * MD5_HASH_SIZE * sizeof(unsigned char));
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMalloc failed!");
		goto Error;
	}
	cudaStatus = cudaMemcpy(dev_hashList, hashList, MAX_HASH_COUNT * MD5_HASH_SIZE * sizeof(unsigned char), cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMalloc failed!");
		goto Error;
	}

	// Память под число хэшей
	cudaStatus = cudaMalloc((void**)&dev_hasListsize, sizeof(unsigned int));
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMalloc failed!");
		goto Error;
	}
	cudaStatus = cudaMemcpy(dev_hasListsize, hashListSize, sizeof(unsigned int), cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMalloc failed!");
		goto Error;
	}

	// Память под число паролей из секлиста
	cudaStatus = cudaMalloc((void**)&dev_passListSize, sizeof(unsigned int));
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMalloc failed!");
		goto Error;
	}
	cudaStatus = cudaMemcpy(dev_passListSize, passListSize, sizeof(unsigned int), cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMalloc failed!");
		goto Error;
	}

	// Launch a kernel on the GPU with one thread for each element.
	brutKernel <<<grid, threads >>> (dev_passList, dev_hashList, dev_passListSize, dev_hasListsize, dev_result);

	// Check for any errors launching the kernel
	cudaStatus = cudaGetLastError();
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "addKernel launch failed: %s\n", cudaGetErrorString(cudaStatus));
		goto Error;
	}

	// cudaDeviceSynchronize waits for the kernel to finish, and returns
	// any errors encountered during the launch.
	cudaStatus = cudaDeviceSynchronize();
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaDeviceSynchronize returned error code %d after launching addKernel!\n", cudaStatus);
		goto Error;
	}

	// Copy output vector from GPU buffer to host memory.
	cudaStatus = cudaMemcpy(result, dev_result, sizeof(unsigned int) * MAX_HASH_COUNT, cudaMemcpyDeviceToHost);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMemcpy failed!");
		goto Error;
	}

Error:
	cudaFree(dev_passList);
	cudaFree(dev_hashList);
    cudaFree(dev_hasListsize);
    cudaFree(dev_passListSize);
    cudaFree(dev_result);
    
    return cudaStatus;
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

__device__ inline byte4 rol_cuda(byte4 a, int offset)
{
	return a << offset | a >> (32 - offset);
}

__device__ inline unsigned int bswap_cuda(unsigned int v)
{
	return (v >> 24) | ((v >> 8) & 0xff00)
		| ((v << 8) & 0xff0000) | (v << 24);
}

void md5_get_hash(unsigned char* buff_in, unsigned char* buff_out) {
	byte4	A0 = INIT_VECTOR_A,
		B0 = INIT_VECTOR_B,
		C0 = INIT_VECTOR_C,
		D0 = INIT_VECTOR_D;
	unsigned long int len_bytes = strlen((char*)buff_in),     // Длина оригинальной входной строки в байтах
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
	size_t in_len = strlen((char*)buff_in), salt_len = strlen((char*)salt);

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

__device__ int strlen_cuda(unsigned char* s) {
	unsigned char* scpy = s;
	int size = 0;

	for (; *scpy != '\0'; size++, scpy++);

	return size;
}

__device__ void md5_get_hash_cuda(unsigned char* buff_in, unsigned char* buff_out) {
	byte4	A0 = INIT_VECTOR_A,
		B0 = INIT_VECTOR_B,
		C0 = INIT_VECTOR_C,
		D0 = INIT_VECTOR_D;
	unsigned long int len_bytes = strlen_cuda(buff_in),     // Длина оригинальной входной строки в байтах
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

	byte_buff = (byte*)malloc(sizeof(byte) * new_len_bytes);
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

			F = F + A + dev_K[i] + block[g];
			A = D;
			D = C;
			C = B;
			B = B + rol_cuda(F, dev_s[i]);
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

void md5_print(unsigned char* hash) {
	for (int i = 0; i < MD5_HASH_SIZE; i++) {
		printf("%02x", hash[i]);
	}
}