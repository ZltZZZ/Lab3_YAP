#pragma once

// ����������� �������� ������ �������������.
#define INIT_VECTOR_A 0x67452301
#define INIT_VECTOR_B 0xefcdab89
#define INIT_VECTOR_C 0x98badcfe
#define INIT_VECTOR_D 0x10325476

/* ������ �������� - ������, ��� ������� ���� ��������.
   ������ �������� - ��������� ����������� (���� ����� ���). */
void get_md5_hash(unsigned char* buff_in, unsigned char* buff_out);
