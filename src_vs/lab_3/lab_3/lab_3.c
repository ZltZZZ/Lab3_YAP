#include <stdio.h>
#include "MD5.h"


int main()
{
    unsigned char md5_hash[MD5_HASH_SIZE];
    md5_get_hash_salt("test", "salt", md5_hash);

    md5_print(md5_hash);

    return 0;
}