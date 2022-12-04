#include <stdio.h>
#include "MD5.h"


int main()
{
    unsigned char* prosto_buff = NULL;
    get_md5_hash("qwerty", prosto_buff);

    return 0;
}