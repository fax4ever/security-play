To compile the program you need to link the OpenSSL libraries.

Assuming you have installed OpenSSL in the directory `/home/fax/lib/open/`.

## AES CBF 128

1. Compile and link

``` bash
gcc comparison.c -o comparison -I /home/fax/lib/open/include -L /home/fax/lib/open/lib64 -lcrypto -Wall -Wextra -g
```

2. Run the program

``` bash
./comparison
```

## AES CBC

