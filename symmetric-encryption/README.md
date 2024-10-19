To compile the program you need to link the OpenSSL libraries.

Assuming you have installed OpenSSL in the directory `/home/fax/lib/open/`.

## AES CBC

``` bash
gcc aes-cbc.c -o aes-cbc -I /home/fax/lib/open/include -L /home/fax/lib/open/lib64 -lcrypto
```

2. Run the program

``` bash
./aes-cbc
```

## AES CBF 128

1. Compile and link

``` bash
gcc aes-cbf.c -o aes-cbf -I /home/fax/lib/open/include -L /home/fax/lib/open/lib64 -lcrypto
```

2. Run the program

``` bash
./aes-cbf
```

