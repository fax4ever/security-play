To compile the program you need to link the OpenSSL libraries.

Assuming you have installed OpenSSL in the directory `/home/fax/lib/open/`.

## AES CBC

1. Compile and link

``` bash
gcc aes-cbc.c -o aes-cbc -I /home/fax/lib/open/include -L /home/fax/lib/open/lib64 -lcrypto
```

2. Run the program

``` bash
./aes-cbc
```

## Camellia CBC

1. Compile and link

``` bash
gcc camellia-cbc.c -o camellia-cbc -I /home/fax/lib/open/include -L /home/fax/lib/open/lib64 -lcrypto
```

2. Run the program

``` bash
./camellia-cbc
```

# EXTRA

## AES CBF 128

1. Compile and link

``` bash
gcc aes-cbf.c -o aes-cbf -I /home/fax/lib/open/include -L /home/fax/lib/open/lib64 -lcrypto
```

2. Run the program

``` bash
./aes-cbf
```

