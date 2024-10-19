To compile the program you need to link the OpenSSL libraries.

Assuming you have installed OpenSSL in the directory `/home/fax/lib/openssl-3.3.2`.

## AES CBC

1. Compile and link

``` bash
gcc aes-cbc.c -o aes-cbc -I /home/fax/lib/openssl-3.3.2/include -L /home/fax/lib/openssl-3.3.2/lib64 -lcrypto
```

2. Run the program

``` bash
./aes-cbc
```

## ARIA CBC

1. Compile and link

``` bash
gcc aria-cbc.c -o aria-cbc -I /home/fax/lib/openssl-3.3.2/include -L /home/fax/lib/openssl-3.3.2/lib64 -lcrypto
```

2. Run the program

``` bash
./aria-cbc
```

## Camellia CBC

1. Compile and link

``` bash
gcc camellia-cbc.c -o camellia-cbc -I /home/fax/lib/openssl-3.3.2/include -L /home/fax/lib/openssl-3.3.2/lib64 -lcrypto
```

2. Run the program

``` bash
./camellia-cbc
```

# EXTRA

## Remove the ignored files

``` bash
./clean.sh
```

or

``` bash
git clean -dfX
```

## AES CBF 128

1. Compile and link

``` bash
gcc aes-cbf.c -o aes-cbf -I /home/fax/lib/openssl-3.3.2/include -L /home/fax/lib/openssl-3.3.2/lib64 -lcrypto
```

2. Run the program

``` bash
./aes-cbf
```

