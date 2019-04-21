PHP_ARG_ENABLE(loracrypt, whether to enable loracrypt support,
[ --enable-loracrypt   Enable loracrypt support])

if test "$PHP_LORACRYPT" = "yes"; then
    AC_DEFINE(HAVE_LORACRYPT, 1, [Whether you have loracrypt])
    PHP_NEW_EXTENSION(loracrypt, php_lora.c aes.c cmac.c utilities.c LoRaMacCrypto.c hexString.c, $ext_shared)
fi
