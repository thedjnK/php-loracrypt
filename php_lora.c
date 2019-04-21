#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

//Includes
#include <stdbool.h>
#include "php.h"
#include "ext/standard/info.h"
#include "LoRaMacCrypto.h"
#include "hexString.h"

//Defines
//todo: make use of these defines
#define LORA_DATA_RAW 0 //
#define LORA_DATA_HEX 1 //

#define PHP_LORACRYPT_EXTNAME "LoRaCrypt" //Extension name
#define PHP_LORACRYPT_VERSION "0.3"       //Extension version
#define APPKEY_LEN             16         //Length in bytes of an application key
#define NWKSKEY_LEN            16         //Length in bytes of a network S Key
#define APPSKEY_LEN            16         //Length in bytes of an application S Key
#define APPNONCE_LEN           6          //Length in bytes of an application nonce and network ID
#define JOINMSG_LEN            16         //Length in bytes of a join message without the optional CF list
#define JOINMSG_CF_LEN         32         //Length in bytes of a join message with the optional CF list
#define APPKEY_HEX_LEN         32         //Length in bytes of an application key (hex-encoded)
#define NWKSKEY_HEX_LEN        32         //Length in bytes of a network S Key (hex-encoded)
#define APPSKEY_HEX_LEN        32         //Length in bytes of an application S Key (hex-encoded)
#define APPNONCE_HEX_LEN       16         //Length in bytes of an application nonce and network ID (hex-encoded)
#define JOINMSG_HEX_LEN        16         //Length in bytes of a join message without the optional CF list (hex-encoded)
#define JOINMSG_CF_HEX_LEN     32         //Length in bytes of a join message with the optional CF list (hex-encoded)
#define FLIP_ENDIAN                       //Flip endianness of Mics
//#define USE_HEX                           //Supplied and returned values are in hex

//Function prototypes
PHP_MINIT_FUNCTION(loracrypt);
PHP_MINFO_FUNCTION(loracrypt);
PHP_FUNCTION(lorasetdatatype);
PHP_FUNCTION(loracomputemic);
PHP_FUNCTION(lorapayloadencrypt);
PHP_FUNCTION(lorapayloaddecrypt);
PHP_FUNCTION(lorajoincomputemic);
PHP_FUNCTION(lorajoinencrypt);
PHP_FUNCTION(lorajoindecrypt);
PHP_FUNCTION(lorajoincomputeskeys);

//Function arguments
ZEND_BEGIN_ARG_INFO_EX(arginfo_lorasetdatatype, 0, 0, 1)
    ZEND_ARG_INFO(0, DataType)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(arginfo_loracomputemic, 0, 0, 5)
    ZEND_ARG_INFO(0, Data)
    ZEND_ARG_INFO(0, AppKey)
    ZEND_ARG_INFO(0, Address)
    ZEND_ARG_INFO(0, UpDown)
    ZEND_ARG_INFO(0, SequenceNum)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(arginfo_lorapayloadencrypt, 0, 0, 5)
    ZEND_ARG_INFO(0, Data)
    ZEND_ARG_INFO(0, AppKey)
    ZEND_ARG_INFO(0, Address)
    ZEND_ARG_INFO(0, UpDown)
    ZEND_ARG_INFO(0, SequenceNum)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(arginfo_lorapayloaddecrypt, 0, 0, 5)
    ZEND_ARG_INFO(0, Data)
    ZEND_ARG_INFO(0, AppKey)
    ZEND_ARG_INFO(0, Address)
    ZEND_ARG_INFO(0, UpDown)
    ZEND_ARG_INFO(0, SequenceNum)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(arginfo_lorajoincomputemic, 0, 0, 2)
    ZEND_ARG_INFO(0, Data)
    ZEND_ARG_INFO(0, AppKey)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(arginfo_lorajoinencrypt, 0, 0, 2)
    ZEND_ARG_INFO(0, Data)
    ZEND_ARG_INFO(0, AppKey)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(arginfo_lorajoindecrypt, 0, 0, 2)
    ZEND_ARG_INFO(0, Data)
    ZEND_ARG_INFO(0, AppKey)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(arginfo_lorajoincomputeskeys, 0, 0, 3)
    ZEND_ARG_INFO(0, AppKey)
    ZEND_ARG_INFO(0, AppNonce)
    ZEND_ARG_INFO(0, DevNonce)
ZEND_END_ARG_INFO();

//Setup function entries
extern zend_module_entry loracrypt_module_entry;

static zend_function_entry loracrypt_functions[] =
{
    PHP_FE(lorasetdatatype, arginfo_lorasetdatatype)
    PHP_FE(loracomputemic, arginfo_loracomputemic)
    PHP_FE(lorapayloadencrypt, arginfo_lorapayloadencrypt)
    PHP_FE(lorapayloaddecrypt, arginfo_lorapayloaddecrypt)
    PHP_FE(lorajoincomputemic, arginfo_lorajoincomputemic)
    PHP_FE(lorajoinencrypt, arginfo_lorajoinencrypt)
    PHP_FE(lorajoindecrypt, arginfo_lorajoindecrypt)
    PHP_FE(lorajoincomputeskeys, arginfo_lorajoincomputeskeys)
    {NULL, NULL, NULL}
};

//Setup extension information
zend_module_entry loracrypt_module_entry =
{
    STANDARD_MODULE_HEADER,
    PHP_LORACRYPT_EXTNAME,
    loracrypt_functions,
    PHP_MINIT(loracrypt),
    NULL,
    NULL,
    NULL,
    PHP_MINFO(loracrypt),
    PHP_LORACRYPT_VERSION,
    STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(loracrypt)

//Global values
ZEND_BEGIN_MODULE_GLOBALS(loracrypt)
    zend_bool DataType;
ZEND_END_MODULE_GLOBALS(loracrypt)

#ifdef ZTS
#define LORACRYPT_G(v) TSRMG(loracrypt_globals_id, zend_loracrypt_globals *, v)
#else
#define LORACRYPT_G(v) (loracrypt_globals.v)
#endif

ZEND_DECLARE_MODULE_GLOBALS(loracrypt)

//Internal functions
static bool CheckHex(const uint8_t *Data, const uint8_t Data_Len)
{
    //Checks that supplied data is hex-encoded
    uint8_t i = 0;
    while (i < Data_Len)
    {
        if (!(Data[i] >= '0' && Data[i] <= '9') && !(Data[i] >= 'a' && Data[i] <= 'f') && !(Data[i] >= 'A' && Data[i] <= 'F'))
        {
            //Invalid character found
            return false;
        }
        ++i;
    }

    //Finished, all are hex
    return true;
}

static void php_loracrypt_init_globals(zend_loracrypt_globals *loracrypt_globals)
{
    //Sets globals to their defaults
    loracrypt_globals->DataType = false;
}

//Initialisation code
PHP_MINIT_FUNCTION(loracrypt)
{
    //Setup constants
    REGISTER_BOOL_CONSTANT("LORA_DATA_RAW", LORA_DATA_RAW, CONST_CS | CONST_PERSISTENT);
    REGISTER_BOOL_CONSTANT("LORA_DATA_HEX", LORA_DATA_HEX, CONST_CS | CONST_PERSISTENT);

    //Setup globals
    ZEND_INIT_MODULE_GLOBALS(loracrypt, php_loracrypt_init_globals, NULL);
}

//Info code
PHP_MINFO_FUNCTION(loracrypt)
{
    //Outputs information about extension
    php_info_print_table_start();
    php_info_print_table_row(2, "LoRaCrypt support", "enabled");
    php_info_print_table_row(2, "LoRaCrypt Version", PHP_LORACRYPT_VERSION);
    php_info_print_table_row(2, "LoRaCrypt Built", __DATE__);
    php_info_print_table_row(2, "LoRaCrypt Flip Mic Endianness", 
#ifdef FLIP_ENDIAN
        "Enabled"
#else
        "Disabled"
#endif
    );
    php_info_print_table_end();
}

//Function code
PHP_FUNCTION(lorasetdatatype)
{
    //Sets data type to be hex-encoded or raw data
    zend_bool NewDataType;

    if (ZEND_NUM_ARGS() != 1)
    {
        //Need both parameters
        php_error(E_WARNING, "1 parameters must be supplied");
        RETURN_NULL();
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "b", &NewDataType) == FAILURE)
    {
        RETURN_NULL();
    }

    //Set the new data type
    LORACRYPT_G(DataType) = NewDataType;
}

PHP_FUNCTION(loracomputemic)
{
    //Computes the Mic of a message
    char *Data, *AppKey;
    size_t Data_Len, AppKey_Len;
    long Address, SequenceNumber;
    zend_bool Direction;
    uint32_t Mic;

    if (ZEND_NUM_ARGS() != 5)
    {
        //Need both parameters
        php_error(E_WARNING, "5 parameters must be supplied");
        RETURN_NULL();
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sslbl", &Data, &Data_Len, &AppKey, &AppKey_Len, &Address, &Direction, &SequenceNumber) == FAILURE)
    {
        RETURN_NULL();
    }
    
    if (LORACRYPT_G(DataType) == LORA_DATA_HEX)
    {
        //Hex: Check lengths
        if (Data_Len < 2)
        {
            //Data must be > 1
            php_error(E_WARNING, "Data must be at least 2-bytes (hex encoded)");
            RETURN_NULL();
        }

        if (AppKey_Len != APPKEY_HEX_LEN)
        {
            //Key must be 16 bytes unencoded
            php_error(E_WARNING, "AppKey must be 32-bytes (hex encoded)");
            RETURN_NULL();
        }

        if (Data_Len % 2 != 0)
        {
            //Data must be equal number of bytes
            php_error(E_WARNING, "Data must be an even number of bytes");
            RETURN_NULL();
        }

        //Check for invalid characters
        if (CheckHex(Data, Data_Len) == false)
        {
            //Invalid hex characters found in data
            php_error(E_WARNING, "Data must be hex-encoded and only contain hex characters");
            RETURN_NULL();
        }

        if (CheckHex(AppKey, AppKey_Len) == false)
        {
            //Invalid hex characters found in key
            php_error(E_WARNING, "AppKey must be hex-encoded and only contain hex characters");
            RETURN_NULL();
        }

        //Hex decode data
        uint8_t *Data_Dec = malloc(Data_Len/2 + 1);
        uint8_t *AppKey_Dec = malloc(AppKey_Len/2 + 1);
        hexStringToBytes(Data_Dec, Data, Data_Len);
        hexStringToBytes(AppKey_Dec, AppKey, AppKey_Len);

        //Calculate Mic
        LoRaMacComputeMic(Data_Dec, Data_Len/2, AppKey_Dec, (uint32_t)Address, Direction, (uint32_t)SequenceNumber, &Mic);
        free(Data_Dec);
        free(AppKey_Dec);
    }
    else
    {
        //Raw: Check lengths
        if (Data_Len < 1)
        {
            //Data must be > 0
            php_error(E_WARNING, "Data must be at least 1-byte");
            RETURN_NULL();
        }

        if (AppKey_Len != APPKEY_LEN)
        {
            //Key must be 16 bytes unencoded
            php_error(E_WARNING, "AppKey must be 16-bytes");
            RETURN_NULL();
        }

        //Calculate Mic
        LoRaMacComputeMic(Data, Data_Len, AppKey, (uint32_t)Address, Direction, (uint32_t)SequenceNumber, &Mic);
    }
    
#ifdef FLIP_ENDIAN
    //Reverse endianness of Mic
    Mic = ((Mic & 0xff) << 24 | (Mic & 0xff00) << 8 | (Mic & 0xff0000) >> 8 | (Mic & 0xff000000) >> 24);
#endif

    //Return as hex in a string
    char *MicStr;
    size_t MicStr_Len = spprintf(&MicStr, 0, "%x", Mic);

    if (LORACRYPT_G(DataType) == LORA_DATA_HEX)
    {
        RETVAL_STRINGL(MicStr, MicStr_Len);
    }
    else
    {
        //Need to decode from hex
//        char *MicStr_Dec = emalloc(MicStr_Len/2 + 1);
        char *MicStr_Dec = emalloc(MicStr_Len + 1);
//shit
        hexStringToBytes(MicStr_Dec, MicStr, MicStr_Len);
//        RETVAL_STRINGL(MicStr_Dec, MicStr_Len/2 + 2);
        RETVAL_STRINGL(MicStr_Dec, MicStr_Len);
        if (MicStr_Dec)
        {
            efree(MicStr_Dec);
        }
    }

    //Clear up variables
    if (Data_Len)
    {
//        efree(Data);
    }

    if (AppKey_Len)
    {
//        efree(AppKey);
    }

    if (MicStr)
    {
        efree(MicStr);
    }

    return;
}

PHP_FUNCTION(lorapayloadencrypt)
{
    //Encrypts LoRa data
    char *Data, *AppKey;
    size_t Data_Len, AppKey_Len;
    long Address, SequenceNumber;
    zend_bool Direction;

    if (ZEND_NUM_ARGS() != 5)
    {
        //Need both parameters
        php_error(E_WARNING, "5 parameters must be supplied");
        RETURN_NULL();
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sslbl", &Data, &Data_Len, &AppKey, &AppKey_Len, &Address, &Direction, &SequenceNumber) == FAILURE)
    {
        RETURN_NULL();
    }

    //Check lengths
#ifdef USE_HEX
    if (Data_Len < 2)
    {
        //Data must be > 1
        php_error(E_WARNING, "Data must be at least 2-bytes (hex encoded)");
        RETURN_NULL();
    }

    if (AppKey_Len != APPKEY_HEX_LEN)
    {
        //Key must be 16 bytes unencoded
        php_error(E_WARNING, "AppKey must be 32-bytes (hex encoded)");
        RETURN_NULL();
    }

    if (Data_Len % 2 != 0)
    {
        //Data must be equal number of bytes
        php_error(E_WARNING, "Data must be an even number of bytes");
        RETURN_NULL();
    }

    //Check for invalid characters
    if (CheckHex(Data, Data_Len) == false)
    {
        //Invalid hex characters found in data
        php_error(E_WARNING, "Data must be hex-encoded and only contain hex characters");
        RETURN_NULL();
    }

    if (CheckHex(AppKey, AppKey_Len) == false)
    {
        //Invalid hex characters found in key
        php_error(E_WARNING, "AppKey must be hex-encoded and only contain hex characters");
        RETURN_NULL();
    }

    //Hex decode data
    uint8_t *Data_Dec = malloc(Data_Len/2 + 1);
    uint8_t *AppKey_Dec = malloc(AppKey_Len/2 + 1);
    hexStringToBytes(Data_Dec, Data, Data_Len);
    hexStringToBytes(AppKey_Dec, AppKey, AppKey_Len);

    //Encrypt data
    char *EncryptedStr = malloc(Data_Len/2 + 1);
    LoRaMacPayloadEncrypt(Data_Dec, Data_Len/2, AppKey_Dec, (uint32_t)Address, Direction, (uint32_t)SequenceNumber, EncryptedStr);
    free(Data_Dec);
    free(AppKey_Dec);
    
    //Encode in hex
    char *EncryptedStr_Hex = emalloc(Data_Len + 1);
    bytesToHexString(EncryptedStr_Hex, EncryptedStr, Data_Len/2);
    free(EncryptedStr);

    //Return to PHP
    RETVAL_STRINGL(EncryptedStr_Hex, Data_Len);

    //Clean up
    if (EncryptedStr_Hex)
    {
        efree(EncryptedStr_Hex);
    }
#else
    if (Data_Len < 1)
    {
        //Data must be > 0
        php_error(E_WARNING, "Data must be at least 1-byte");
        RETURN_NULL();
    }

    if (AppKey_Len != APPKEY_LEN)
    {
        //Key must be 16 bytes unencoded
        php_error(E_WARNING, "AppKey must be 16-bytes");
        RETURN_NULL();
    }

    if (Data_Len % 2 != 0)
    {
        //Data must be equal number of bytes
        php_error(E_WARNING, "Data must be an even number of bytes");
        RETURN_NULL();
    }

    //Encrypt data
    char *EncryptedStr = emalloc(Data_Len + 1);
    LoRaMacPayloadEncrypt(Data, Data_Len, AppKey, (uint32_t)Address, Direction, (uint32_t)SequenceNumber, EncryptedStr);

    //Return to PHP
    RETVAL_STRINGL(EncryptedStr, Data_Len);

    //Clean up
    if (EncryptedStr)
    {
        efree(EncryptedStr);
    }
#endif

    //Tidy up PHP variables
    if (Data_Len)
    {
//        efree(Data);
    }

    if (AppKey_Len)
    {
//        efree(AppKey);
    }

    return;
}

PHP_FUNCTION(lorapayloaddecrypt)
{
    //Decrypts LoRa data
    char *Data, *AppKey;
    size_t Data_Len, AppKey_Len;
    long Address, SequenceNumber;
    zend_bool Direction;

    if (ZEND_NUM_ARGS() != 5)
    {
        //Need both parameters
        php_error(E_WARNING, "5 parameters must be supplied");
        RETURN_NULL();
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sslbl", &Data, &Data_Len, &AppKey, &AppKey_Len, &Address, &Direction, &SequenceNumber) == FAILURE)
    {
        RETURN_NULL();
    }

    //Check lengths
#ifdef USE_HEX
    if (Data_Len < 2)
    {
        //Data must be > 1
        php_error(E_WARNING, "Data must be at least 2-bytes (hex encoded)");
        RETURN_NULL();
    }

    if (AppKey_Len != APPKEY_HEX_LEN)
    {
        //Key must be 16 bytes unencoded
        php_error(E_WARNING, "AppKey must be 32-bytes (hex encoded)");
        RETURN_NULL();
    }

    if (Data_Len % 2 != 0)
    {
        //Data must be equal number of bytes
        php_error(E_WARNING, "Data must be an even number of bytes");
        RETURN_NULL();
    }

    //Check for invalid characters
    if (CheckHex(Data, Data_Len) == false)
    {
        //Invalid hex characters found in data
        php_error(E_WARNING, "Data must be hex-encoded and only contain hex characters");
        RETURN_NULL();
    }

    if (CheckHex(AppKey, AppKey_Len) == false)
    {
        //Invalid hex characters found in key
        php_error(E_WARNING, "AppKey must be hex-encoded and only contain hex characters");
        RETURN_NULL();
    }

    //Hex decode data
    uint8_t *Data_Dec = malloc(Data_Len/2 + 1);
    uint8_t *AppKey_Dec = malloc(AppKey_Len/2 + 1);
    hexStringToBytes(Data_Dec, Data, Data_Len);
    hexStringToBytes(AppKey_Dec, AppKey, AppKey_Len);

    //Decrypt data
    char *DecryptedStr = malloc(Data_Len/2 + 1);
    LoRaMacPayloadDecrypt(Data_Dec, Data_Len/2, AppKey_Dec, (uint32_t)Address, Direction, (uint32_t)SequenceNumber, DecryptedStr);
    free(Data_Dec);
    free(AppKey_Dec);
    
    //Encode in hex
    char *DecryptedStr_Hex = emalloc(Data_Len + 1);
    bytesToHexString(DecryptedStr_Hex, DecryptedStr, Data_Len/2);
    free(DecryptedStr);

    //Return to PHP
    RETVAL_STRINGL(DecryptedStr_Hex, Data_Len);

    //Clean up
    if (DecryptedStr_Hex)
    {
        efree(DecryptedStr_Hex);
    }
#else
    if (Data_Len < 1)
    {
        //Data must be > 0
        php_error(E_WARNING, "Data must be at least 1-byte");
        RETURN_NULL();
    }

    if (AppKey_Len != APPKEY_LEN)
    {
        //Key must be 16 bytes unencoded
        php_error(E_WARNING, "AppKey must be 16-bytes");
        RETURN_NULL();
    }

    //Decrypt data
    char *DecryptedStr = emalloc(Data_Len + 1);
    LoRaMacPayloadDecrypt(Data, Data_Len, AppKey, (uint32_t)Address, Direction, (uint32_t)SequenceNumber, DecryptedStr);

    //Return to PHP
    RETVAL_STRINGL(DecryptedStr, Data_Len);

    //Clean up
    if (DecryptedStr)
    {
        efree(DecryptedStr);
    }
#endif

    if (Data_Len)
    {
//        efree(Data);
    }

    if (AppKey_Len)
    {
//        efree(AppKey);
    }

    return;
}

PHP_FUNCTION(lorajoincomputemic)
{
    //Computes a join Mic
    char *Data, *AppKey;
    size_t Data_Len, AppKey_Len;
    uint32_t Mic;

    if (ZEND_NUM_ARGS() != 2)
    {
        //Need both parameters
        php_error(E_WARNING, "2 parameters must be supplied");
        RETURN_NULL();
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &Data, &Data_Len, &AppKey, &AppKey_Len) == FAILURE)
    {
        RETURN_NULL();
    }

    //Check lengths
#ifdef USE_HEX
    if (Data_Len < 2)
    {
        //Data must be > 1
        php_error(E_WARNING, "Data must be at least 2-bytes (hex encoded)");
        RETVAL_NULL();
        goto lorajoincomputemiccleanup;
    }

    if (AppKey_Len != APPKEY_HEX_LEN)
    {
        //Key must be 16 bytes unencoded
        php_error(E_WARNING, "AppKey must be 32-bytes (hex encoded)");
        RETVAL_NULL();
        goto lorajoincomputemiccleanup;
    }

    if (Data_Len % 2 != 0)
    {
        //Data must be equal number of bytes
        php_error(E_WARNING, "Data must be an even number of bytes");
        RETVAL_NULL();
        goto lorajoincomputemiccleanup;
    }

    //Check for invalid characters
    if (CheckHex(Data, Data_Len) == false)
    {
        //Invalid hex characters found in data
        php_error(E_WARNING, "Data must be hex-encoded and only contain hex characters");
        RETVAL_NULL();
        goto lorajoincomputemiccleanup;
    }

    if (CheckHex(AppKey, AppKey_Len) == false)
    {
        //Invalid hex characters found in key
        php_error(E_WARNING, "AppKey must be hex-encoded and only contain hex characters");
        RETVAL_NULL();
        goto lorajoincomputemiccleanup;
    }

    //Hex decode data
    uint8_t *Data_Dec = malloc(Data_Len/2 + 1);
    uint8_t *AppKey_Dec = malloc(AppKey_Len/2 + 1);
    hexStringToBytes(Data_Dec, Data, Data_Len);
    hexStringToBytes(AppKey_Dec, AppKey, AppKey_Len);

    //Calculate Mic
    LoRaMacJoinComputeMic(Data_Dec, Data_Len/2, AppKey_Dec, &Mic);
    free(Data_Dec);
    free(AppKey_Dec);
#else
    if (Data_Len < 1)
    {
        //Data must be > 0
        php_error(E_WARNING, "Data must be at least 1-byte");
        RETVAL_NULL();
        goto lorajoincomputemiccleanup;
    }

    if (AppKey_Len != APPKEY_LEN)
    {
        //Key must be 16 bytes unencoded
        php_error(E_WARNING, "AppKey must be 16-bytes");
        RETVAL_NULL();
        goto lorajoincomputemiccleanup;
    }

    //Calculate Mic
    LoRaMacJoinComputeMic(Data, Data_Len, AppKey, &Mic);
#endif

#ifdef FLIP_ENDIAN
    //Reverse endianness of Mic
    Mic = ((Mic & 0xff) << 24 | (Mic & 0xff00) << 8 | (Mic & 0xff0000) >> 8 | (Mic & 0xff000000) >> 24);
#endif

    //Return as hex in a string
    char *MicStr;
    size_t MicStr_Len = spprintf(&MicStr, 0, "%x", Mic);

#ifdef USE_HEX
    RETVAL_STRINGL(MicStr, MicStr_Len);
#else
    //Need to decode from hex
    char *MicStr_Dec = emalloc(MicStr_Len/2 + 1);
    hexStringToBytes(MicStr_Dec, MicStr, MicStr_Len);
    RETVAL_STRINGL(MicStr_Dec, MicStr_Len/2);
    if (MicStr_Dec)
    {
        efree(MicStr_Dec);
    }
#endif

lorajoincomputemiccleanup:
    //Tidy up PHP variables
    if (Data_Len)
    {
//        efree(Data);
    }

    if (AppKey_Len)
    {
//        efree(AppKey);
    }

    if (MicStr)
    {
        efree(MicStr);
    }

    return;
}

PHP_FUNCTION(lorajoinencrypt)
{
    //Encrypts a join message
    char *Data, *AppKey;
    size_t Data_Len, AppKey_Len;

    if (ZEND_NUM_ARGS() != 2)
    {
        //Need both parameters
        php_error(E_WARNING, "2 parameters must be supplied");
        RETURN_NULL();
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &Data, &Data_Len, &AppKey, &AppKey_Len) == FAILURE)
    {
        RETURN_NULL();
    }

    //Check lengths
#ifdef USE_HEX
    if (Data_Len != JOINMSG_HEX_LEN && Data_Len != JOINMSG_CF_HEX_LEN)
    {
        //Data must 16 or 32 bytes unencoded
        php_error(E_WARNING, "Data must be 32-bytes (without optional CF list) or 64-bytes (with optional CF list) (hex-encoded)");
        RETVAL_NULL();
        goto lorajoinencryptcleanup;
    }

    if (AppKey_Len != APPKEY_HEX_LEN)
    {
        //Key must be 16 bytes unencoded
        php_error(E_WARNING, "AppKey must be 32-bytes (hex-encoded)");
        RETVAL_NULL();
        goto lorajoinencryptcleanup;
    }

    //Check for invalid characters
    if (CheckHex(Data, Data_Len) == false)
    {
        //Invalid hex characters found in data
        php_error(E_WARNING, "Data must be hex-encoded and only contain hex characters");
        RETVAL_NULL();
        goto lorajoinencryptcleanup;
    }

    if (CheckHex(AppKey, AppKey_Len) == false)
    {
        //Invalid hex characters found in key
        php_error(E_WARNING, "AppKey must be hex-encoded and only contain hex characters");
        RETVAL_NULL();
        goto lorajoinencryptcleanup;
    }

    //Hex decode data
    uint8_t *Data_Dec = malloc(Data_Len/2 + 1);
    uint8_t *AppKey_Dec = malloc(AppKey_Len/2 +1);
    hexStringToBytes(Data_Dec, Data, Data_Len);
    hexStringToBytes(AppKey_Dec, AppKey, AppKey_Len);

    //Encrypt join message
    char *EncryptedStr = malloc(Data_Len/2 + 1);
    LoRaMacJoinEncrypt(Data_Dec, Data_Len/2, AppKey_Dec, EncryptedStr);
    free(Data_Dec);
    free(AppKey_Dec);

    //Encode in hex
    char *EncryptedStr_Hex = emalloc(Data_Len + 1);
    bytesToHexString(EncryptedStr_Hex, EncryptedStr, Data_Len/2);
    free(EncryptedStr);

    //Return to PHP
    RETVAL_STRINGL(EncryptedStr_Hex, Data_Len);

    //Clean up
    if (EncryptedStr_Hex)
    {
        efree(EncryptedStr_Hex);
    }
#else
    if (Data_Len != JOINMSG_LEN && Data_Len != JOINMSG_CF_LEN)
    {
        //Data must 16 or 32 bytes unencoded
        php_error(E_WARNING, "Data must be 16-bytes (without optional CF list) or 32-bytes (with optional CF list)");
        RETVAL_NULL();
        goto lorajoinencryptcleanup;
    }

    if (AppKey_Len != APPKEY_LEN)
    {
        //Key must be 16 bytes unencoded
        php_error(E_WARNING, "AppKey must be 16-bytes");
        RETVAL_NULL();
        goto lorajoinencryptcleanup;
    }

    //Encrypt join message
    char *EncryptedStr = emalloc(Data_Len + 1);
    LoRaMacJoinEncrypt(Data, Data_Len, AppKey, EncryptedStr);

    //Return to PHP
    RETVAL_STRINGL(EncryptedStr, Data_Len);

    //Clean up
    if (EncryptedStr)
    {
        efree(EncryptedStr);
    }
#endif

lorajoinencryptcleanup:
    if (Data_Len)
    {
//        efree(Data);
    }

    if (AppKey_Len)
    {
//        efree(AppKey);
    }

    return;
}

PHP_FUNCTION(lorajoindecrypt)
{
    //Decrypts a join message
    char *Data, *AppKey;
    size_t Data_Len, AppKey_Len;

    if (ZEND_NUM_ARGS() != 2)
    {
        //Need both parameters
        php_error(E_WARNING, "2 parameters must be supplied");
        RETURN_NULL();
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &Data, &Data_Len, &AppKey, &AppKey_Len) == FAILURE)
    {
        RETURN_NULL();
    }

    //Check lengths
#ifdef USE_HEX
    if (Data_Len != JOINMSG_HEX_LEN && Data_Len != JOINMSG_CF_HEX_LEN)
    {
        //Data must 16 or 32 bytes unencoded
        php_error(E_WARNING, "Data must be 32-bytes (without optional CF list) or 64-bytes (with optional CF list) (hex-encoded)");
        RETVAL_NULL();
        goto lorajoindecryptcleanup;
    }

    if (AppKey_Len != APPKEY_HEX_LEN)
    {
        //Key must be 16 bytes unencoded
        php_error(E_WARNING, "AppKey must be 32-bytes (hex-encoded)");
        RETVAL_NULL();
        goto lorajoindecryptcleanup;
    }

    //Check for invalid characters
    if (CheckHex(Data, Data_Len) == false)
    {
        //Invalid hex characters found in data
        php_error(E_WARNING, "Data must be hex-encoded and only contain hex characters");
        RETVAL_NULL();
        goto lorajoindecryptcleanup;
    }

    if (CheckHex(AppKey, AppKey_Len) == false)
    {
        //Invalid hex characters found in key
        php_error(E_WARNING, "AppKey must be hex-encoded and only contain hex characters");
        RETVAL_NULL();
        goto lorajoindecryptcleanup;
    }

    //Hex decode data
    uint8_t *Data_Dec = malloc(Data_Len/2 + 1);
    uint8_t *AppKey_Dec = malloc(AppKey_Len/2 +1);
    hexStringToBytes(Data_Dec, Data, Data_Len);
    hexStringToBytes(AppKey_Dec, AppKey, AppKey_Len);

    //Decrypt join message
    char *DecryptedStr = malloc(Data_Len/2 + 1);
    LoRaMacJoinDecrypt(Data_Dec, Data_Len/2, AppKey_Dec, DecryptedStr);
    free(Data_Dec);
    free(AppKey_Dec);

    //Encode in hex
    char *DecryptedStr_Hex = emalloc(Data_Len + 1);
    bytesToHexString(DecryptedStr_Hex, DecryptedStr, Data_Len/2);
    free(DecryptedStr);

    //Return to PHP
    RETVAL_STRINGL(DecryptedStr_Hex, Data_Len);

    //Clean up
    if (DecryptedStr_Hex)
    {
        efree(DecryptedStr_Hex);
    }
#else
    if (Data_Len != JOINMSG_LEN && Data_Len != JOINMSG_CF_LEN)
    {
        //Data must 16 or 32 bytes unencoded
        php_error(E_WARNING, "Data must be 16-bytes (without optional CF list) or 32-bytes (with optional CF list)");
        RETVAL_NULL();
        goto lorajoindecryptcleanup;
    }

    if (AppKey_Len != APPKEY_LEN)
    {
        //Key must be 16 bytes unencoded
        php_error(E_WARNING, "AppKey must be 16-bytes");
        RETVAL_NULL();
        goto lorajoindecryptcleanup;
    }

    //Decrypt join message
    char *DecryptedStr = emalloc(Data_Len + 1);
    LoRaMacJoinDecrypt(Data, Data_Len, AppKey, DecryptedStr);

    //Return to PHP
    RETVAL_STRINGL(DecryptedStr, Data_Len);

    //Clean up
    if (DecryptedStr)
    {
        efree(DecryptedStr);
    }
#endif

lorajoindecryptcleanup:
    if (Data_Len)
    {
//        efree(Data);
    }

    if (AppKey_Len)
    {
//        efree(AppKey);
    }

    return;
}

PHP_FUNCTION(lorajoincomputeskeys)
{
    //Calculates Network and Application S Keys
    char *AppKey, *AppNonce;
    char *NetworkSKeyStr, *ApplicationSKeyStr;
    long DevNonce;
    size_t AppKey_Len, AppNonce_Len;

    if (ZEND_NUM_ARGS() != 3)
    {
        //Need both parameters
        php_error(E_WARNING, "3 parameters must be supplied");
        RETURN_NULL();
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssl", &AppKey, &AppKey_Len, &AppNonce, &AppNonce_Len, &DevNonce) == FAILURE)
    {
        RETURN_NULL();
    }

    //Check lengths
#ifdef USE_HEX
    if (AppKey_Len != APPKEY_HEX_LEN)
    {
        //Key must be 16 bytes unencoded
        php_error(E_WARNING, "AppKey must be 32-bytes (hex encoded)");
        RETURN_NULL();
    }

    if (AppNonce_Len != APPNONCE_HEX_LEN)
    {
        //Application nonce must be 12 bytes
        php_error(E_WARNING, "App Nonce (including network ID) must be 12-bytes (hex encoded)");
        RETURN_NULL();
    }

    //Check for invalid characters
    if (CheckHex(AppKey, AppKey_Len) == false)
    {
        //Invalid hex characters found in key
        php_error(E_WARNING, "AppKey must be hex-encoded and only contain hex characters");
        RETURN_NULL();
    }

    if (CheckHex(AppNonce, AppNonce_Len) == false)
    {
        //Invalid hex characters found in application nonce
        php_error(E_WARNING, "AppNonce must be hex-encoded and only contain hex characters");
        RETURN_NULL();
    }

    //Hex decode data
    uint8_t *AppKey_Dec = malloc(AppKey_Len/2 + 1);
    uint8_t *AppNonce_Dec = malloc(AppNonce_Len/2 + 1);
    hexStringToBytes(AppKey_Dec, AppKey, AppKey_Len);
    hexStringToBytes(AppNonce_Dec, AppNonce, AppNonce_Len);

    //Compute S Keys
    NetworkSKeyStr = emalloc(NWKSKEY_LEN + 1);
    ApplicationSKeyStr = emalloc(APPSKEY_LEN + 1);
    LoRaMacJoinComputeSKeys(AppKey_Dec, AppNonce_Dec, (uint16_t)DevNonce, NetworkSKeyStr, ApplicationSKeyStr);
    NetworkSKeyStr[NWKSKEY_LEN] = 0;
    ApplicationSKeyStr[APPSKEY_LEN] = 0;
    free(AppKey_Dec);
    free(AppNonce_Dec);
    
    //Encode in hex
    char *NetworkSKeyStr_Hex = emalloc(NWKSKEY_HEX_LEN + 1);
    char *ApplicationSKeyStr_Hex = emalloc(APPSKEY_HEX_LEN + 1);
    bytesToHexString(NetworkSKeyStr_Hex, NetworkSKeyStr_Hex, NWKSKEY_LEN);
    bytesToHexString(ApplicationSKeyStr_Hex, ApplicationSKeyStr, APPSKEY_LEN);
    free(NetworkSKeyStr);
    free(ApplicationSKeyStr);

    //Return hex-encoded S Keys in an array
    array_init(return_value);
    add_index_stringl(return_value, 1, NetworkSKeyStr_Hex, NWKSKEY_HEX_LEN);
    add_index_stringl(return_value, 2, ApplicationSKeyStr_Hex, APPSKEY_HEX_LEN);

    //Clean up
    if (NetworkSKeyStr_Hex)
    {
        efree(NetworkSKeyStr_Hex);
    }

    if (ApplicationSKeyStr_Hex)
    {
        efree(ApplicationSKeyStr_Hex);
    }
#else
    if (AppKey_Len != APPKEY_LEN)
    {
        //Key must be 16 bytes unencoded
        php_error(E_WARNING, "AppKey must be 16-bytes");
        RETURN_NULL();
    }

    if (AppNonce_Len != APPNONCE_LEN)
    {
        //Application nonce must be 6 bytes
        php_error(E_WARNING, "App Nonce (including network ID) must be 6-bytes");
        RETURN_NULL();
    }

    //Compute S Keys
    NetworkSKeyStr = emalloc(NWKSKEY_LEN + 1);
    ApplicationSKeyStr = emalloc(APPSKEY_LEN + 1);
    LoRaMacJoinComputeSKeys(AppKey, AppNonce, (uint16_t)DevNonce, NetworkSKeyStr, ApplicationSKeyStr);
    NetworkSKeyStr[NWKSKEY_LEN] = 0;
    ApplicationSKeyStr[APPSKEY_LEN] = 0;
    
    //Return S Keys in an array
    array_init(return_value);
    add_index_stringl(return_value, 1, NetworkSKeyStr, NWKSKEY_LEN);
    add_index_stringl(return_value, 2, ApplicationSKeyStr, APPSKEY_LEN);

    //Clean up
    if (NetworkSKeyStr)
    {
        efree(NetworkSKeyStr);
    }

    if (ApplicationSKeyStr)
    {
        efree(ApplicationSKeyStr);
    }
#endif

    if (AppKey_Len)
    {
//        efree(AppKey);
    }

    if (AppNonce_Len)
    {
//        efree(AppNonce);
    }

    return;
}
