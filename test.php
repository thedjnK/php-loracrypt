<?PHP
//$Dat = lorapayloadencrypt('1818aa434563', '010203040102030e', 50, 1, 1);
//echo $Dat;

$Done = lorajoincomputemic(
hex2bin("0004040303020201010808070706060505bfff"),
//hex2bin("0001010202030304040505060607070808bfff"), 
//hex2bin("0001010202030304040505060607070808ffbf"), 
hex2bin("00010203040506070809101112131415")
//("15141312121009080706050403020100")
);

echo ": ".bin2hex($Done)."\r\n";

lorasetdatatype(LORA_DATA_RAW);

$MicA = loracomputemic(
hex2bin('6a6b6d6e6f7788227733001144'),
hex2bin('0102030405060708ffbbddee88667722'),
0x25638206,
1,
50);

lorasetdatatype(LORA_DATA_HEX);

$MicA2 = loracomputemic(
'6a6b6d6e6f7788227733001144',
'0102030405060708ffbbddee88667722',
0x25638206,
1,
50);

echo "> ".bin2hex($MicA)."\r\n";
//echo "> ".$MicA."\r\n";
echo "> ".$MicA2."\r\n";

$EncA = lorapayloadencrypt(
hex2bin('01020304050607080902bbccddeeff6655447722885599220011885825953125'),
hex2bin('11223344556677889900112233445588'),
0x11223344,
0,
180);

$DecA = lorapayloaddecrypt(
hex2bin('01020304050607080902bbccddeeff6655447722885599220011885825953125'),
hex2bin('11223344556677889900112233445588'),
0x11223344,
0,
180);

$EncB = lorajoinencrypt(
hex2bin('01020304050607080901020355664433'),
hex2bin('11111111111111111111222222222222')
);

$DecB = lorajoindecrypt(
//hex2bin('06060606059593840583892069382910'),
hex2bin('aabbccddeeff55664477228811772298aabbccddeeff55664477228811772298'),
hex2bin('66554477336655882299110088557733')
);

$Keys = lorajoincomputeskeys(
hex2bin('99999999999999997777777777777777'),
hex2bin('385938592719'),
0x0104
);

echo bin2hex($Done)."\r\n";
echo bin2hex($MicA)."\r\n";
echo bin2hex($EncA)."\r\n";
echo bin2hex($DecA)."\r\n";
echo bin2hex($EncB)."\r\n";
echo bin2hex($DecB)."\r\n";
print_r($Keys)."\r\n";

//e88dec47 ^

$EncB = lorajoinencrypt(
hex2bin('01020304050607080901020355664433'),
hex2bin('11111111111111111111222222222222')
); //FC8D5555C7604328E38CC7E753672FBC

$EncC = lorajoindecrypt(
hex2bin('FC8D5555C7604328E38CC7E753672FBC'),
hex2bin('11111111111111111111222222222222')
);

$EncD = lorajoindecrypt(
hex2bin('55667788C7604328E38CC7E753672FBC'),
hex2bin('111111ff11ee11ab2611222222222222')
); //8B9685C18A6F10B44DC41BAE8125B1AF

$EncE = lorajoinencrypt(
hex2bin('8B9685C18A6F10B44DC41BAE8125B1AF'),
hex2bin('111111ff11ee11ab2611222222222222')
);

echo "Test : ".bin2hex($EncB)."\n";
echo "Test : ".bin2hex($EncC)."\n";
echo "Test : ".bin2hex($EncD)."\n";
echo "Test : ".bin2hex($EncE)."\n";

?>
