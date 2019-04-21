<?PHP
if (!extension_loaded('loracrypt') && !dl('loracrypt'))
{
    //LoRaCrypt extension not loaded
    echo 'Unable to load LoRaCrypt PHP extension - check that it is installed correctly and restart your PHP server.';
    die();
}

if ($_POST['Key'] && $_POST['Data'] && $_POST['Address'] && $_POST['Sequence'])
{
    //Data for a packet has been supplied
    $Decrypted = lorapayloaddecrypt(hex2bin($_POST['Data']), hex2bin($_POST['Key']), $_POST['Address'], (isset($_POST['Direction']) ? 1 : 0), $_POST['Sequence']);
    if ($Decrypted === null)
    {
        //Invalid data
        echo 'Supplied data is not valid.<br><br>';
    }
    else
    {
        //Data check passed
        $Decrypted = bin2hex($Decrypted);
        echo 'Decrypted packet: '.$Decrypted.'<br><br>';
    }
}

//Show fields for decrypting data
?>
Decrypt a LoRa packet:<br>
<form action="" method="POST">
Key (hex): <input type="text" name="Key" id="Key"><br>
Data (hex): <input type="text" name="Data" id="Data"><br>
Address: <input type="text" name="Address" id="Address"><br>
Direction: <input type="checkbox" name="Direction" id="Direction"> <label for="Direction">Downlink</label><br>
Sequence Number: <input type="text" name="Sequence" id="Sequence"><br>
<input type="submit" value="Decrypt">
</form>

