<?php

$servername = "localhost";
$username = "rg";
$password = "1234";
$database = "project";

$db = mysqli_connect($servername, $username, $password, $database);

if (!$db)
	die('database connection error');
else
{
	$db->set_charset('utf-8');
	date_default_timezone_set('Asia/Seoul');
}

?>
