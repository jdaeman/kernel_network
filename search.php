<?php
require_once("dbconfig.php");
?>

<?php

$title=$_POST['title'];

$query_m="select * from movie ".
	"where title="."'".$title."'";

$query_a="select * from actor ".
	"where name="."'".$title."'";

$fail=0;

$result=mysqli_query($db, $query_m); //db, query sequence

if (mysqli_num_rows($result) == 0)
{
	$result=mysqli_query($db, $query_a);
	mysqli_close($db);

	if (mysqli_num_rows($result) == 0)
	{
		echo "<meta http-equiv='refresh' content='0;url=noret.php?val=$title'>";

	}
	else
	{
		$info=mysqli_fetch_array($result);
		mysqli_close($db);

		echo "<meta http-equiv='refresh' content='0;url=actor.php?index=".$info['a_id']."'>";
	}
}
else
{
	$info=mysqli_fetch_array($result);
	mysqli_close($db);

	echo "<meta http-equiv='refresh' content='0;url=movie.php?index=".$info['m_id']."'>";
}

?> 
