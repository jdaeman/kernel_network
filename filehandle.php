<?php

echo '<pre>';
print_r($_FILES);

$path='./upload/';
$tmpname=$_FILES['filename']['tmp_name'];
$name=$_FILES['filename']['name'];

if (move_uploaded_file($tmpname, $path.$name))
{
?>

	<script>
		alert("File upload success");
	</script>
<?php
}
else
{
?>
	<script>
		alert("File upload error");
	</script>
<?php
}

echo "<meta http-equiv='refresh' content='0;url=home.html'>";


?>
