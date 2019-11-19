<?php

$err=$_GET['val']; //[] not ()

?>

<html>
	<head>
		<title>No searching result</title>
		<style>
			#head {
			display:block;
			align:center;
			text-align:center;
			font-family:'Lucida Console';
			padding-top:50px;
			}
			#bot {
			display:block;
			align:right;
			text-align:right;
			padding-top:170px;
			padding-right:100px;
			font-style:italic;
			font-size:20px;
			}	

			footer{
			position:fixed;
			right:10px;
			bottom:0px;
			height:50px;
			width:auto;
			font-size:20px;
			font-style:italic;
			}

		</style>
	</head>

	<body>
		<div id='head'>
			<img src=./image/oops.jpg width='400'>
			<h1> Can not found <?php echo "<U>".$err."</U> in server :("; ?></h1>
		</div>

		<footer>
			<a href='./home.html'>---> Click me for go to the main home page.</a>	
		</footer>
	</body>
	
</html>
