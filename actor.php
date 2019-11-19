<?php
require_once('dbconfig.php');

$id=$_GET['index'];
$query=
	"select * from actor ".
	"where a_id=$id";

$result=mysqli_query($db, $query);
$info=mysqli_fetch_array($result);

$query1=
	"select * from awards ".
	"where a_id=$id";
$result1=mysqli_query($db, $query1);

$query2=
	"with career(id) as ".
	"(select m_id ".
	"from cast ".
	"where a_id=$id) ".
	"select movie.m_id, movie.title ".
	"from movie, career ".
	"where movie.m_id=career.id";
$result2=mysqli_query($db, $query2);
?>


<html>
	<head>
		<title>Actor Information</title>

		<style>
		
		#profile {
		display:block;
		float:left;
		margin-right:20px;
		}

		.test {
		}

		.title {
		text-align:center;
		}

		.bound {
		display:block;
		float:left;
		margin-left:20px;
		margin-right:30px;
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
		<div class='test bound'>
			<div class='test title' style='display:block'>
				<h1>Profile</h1>
			</div>

			<div class='test' id='profile'>
				<img src=./image/actor/<?php echo $id?>.jpg width='300px'>
			</div>

			<div class='test' id='profile'>

				<div class='test' style='display:block'>	
				<?php
					echo "이름: ".$info['name']."<br>";
					echo "성별: ";
					if ($info['gender'] == 'male')
						echo "남자<br>";
					else
						echo "여자<br>";
					echo "생년월일: ".$info['birth']."<br><br>";
				?>
				</div>

				<div class='test' style='display:block'>
				
					<div class='test title'>	
						<h2>수상 경력</h2>
					</div>
				<?php
					while ($info=mysqli_fetch_array($result1))
					{
						echo $info['year']."년---";
						echo $info['award']."<br>";
					}
				?>
				</div>
			</div>
		</div>
		

		<div class='test bound'>
			<div class='test title' style='display:block'>
				<h1>Movie Career</h1>
			</div>

			<?php
			$cnt=1;
			while ($info=mysqli_fetch_array($result2))
			{
				$index=$info['m_id'];
				$title=$info['title'];
				
				echo $cnt."->   ";
				echo "<a href='movie.php?index=$index'>$title</a>";
				echo "<br><br>";
				$cnt+=1;
			}
			?>

		</div>

		
		<footer>
			<a href='home.html'>---> Click me for go to main home page</a>
	 	</footer>
	</body>


</html>
