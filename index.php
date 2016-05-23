<?php
namespace bonbon;
error_reporting(E_ALL);
include("bonbon.php");

App::getInstance()
	->all("/user/{id}", 
		function($params)
		{		
			echo json_encode(
				[
					'firstname'	=>	"David--", 
					'lastname'=>		"Chabrier--",
					'for-customers'	=> [
						[
							'id'		=> 1,
							'lastname'	=> "Chabrier 1-",
							'firstname'	=> "David 1-"						
						],
						[						
							'firstname'	=> "David 2-", 
							'lastname'	=> "Chabrier 2-",
							'id'		=> 2
						],
					]
				]
			);
		}
	)->all("/user/{id}/name/{name}", 
		function($params)
		{			
			echo json_encode($params);
		}
	)->get("/user/{id}/{name}", 
		function($params)
		{			
			echo json_encode($params);
		}
	)->post("/user/add", 
		function($params)
		{			
			echo json_encode($params);
		}
	)->get("/home", 
		function()
		{
			echo json_encode(null);
		}
	)->run();
