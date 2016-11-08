<?php
namespace bonbon;
error_reporting(E_ALL);
include("bonbon.php");

App::getInstance('bonbon')
	->setConfig([
		'database' => [
			'type' => 'mysql',
			'host' => 'localhost',
			'user' => 'root',
			'password' => '',
			'database_name' => 'david'
		]
	])
	->all("/user/{id}", 
		function($params)
		{		
			App::send(
				[
					'identity' 			=> [
						'firstname'		=>	"DAVID", 
						'lastname'		=>	"CHABRIER",
						'address'		=>	[
							"city"		=>	"Delray Beach",
							"zipcode"	=>	"33444",
						],
						'customers' => [
							[
								'id'		=> 11,
								'lastname'	=> "Chabrier 11",
								'firstname'	=> "David 11",
								'tels' => [
									[
										
										'type'		=> "mobile",
										'number'	=> "7865414662",
										'emails'	=> [
											'personnal'	=> 'test@abc.com',
											'pro'		=> 'pro@abc.com'
										]
									],
									[						
										'type'		=> "work",
										'number'	=> "3865414662",
										'emails'	=> [
											'personnal'	=> 'test2@abc.com',
											'pro'		=> 'pro2@abc.com'
										]
									],
								]		
							],
							[						
								'firstname'	=> "David 22", 
								'lastname'	=> "Chabrier 22",
								'id'		=> 22,
								'tels' => [
									[
										
										'type'		=> "mobile",
										'number'	=> "7775557777",
										'emails'	=> [
											'personnal'	=> null,
											'pro'		=> null
										]
									],
									[						
										'type'		=> "work",
										'number'	=> "3334445555"										
									],
								]
							],
						]
					],
					'firstname'			=>	"David--", 
					'lastname'			=>	"Chabrier--",					
					'customers'	=> [
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
					],
					'onclick' =>	'customerButtonClick',
					'onchange' =>	'customerTextChange',
				]
			);
		}
	)->all("/user/{firstname}/email/{email}", 
		function($params)
		{	
			$query = "INSERT into USER (`firstname`, `email`) VALUES('" . $params['firstname'] . "', '" . $params['email'] . "')";		
			
			$results = App::getInstance()->executeQuery($query);
			
			App::send(['results' => $results]);
		}
	)->get("/user/{id}/{name}", 
		function($params)
		{			
			App::send($params);
		}
	)->post("/user/add", 
		function($params)
		{			
			App::getConfig();
			App::send($params);
		}
	)->get("/home", 
		function()
		{
			App::send(null);
		}
	)->run();
