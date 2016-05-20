<?php
namespace bonbon;
error_reporting(E_ALL);
include("bonbon.php");

$app = App::getInstance();

$app->all("/user/{id}", function($app, $data) {
	echo "user id:{$data['id']}";	
	var_dump($data);
});

$app->get("/user/{id}/name/{name}", function($app, $data) {
	echo "user id:{$data['id']} name:{$data['name']}";	
	var_dump($data);
});

$app->get("/user/{id}/{name}", function($app, $data) {
	echo "user id:{$data['id']} name:{$data['name']}";	
	var_dump($data);
});

$app->get("/home", function() {
	echo "home";	
});

$app->run();
