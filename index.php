<?php
namespace bonbon;

error_reporting(E_ALL);
define('PATH_LIB', '');

include("bonbon.php");
//header('Cache-Control: public, max-age=3600, must-revalidate');
//header('Expires: ' . gmdate("D, d M Y H:i:", $_SERVER['REQUEST_TIME'] + 3600));

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
var_dump($app);
  /*$_SESSION['c'] = Sql::GetSanitizeString('c');
  if ($_SESSION['c'] == '')
    $_SESSION['c'] = 'index';

  $_SESSION['a'] = Sql::GetSanitizeString('a');
  if ($_SESSION['a'] == '')
    $_SESSION['a'] = 'Action';

  // contenu principal        
  $page = new App(PATH_LIB);
  MvcView::set('result', $page->Execute());

  $render = MvcView::Render( PATH_LIB. "_default/view/masterpage.view.php");
  echo $render;*/
 