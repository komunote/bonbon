<?php
namespace index;
error_reporting(E_ALL);
require("bonbon.php");
use bonbon\Bonbon as App;

App::getInstance('bonbon')
   ->setConfig(
       [
           'routes' => [
               'routes/main.inc',
               'routes/user.inc',
               'routes/test.inc',
           ],
           'database' => [
               'type' => 'mysql',
               'host' => 'localhost',
               'user' => 'root',
               'password' => '',
               'database_name' => 'david'
           ]
       ]
   )->run();
