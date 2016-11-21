# bonbon
micro REST API framework


##Setup :

###- .htaccess
```java
<IfModule mod_rewrite.c>
RewriteEngine on
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d

RewriteRule ^(.*)$ /index.php?app=$1&controler=0&process=0 [NC,L,QSA]
</IfModule>
```

###- index.php

```php
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
   ```
   
###- routes/main.php (example)
   ```php
   <?php
namespace bonbon;

use bonbon\Bonbon as App;

App::getInstance()
   ->get('/home',
       function () {
           App::drawView('/views/home.php', ['test' => 'blabla', 'var_test' => 'blabla 2']);
       }
   );
   ```

###- views/home.php
```html
<p>Home page with REST API : <?php echo $test, $var_test?></p>
```
