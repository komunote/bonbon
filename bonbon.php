<?php
namespace bonbon;

/**
 * @param $val
 */
function debug($val)
{
    echo "<pre>";
    var_dump($val);
    echo "</pre>";
}

/**
 * XSS filtering
 *
 * @param $data
 * @return mixed|string
 */
function xss_clean($data)
{
    // Fix &entity\n;
    $data = str_replace(array('&amp;', '&lt;', '&gt;'), array('&amp;amp;', '&amp;lt;', '&amp;gt;'), $data);
    $data = preg_replace('/(&#*\w+)[\x00-\x20]+;/u', '$1;', $data);
    $data = preg_replace('/(&#x*[0-9A-F]+);*/iu', '$1;', $data);
    $data = html_entity_decode($data, ENT_COMPAT, 'UTF-8');

    // removes all attributes starting by "on" or xmlns
    $data = preg_replace('#(<[^>]+?[\x00-\x20"\'])(?:on|xmlns)[^>]*+>#iu', '$1>', $data);

    // removes all javascript: and vbscript: protocols
    $data = preg_replace('#([a-z]*)[\x00-\x20]*=[\x00-\x20]*([`\'"]*)[\x00-\x20]*j[\x00-\x20]*a[\x00-\x20]*v[\x00-\x20]*a[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2nojavascript...', $data);
    $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*v[\x00-\x20]*b[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2novbscript...', $data);
    $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*-moz-binding[\x00-\x20]*:#u', '$1=$2nomozbinding...', $data);

    // only for IE: <span style="width: expression(alert('Ping!'));"></span>
    $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?expression[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
    $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?behaviour[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
    $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:*[^>]*+>#iu', '$1>', $data);

    // removes all  elements with namespace
    $data = preg_replace('#</*\w+:\w[^>]*+>#i', '', $data);

    do {
        // removes all unwanted tags
        $old_data = $data;
        $data = preg_replace('#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>]*+>#i', '', $data);
    } while ($old_data !== $data);

    return $data;
}

/**
 * Class Bonbon
 * @package bonbon
 */
class Bonbon
{
    private static $instance;
    private $config;
    private $secret_key;
    private $init = false;
    private $vars;
    private $routes;
    private $token;
    private $errors;

    /**
     * Bonbon constructor.
     * Protected method to prevent new instance with 'new' operator
     */
    protected function __construct()
    {
    }

    /**
     * Private clone method to prevent cloning of the instance of the
     * *Singleton* instance.
     *
     * @return void
     */
    private function __clone()
    {
    }

    /**
     * Private unserialize method to prevent unserializing of the *Singleton*
     * instance.
     *
     * @return void
     */
    private function __wakeup()
    {
    }

    /**
     * @param string $secret_key
     * @return App
     */
    public static function getInstance(string $secret_key = 'BoNBoN')
    {
        if (null === static::$instance) {
            static::$instance = new static();
            static::$instance->init($secret_key);
        }

        return static::$instance;
    }

    /**
     * @param string $secret_key
     * @return bool
     */
    private function init(string $secret_key)
    {
        session_start();
        if (empty($_SESSION['token'])) {
            if (function_exists('mcrypt_create_iv')) {
                $_SESSION['token'] = bin2hex(mcrypt_create_iv(32, MCRYPT_DEV_URANDOM));
            } else {
                $_SESSION['token'] = bin2hex(openssl_random_pseudo_bytes(32));
            }
        }
        $this->token = $_SESSION['token'];

        if (!$this->init) {
            $this->vars = [];
            $this->routes = [];
            $this->secret_key = $secret_key;
            $this->init = true;
            $this->errors = [];
        }
        return true;
    }

    /**
     *
     */
    private function checkCSRFToken() : bool
    {
        if (!empty($_POST['token'])) {
            if (hash_equals($_SESSION['token'], $_POST['token'])) {
                // Proceed to process the form data
                return true;
            } else {
                // Log this as a warning and keep an eye on these attempts
                return false;
            }
        }
    }

    /**
     * Encrypt string into hmac-sha256 with secret key
     *
     * @param string $string
     * @return string
     */
    public static function sha256_crypt(string $string) : string
    {
        return hash_hmac('sha256', $string, self::$secret_key);
    }

    /**
     * @return string
     */
    public static function generateToken()
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * @param $data
     * @param bool $isJSON
     */
    public static function send($data, $isJSON = true)
    {
        if ($isJSON) {
            if (null === $data || false === is_array($data)) {
                $data = [];
            }
            header('Content-Type: application/json;charset=utf-8');

            $data['token'] = static::$instance->token;
            echo $isJSON ? json_encode($data) : $data;
        } else {
            header('Content-Type: text/html;charset=utf-8');
            echo $data;
        }
    }

    /**
     * @param string $filename
     * @param $data
     * @param bool $prefix
     * @return string
     */
    public static function view(string $filename, $data, bool $prefix = false)
    {
        if (null === $data || false === is_array($data)) {
            $data = (array)$data;
        }
        var_dump($data);
        // démarre la temporisation
        ob_start(); //ob_start("ob_gzhandler_no_errors"); ob_start("ob_gzhandler");
        // exporte les variables dans le template en les préfixants de 'var'
        if (count($data)) {
            extract($data, $prefix ? EXTR_PREFIX_ALL : EXTR_PREFIX_SAME, 'var');
        }
        // exécute le template
        include($filename);
        // récupère le flux Html et vide le tampon
        $str = ob_get_contents();
        ob_end_clean();
        return $str;
    }

    /**
     * @param string $filename
     * @param $data
     * @param bool $prefix
     */
    public static function drawView(string $filename, $data, bool $prefix = false)
    {
        static::send(static::view($filename, $data, $prefix), false);
    }

    /**
     * Associate key value pair in Route URL : /name/{value}/id/{id}
     * @param $val1
     * @param $val2
     * @return array
     */
    private function associateKeyValuePair(array $val1, array $val2) : array
    {
        $param = [];

        foreach ($val1 as $i => $key) {
            if (strpos($key, '{') === 0 &&
                strpos($key, '}') === (strlen($key) - 1) &&
                isset($val2[$i])
            ) {
                $param[trim($key, '{}')] = $val2[$i];
            }
        }

        return $param;
    }

    /**
     * @return bool|\Closure
     */
    public function run()
    {
        $parsed_url = $this->parseUrl();

        foreach ($this->routes as $verb => $routeItem) {
            if ($_SERVER['REQUEST_METHOD'] !== $verb)
                continue;

            foreach ($routeItem as $route => $closure) {
                if ($parsed_url['path'] === $route) {
                    return $closure();
                } else {
                    $ex = explode('/', $route);
                    $ex2 = explode('/', $parsed_url['path']);

                    if (count($ex) !== count($ex2))
                        continue;

                    $params = [];

                    foreach ($ex as $key => $value) {
                        if (!isset($ex2[$key])) {
                            break;
                        }
                        if ($ex[$key] !== $ex2[$key])
                            continue;

                        $params = array_merge($this->associateKeyValuePair($ex, $ex2), $params);
                    }

                    return $closure($params);
                }
            }
        }
        return false;
    }

    /**
     * @param array $data
     * @return $this
     */
    public function setConfig(array $data)
    {
        $this->config = $data;

        // configure routes
        if (isset($this->config['routes']) && is_array($this->config['routes'])) {
            foreach ($this->config['routes'] as $route_file) {
                file_exists($route_file) && include($route_file);
            }
        }
        return $this;
    }

    /**
     * @return array
     */
    public function getConfig() : array
    {
        return $this->config;
    }

    /**
     * @param string $query
     * @return bool|\mysqli_result
     */
    public function executeQuery(string $query)
    {
        $config = $this->getConfig();
        $cfgDB = $config['database'];

        $mysqli = new \mysqli($cfgDB['host'], $cfgDB['user'], $cfgDB['password'], $cfgDB['database_name']) or false;

        if (!$mysqli) {
            $this->errors[] = [
                'code' => 55,
                'message' => 'Could not select database'
            ];
            return false;
        }
        $results = $mysqli->query($query);

        if ($mysqli->connect_errno) {
            die('Could not connect: ' . $mysqli->connect_error);
        }

        return $results;
    }

    /**
     * @param bool $url
     * @return array
     */
    private function parseUrl(bool $url = false)
    {
        if (!$url) {
            $url = $_SERVER['REQUEST_URI'];
        }

        $parsedUrl = parse_url($url);
        $params = [];
        parse_str($parsedUrl['query']?? null, $params);

        return ['path' => $this->route_clean($parsedUrl['path']), 'params' => $params];
    }

    /**
     * @param string $verb
     * @param string $route
     * @param $callback
     * @return $this
     */
    protected function addRoute(string $verb, string $route, \Closure $callback)
    {
        $route = $this->route_clean($route);
        if (!isset($this->routes[$verb]) || !is_array($this->routes[$verb])) {
            $this->routes[$verb] = [];
        }

        $this->routes[$verb][$route] = $callback;
        return $this;
    }

    /**
     * @param string $route
     * @param $callback
     * @return Bonbon
     */
    public function get(string $route, \Closure $callback)
    {
        return $this->addRoute('GET', $route, $callback);
    }

    /**
     * @param string $route
     * @param $callback
     * @return Bonbon
     */
    public function post(string $route, \Closure $callback)
    {
        return $this->addRoute('POST', $route, $callback);
    }

    /**
     * @param string $route
     * @param $callback
     * @return Bonbon
     */
    public function put(string $route, \Closure $callback)
    {
        return $this->addRoute('PUT', $route, $callback);
    }

    /**
     * @param string $route
     * @param $callback
     * @return Bonbon
     */
    public function delete(string $route, \Closure $callback)
    {
        return $this->addRoute('DELETE', $route, $callback);
    }

    /**
     * @param string $route
     * @param $callback
     * @return mixed
     */
    public function all(string $route, \Closure $callback)
    {
        return $this->addRoute('GET', $route, $callback)
                    ->addRoute('POST', $route, $callback)
                    ->addRoute('PUT', $route, $callback)
                    ->addRoute('DELETE', $route, $callback);
    }

    /**
     * @param string $route
     * @return mixed|string
     */
    private function route_clean(string $route)
    {
        return xss_clean(trim(str_replace('//', '/', $route), '/'));
    }
}
