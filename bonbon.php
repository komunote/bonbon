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
 * Class App
 * @package bonbon
 */
class App
{
    private static $instance;
    private $secret_key;
    private $init = false;
    private $vars;
    private $routes;

    /**
     * App constructor.
     */
    protected function __construct()
    {

    }

    /**
     * @param string $secret_key
     * @return App
     */
    public static function getInstance(string $secret_key)
    {
        if (null === static::$instance) {
            static::$instance = new static();
            static::$instance->init();
        }

        return static::$instance;
    }

    /**
     * @param string $secret_key
     * @return bool
     */
    private function init(string $secret_key = 'BoNBoN')
    {
        if (!$this->init) {
            $this->vars = [];
            $this->routes = [];
            $this->secret_key = $secret_key;
            $this->init = true;
        }
        return true;
    }

    /**
     * Encrypt string into hmac-sha256 with secret key
     *
     * @param type $string
     * @return string 64 caracteres
     */
    public static function sha256_crypt($string)
    {

        return hash_hmac('sha256', $string, self::$secret_key);
    }

    /**
     * @param $data
     * @param bool $isJSON
     */
    public static function send($data, $isJSON = true)
    {
        echo $isJSON ? json_encode($data) : $data;
    }

    /**
     * @param $val1
     * @param $val2
     * @return array
     */
    private function associateKeyValuePair($val1, $val2)
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
     * @return bool
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
     */
    public static function config(array $data)
    {

    }

    /**
     * @param bool $url
     * @return array
     */
    private function parseUrl($url = false)
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
    protected function addRoute(string $verb, string $route, $callback)
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
     * @param bool $isJSON
     * @return App
     */
    public function get(string $route, $callback, $isJSON = true)
    {
        header('Content-Type: application/json;charset=utf-8');

        return $this->addRoute('GET', $route, $callback);
    }

    /**
     * @param string $route
     * @param $callback
     * @param bool $isJSON
     * @return App
     */
    public function post(string $route, $callback, $isJSON = true)
    {
        header('Content-Type: application/json;charset=utf-8');

        return $this->addRoute('POST', $route, $callback);
    }

    /**
     * @param string $route
     * @param $callback
     * @param bool $isJSON
     * @return App
     */
    public function put(string $route, $callback, $isJSON = true)
    {
        header('Content-Type: application/json;charset=utf-8');

        return $this->addRoute('PUT', $route, $callback);
    }

    /**
     * @param string $route
     * @param $callback
     * @param bool $isJSON
     * @return App
     */
    public function delete(string $route, $callback, $isJSON = true)
    {
        header('Content-Type: application/json;charset=utf-8');

        return $this->addRoute('DELETE', $route, $callback);
    }

    /**
     * @param string $route
     * @param $callback
     * @return mixed
     */
    public function all(string $route, $callback)
    {
        header('Content-Type: application/json;charset=utf-8');

        return $this->addRoute('GET', $route, $callback)
                    ->addRoute('POST', $route, $callback)
                    ->addRoute('PUT', $route, $callback)
                    ->addRoute('DELETE', $route, $callback);
    }

    /**
     * @param $route
     * @return mixed|string
     */
    private function route_clean($route)
    {
        return xss_clean(trim(str_replace('//', '/', $route), '/'));
    }
}
