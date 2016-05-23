<?php
namespace bonbon;

class App {
    
	private static $instance;
	private $init = false;
	private $vars;
	private $routes;
	

    protected function __construct() 
	{	
	
    }
	
	public static function getInstance()
    {
        if (null === static::$instance) {
            static::$instance = new static();
			static::$instance->init();
        }
        
        return static::$instance;
    }
	
	private function init()
	{
		if(!$this->init){
			$this->vars 	?? [];
			$this->routes 	?? [];
			$this->init 	= true;
		}
		return true;		
	}
	
    private function associateKeyValuePair($val1, $val2)
	{		
		$param = [];
		foreach($val1 as $i => $key) {
			if(strpos($key, '{') === 0 && strpos($key, '}')=== (strlen($key) - 1) &&
				isset($val2[$i])) {
				$param[trim($key, '{}')] = $val2[$i];
			}
		}
		
		return $param;
	}
	
    public function run() 
	{
        $parsedUrl = $this->parseUrl();		
		foreach($this->routes as $verb => $routeItem) {			
			if($_SERVER['REQUEST_METHOD'] !== $verb)
				continue;
			
			foreach($routeItem as $route => $closure) {				
				if ($parsedUrl['path'] === $route) {				
					return $closure();
				} else {
					$ex = explode('/', $route);
					$ex2 = explode('/', $parsedUrl['path']);
					
					if (count($ex) !== count($ex2))
						continue;
					
					$params = [];
					
					foreach($ex as $key => $value) {
						if( !isset($ex2[$key])) {
							break;
						}
						if($ex[$key] !== $ex2[$key]) 
							continue;					
					
						$params = array_merge($this->associateKeyValuePair($ex, $ex2), $params);
					}					
					
					return $closure($params);
				}
			}
		}
		return false;
    }
	
	public static function config(array $data) 
	{
	
	}
	
	private function parseUrl($url = false) 
	{
		if(!$url) {
			$url = $_SERVER['REQUEST_URI'];
		}
		
		$parsedUrl = parse_url($url);		
		$params = [];
		parse_str($parsedUrl['query']?? null, $params);
		
		return ['path' => $this->route_clean($parsedUrl['path']), 'params' => $params];
	}
	
	private function addRoute (string $verb, string $route, $callback)
	{
		$route = $this->route_clean($route);
		$this->routes[$verb] 			?? [];			
		$this->routes[$verb][$route] 	?? null;
				
		return $this->routes[$verb][$route] = $callback;
	}
	
	public function get(string $route, $callback, $isJSON = true) 
	{
		header('Content-Type: application/json;charset=utf-8');
		$this->addRoute('GET', $route, $callback);
		return $this;
	}
	
	public function post(string $route, $callback, $isJSON = true) 
	{
		header('Content-Type: application/json;charset=utf-8');
		$this->addRoute('POST', $route, $callback);
		return $this;
	}
	
	public function put(string $route, $callback, $isJSON = true) 
	{
		header('Content-Type: application/json;charset=utf-8');
		$this->addRoute('PUT', $route, $callback);
		return $this;
	}
	
	public function delete(string $route, $callback, $isJSON = true) 
	{
		header('Content-Type: application/json;charset=utf-8');
		$this->addRoute('DELETE', $route, $callback);
		return $this;
	}
	
	public function all(string $route, $callback) 
	{
		header('Content-Type: application/json;charset=utf-8');
		$this->addRoute('GET', $route, $callback);
		$this->addRoute('POST', $route, $callback);
		$this->addRoute('PUT', $route, $callback);
		$this->addRoute('DELETE', $route, $callback);
		return $this;
	}
	
	private function route_clean($route) {
		$route = xss_clean(trim(str_replace('//', '/', $route), '/'));
		//var_dump($route);
		return $route;
	}
	
	
}

function debug($val) 
{
    echo "<pre>";
    var_dump($val);
    echo "</pre>";
}

/**
 * Crypte une chaine en hmac sha256 via une cle secrete
 * 
 * @param type $string
 * @return string 64 caracteres
 */
function sha256_crypt($string, $key = 'BoNBoN') 
{
    return hash_hmac('sha256', $string, $key);
}

/**
 * protection xss
 */
function xss_clean($data) 
{
	// Fix &entity\n;
    $data = str_replace(array('&amp;', '&lt;', '&gt;'), array('&amp;amp;', '&amp;lt;', '&amp;gt;'), $data);
    $data = preg_replace('/(&#*\w+)[\x00-\x20]+;/u', '$1;', $data);
    $data = preg_replace('/(&#x*[0-9A-F]+);*/iu', '$1;', $data);
    $data = html_entity_decode($data, ENT_COMPAT, 'UTF-8');

	// supprime tout attribut commencant par "on" ou xmlns
    $data = preg_replace('#(<[^>]+?[\x00-\x20"\'])(?:on|xmlns)[^>]*+>#iu', '$1>', $data);

	// supprime tout javascript: et vbscript: protocoles
    $data = preg_replace('#([a-z]*)[\x00-\x20]*=[\x00-\x20]*([`\'"]*)[\x00-\x20]*j[\x00-\x20]*a[\x00-\x20]*v[\x00-\x20]*a[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2nojavascript...', $data);
    $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*v[\x00-\x20]*b[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2novbscript...', $data);
    $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*-moz-binding[\x00-\x20]*:#u', '$1=$2nomozbinding...', $data);

	// uniquement avec IE: <span style="width: expression(alert('Ping!'));"></span>
    $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?expression[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
    $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?behaviour[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
    $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:*[^>]*+>#iu', '$1>', $data);

	// supprime les elements avec un namespace
    $data = preg_replace('#</*\w+:\w[^>]*+>#i', '', $data);

    do {
		// supprime reellement les tags non desires
        $old_data = $data;
        $data = preg_replace('#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>]*+>#i', '', $data);
    } while ($old_data !== $data);

    return $data;
}
