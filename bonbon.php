<?php
namespace bonbon;

class App {
    
	private static $instance;
	private static $init	= false;
	private $vars;
	private $routes;
	

    protected function __construct() 
	{	
	
    }
	
	public static function getInstance()
    {
        if (null === static::$instance) {
            static::$instance = new static();
        }
        
        return static::$instance;
    }
	
	private function init() 
	{
		if(!static::$init){
			$this->vars 	?? [];
			$this->routes 	?? [];
			static::$init 	= true;
		}
		return true;		
	}
	
    private function associateKeyValuePair($val1, $val2)
	{		
		$param = [];
		foreach($val1 as $i => $key) {
			if(strpos($key, '{') === 0 && strpos($key, '}')=== (strlen($key) - 1) &&
				isset($val2[$i])) {
				$var = explode('{', $key);
				$var = explode('}', $var[1]);
				$param[$var[0]] = $val2[$i];
			}
		}
		
		return $param;
	}
	
    public function run() 
	{
		$this->init();
		
        $parsedUrl = $this->parseUrl();		
		foreach($this->routes as $verb => $routeItem) {
var_dump($verb);			
			if($_SERVER['REQUEST_METHOD'] !== $verb)
				continue;
			
			foreach($routeItem as $route => $closure) {				
//			
				if ($parsedUrl['path'] === $route) {				
					return $closure($this);
				} else {
					$ex = explode('/', $route);
					$ex2 = explode('/', $parsedUrl['path']);
					
					if (sizeof($ex) !== sizeof($ex2))
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
					
					return $closure($this, $params);
				}
			}
		}
		return false;
    }
	
	public static function config(array $data) 
	{
	
	}
	
	private function parseUrl($url = false) {
		if(!$url) {
			$url = $_SERVER['REQUEST_URI'];
		}
		
		$parsedUrl = parse_url($url);		
		$params = [];
		parse_str($parsedUrl['query']?? null, $params);
		
		return ['path' => route_clean($parsedUrl['path']), 'params' => $params];
	}
	
	private function addRoute (string $verb, string $route, $callback)
	{
		$route = route_clean($route);
		$this->routes[$verb] 			?? [];			
		$this->routes[$verb][$route] 	?? null;
				
		return $this->routes[$verb][$route] = $callback;
	}
	
	public function get(string $route, $callback, $isJSON = true) 
	{		
		return $this->addRoute('GET', $route, $callback);
	}
	
	public function post(string $route, $callback, $isJSON = true) 
	{
		return $this->addRoute('POST', $route, $callback);
	}
	
	public function put(string $route, $callback, $isJSON = true) 
	{
		return $this->addRoute('PUT', $route, $callback);
	}
	
	public function delete(string $route, $callback, $isJSON = true) 
	{
		return $this->addRoute('DELETE', $route, $callback);
	}
	
	public function all(string $route, $callback) 
	{
		$this->addRoute('GET', $route, $callback);
		$this->addRoute('POST', $route, $callback);
		$this->addRoute('PUT', $route, $callback);
		return $this->addRoute('DELETE', $route, $callback);		
	}
	
	
}

function debug($val) {
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
function sha256_crypt($string) {
    return hash_hmac('sha256', $string, 'KoMuNoTe');
}


function route_clean($route) {
    return trim($route, '/');
}

/**
 * protection xss
 */
function xss_clean($data) {
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

/**
 * Variante du var_dump
 * @param type $var
 * @param type $var_name
 * @param type $indent
 * @param string $reference 
 */
function do_dump(&$var, $var_name = NULL, $indent = NULL, $reference = NULL) {
    $do_dump_indent = "<span style='color:#666666;'>|</span> &nbsp;&nbsp; ";
    $reference = $reference . $var_name;
    $keyvar = 'the_do_dump_recursion_protection_scheme';
    $keyname = 'referenced_object_name';

    // So this is always visible and always left justified and readable
    echo "<div style='text-align:left; background-color:white; font: 100% monospace; color:black;'>";

    if (is_array($var) && isset($var[$keyvar])) {
        $real_var = &$var[$keyvar];
        $real_name = &$var[$keyname];
        $type = ucfirst(gettype($real_var));
        echo "$indent$var_name <span style='color:#666666'>$type</span> = <span style='color:#e87800;'>&amp;$real_name</span><br>";
    } else {
        $var = array($keyvar => $var, $keyname => $reference);
        $avar = &$var[$keyvar];

        $type = ucfirst(gettype($avar));
        if ($type == "String")
            $type_color = "<span style='color:#FF00FF'>";
        elseif ($type == "Integer")
            $type_color = "<span style='color:red'>";
        elseif ($type == "Double") {
            $type_color = "<span style='color:#0099c5'>";
            $type = "Float";
        } elseif ($type == "Boolean")
            $type_color = "<span style='color:#92008d'>";
        elseif ($type == "NULL")
            $type_color = "<span style='color:black'>";

        if (is_array($avar)) {
            $count = count($avar);
            echo "$indent" . ($var_name ? "$var_name => " : "") . "<span style='color:#666666'>$type ($count)</span><br>$indent(<br>";
            $keys = array_keys($avar);
            foreach ($keys as $name) {
                $value = &$avar[$name];
                do_dump($value, "[$name]", $indent . $do_dump_indent, $reference);
            }
            echo "$indent)<br>";
        } elseif (is_object($avar)) {
            echo "$indent$var_name <span style='color:#666666'>$type</span><br>$indent(<br>";
            foreach ($avar as $name => $value)
                do_dump($value, "$name", $indent . $do_dump_indent, $reference);
            echo "$indent)<br>";
        } elseif (is_int($avar))
            echo "$indent$var_name = <span style='color:#666666'>$type(" . strlen($avar) . ")</span> $type_color" . htmlentities($avar) . "</span><br>";
        elseif (is_string($avar))
            echo "$indent$var_name = <span style='color:#666666'>$type(" . strlen($avar) . ")</span> $type_color\"" . htmlentities($avar) . "\"</span><br>";
        elseif (is_float($avar))
            echo "$indent$var_name = <span style='color:#666666'>$type(" . strlen($avar) . ")</span> $type_color" . htmlentities($avar) . "</span><br>";
        elseif (is_bool($avar))
            echo "$indent$var_name = <span style='color:#666666'>$type(" . strlen($avar) . ")</span> $type_color" . ($avar == 1 ? "TRUE" : "FALSE") . "</span><br>";
        elseif (is_null($avar))
            echo "$indent$var_name = <span style='color:#666666'>$type(" . strlen($avar) . ")</span> {$type_color}NULL</span><br>";
        else
            echo "$indent$var_name = <span style='color:#666666'>$type(" . strlen($avar) . ")</span> " . htmlentities($avar) . "<br>";

        $var = $var[$keyvar];
    }

    echo "</div>";
}