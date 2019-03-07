<?php



$container['cache'] = function () {
    return new \Slim\HttpCache\CacheProvider();
};


//var_dump(_SETTINGS['twig']['cache']);
//die();

$container['view'] = function ($c){

	$view = new \Slim\Views\Twig(_SETTINGS['paths']['templates'], [
		'cache' => false /*_SETTINGS['twig']['cache']*/,
		'debug' => _SETTINGS['twig']['debug']
	]);

	// Instantiate and add Slim specific extension
	$basePath = rtrim(str_ireplace('index.php', '', $c->get('request')->getUri()->getBasePath()), '/');

	// Add twigExtension
	$view->addExtension(new \Slim\Views\TwigExtension($c->get('router'), $basePath));

	// Add the debug extension
	if(_SETTINGS['twig']['debug']==true){
		$view->addExtension(new \Twig_Extension_Debug() );
	}

	// add Translation extensions.
	$view->addExtension(new \Twig_Extensions_Extension_I18n());

	//$view->addExtension(new \Twig_Extensions_Extension_Intl());
	//$twig->addExtension(new Project_Twig_Extension());
	//
	//$twig->addFunction('functionName', new Twig_Function_Function('someFunction'));

	if(array_key_exists('sfeBackend',_SETTINGS)){
		//$view->addFunction('functionName', new Twig_Function_Function('someFunction'));

		//$view->addExtension ( new \Botnyx\sfeBackend\twigExtension\Userinfo() );
	}
	return $view;
};
