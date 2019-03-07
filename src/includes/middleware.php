<?php

use OAuth2\Storage;
use OAuth2\GrantType;

use Chadicus\Slim\OAuth2\Routes;
use Chadicus\Slim\OAuth2\Middleware;


/* add the middleware */
$app->add(function ($request, $response, $next) {
	$sid= \Botnyx\Sfe\Shared\Util::getCookieValue( $request,'SID');
	//$request = $request->withHeader('Authorization', 'Bearer '.$sid);
	//$response = $response->withHeader('Authorization', 'Bearer '.$sid);

	$request = $request->withAttribute('SID', $sid);
	//$request = $request->setQueryParams('access_token', $sid);
	//$response->getBody()->write($x);
	$response = $next($request, $response);
	//$response->getBody()->write('AFTER');
	//$response = $response->withHeader('Authorization', 'Bearer '.$sid);

	return $response;
});




/* create the authorization middleware */
$authorization = new Middleware\Authorization($server, $app->getContainer() );

/* create the authorization middleware */
//Botnyx\Sfe\Auth\Core\LoginMiddleWare
$loginMiddleware = new Botnyx\Sfe\Auth\Core\LoginMiddleWare($server, $app->getContainer() );
