<?php


use Slim\Http;
use Slim\Views;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;

use Chadicus\Slim\OAuth2\Routes;
use Chadicus\Slim\OAuth2\Middleware;


/**
 * UserId Provider which extracts the user_id from the request Attributes.
 */
final class UserIdProvider implements \Chadicus\Slim\OAuth2\Routes\UserIdProviderInterface
{
    /**
     * Extracts a user_id from the given request attributes, added by the auth middleware.
     *
     * @param ServerRequestInterface $request   The incoming HTTP request.
     * @param array                  $arguments Any route parameters associated with the request.
     *
     * @return string|null The user id if it exists, otherwise null
     */
    public function getUserId(ServerRequestInterface $request, array $arguments = [])
    {
         $queryParams = $request->getQueryParams();
		 //$queryParams = $request->getAttributes();
         return array_key_exists('user_id', $queryParams) ? $queryParams['user_id'] : null;
    }
}


error_log($_SERVER['REQUEST_METHOD']." ".$_SERVER['REQUEST_URI']." ");

$authFunc = new Routes\Authorize($server, $container['view'], '/authorize.phtml',new UserIdProvider() );

$app->map(['get','post'], _SETTINGS['oauthdiscovery']['authorization_endpoint'], $authFunc )->setName('authorize')->add($loginMiddleware);

$app->map(['get','post'], _SETTINGS['oauthdiscovery']['authorization_endpoint']."2", $authFunc )->setName('authorize')->add($authorization);


/* POST endpoint for token */
$app->post( _SETTINGS['oauthdiscovery']['token_endpoint'], new Routes\Token($server))->setName('token');


/* GET userinfo endpoint */
$app->get( _SETTINGS['oauthdiscovery']['userinfo_endpoint'],  function ( $request,  $response, array $args){

	$t = array('token'=>$this->token,'user_id'=>$this->token[ 'user_id']);

	return $response->withJson($t);
})->add($authorization);












/* GET oAuth discovery endpoint. */
$app->get('/.well-known/oauth-authorization-server',  function  ( $request,  $response, array $args) {
	return $response->withJson(_SETTINGS['oauthdiscovery']);
});

/* Weblogin stuff */
if(_SETTINGS['oauthsettings']['weblogin_enabled']==true){



	/* Login page */
	$app->get(_SETTINGS['oauthsettings']['weblogin_endpoint'],  function ( $request,  $response, array $args){

		// has cookie SID ??  Y: redir to referrer.
		$x = $request->getCookieParam('SID');
		// no cookie, show login.
		//print_r($x);
		//die();

		$get = $request->getQueryParams();

		return $this->view->render($response, _SETTINGS['oauthsettings']['weblogin_template'], ['ref' => $get['ref']]);
	});



	$app->post(_SETTINGS['oauthsettings']['weblogin_endpoint'],  function ( $request,  $response, array $args){




		$postvars = $request->getParsedBody();
		//$postvars['login'];
		//$postvars['pass'];
		//$postvars['print'];
		//$postvars['ref'];

		//var_dump($_SERVER);
//die();
		//print_r(_SETTINGS['oauthsettings']['weblogin_clientid']);
		//return $response->withStatus(404);
		error_log("Posting logindata to '"._SETTINGS['oauthdiscovery']['issuer']._SETTINGS['oauthdiscovery']['token_endpoint']."'");
		error_log("clientid:"._SETTINGS['oauthsettings']['weblogin_clientid'].",clientsecret:"._SETTINGS['oauthsettings']['weblogin_clientsecret']);
		//die();
		//var_dump('POST'." "._SETTINGS['oauthdiscovery']['issuer']._SETTINGS['oauthdiscovery']['authorization_endpoint']);
		$client = new \GuzzleHttp\Client(['http_errors' => false]);
		$guzzleresponse = $client->request('POST', _SETTINGS['oauthdiscovery']['issuer']._SETTINGS['oauthdiscovery']['token_endpoint'], [
			'auth' => [_SETTINGS['oauthsettings']['weblogin_clientid'],_SETTINGS['oauthsettings']['weblogin_clientsecret']],
			'form_params' => [
				'grant_type' => 'password',
				'username' => $postvars['login'],
				'password' => $postvars['password']
				/*,
				'client_id' => _SETTINGS['oauthsettings']['weblogin_clientid'],
				'client_secret' => _SETTINGS['oauthsettings']['weblogin_clientsecret']/**/
			]
		]);
		$body = $guzzleresponse->getBody();
		//print_r($body->getContents());

		$statuscode = $guzzleresponse->getStatusCode();


		return $response->withJson(json_decode($body->getContents()) )->withStatus($statuscode);


	});



} /* end Weblogin stuff */
