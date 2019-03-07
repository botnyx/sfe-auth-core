<?php

namespace Botnyx\Sfe\Auth\Core;

use ArrayAccess;
use Chadicus\Slim\OAuth2\Http\RequestBridge;
use Chadicus\Slim\OAuth2\Http\ResponseBridge;
use Chadicus\Psr\Middleware\MiddlewareInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use OAuth2;

/**
 * Slim Middleware to handle OAuth2 Authorization.
 */
class LoginMiddleWare implements MiddlewareInterface
{
    /**
     * @var string
     */
    const TOKEN_ATTRIBUTE_KEY = 'oauth2-token';

    /**
     * OAuth2 Server
     *
     * @var OAuth2\Server
     */
    private $server;

    /**
     * Array of scopes required for authorization.
     *
     * @var array
     */
    private $scopes;

    /**
     * Container for token.
     *
     * @var mixed
     */
    private $container;

    /**
     * Create a new instance of the Authroization middleware.
     *
     * @param OAuth2\Server $server    The configured OAuth2 server.
     * @param mixed         $container A container object in which to store the token from the request.
     * @param array         $scopes    Scopes required for authorization. $scopes can be given as an
     *                                 array of arrays. OR logic will use with each grouping.
     *                                 Example:
     *                                 Given ['superUser', ['basicUser', 'aPermission']], the request
     *                                 will be verified if the request token has 'superUser' scope
     *                                 OR 'basicUser' and 'aPermission' as its scope.
     *
     * @throws \InvalidArgumentException Thrown if $container is not an instance of ArrayAccess or ContainerInterface.
     */
    public function __construct(OAuth2\Server $server, $container, array $scopes = [])
    {
        $this->server = $server;
        $this->container = $this->validateContainer($container);
        $this->scopes = $this->formatScopes($scopes);
    }

    /**
     * Execute this middleware.
     *
     * @param  ServerRequestInterface $request  The PSR7 request.
     * @param  ResponseInterface      $response The PSR7 response.
     * @param  callable               $next     The Next middleware.
     *
     * @return ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, callable $next)
    {
        error_log("__invoke");
		$sid= $this->getCookieValue( $request,'SID');
		$referrer = $request->getHeader("HTTP_REFERER")[0];
		//error_log(json_encode($sid));

		if(!is_null($sid)){
			error_log("COOKIE IS NOT NULL, ADDING HEADER");
			$request = $request->withHeader('Authorization', 'Bearer '.$sid);

			/* get all request query params. */
			$array = $request->getQueryParams();

			/* Add the acces_token to the queryparams. */
			$array['access_token'] = $sid;
			/* Add the queryparams to the request */
			$request = $request->withQueryParams( $array );
		}



		$oauth2Request = RequestBridge::toOAuth2($request);
        foreach ($this->scopes as $scope) {
            if ($this->server->verifyResourceRequest($oauth2Request, null, $scope)) {
                $token = $this->server->getResourceController()->getToken();
                $this->setToken($token);

				/* get all request query params. */
				$array = $request->getQueryParams();
				$array['user_id'] = $token['user_id'];
				return $next($request->withAttribute(self::TOKEN_ATTRIBUTE_KEY, $token)->withQueryParams($array), $response);
            }
        }

        $response = ResponseBridge::fromOauth2($this->server->getResponse());

		$status = $response->getStatusCode();

		/* check if authorization failed, then show the login page.*/
		if($status==401){
			return $this->container->get('view')->render($response,_SETTINGS['oauthsettings']['weblogin_template'], ['referrer' => $referrer]);
		}


        if ($response->hasHeader('Content-Type')) {
            return $response;
        }

        return $response->withHeader('Content-Type', 'application/json');
    }

	/**
     * Helper method to get the cookie from the request
	 * Cookie helper func.
	 */
	private function getCookieValue(\Slim\Http\Request $request, $cookieName)
	{
		$cookies = $request->getCookieParams();
		return isset($cookies[$cookieName]) ? $cookies[$cookieName] : null;
	}





    /**
     * Helper method to set the token value in the container instance.
     *
     * @param array $token The token from the incoming request.
     *
     * @return void
     */
    private function setToken(array $token)
    {
        if (is_a($this->container, '\\ArrayAccess')) {
            $this->container['token'] = $token;
            return;
        }

        $this->container->set('token', $token);
    }

    /**
     * Returns a callable function to be used as a authorization middleware with a specified scope.
     *
     * @param array $scopes Scopes require for authorization.
     *
     * @return Authorization
     */
    public function withRequiredScope(array $scopes)
    {
        $clone = clone $this;
        $clone->scopes = $clone->formatScopes($scopes);
        return $clone;
    }

    /**
     * Helper method to ensure given scopes are formatted properly.
     *
     * @param array $scopes Scopes required for authorization.
     *
     * @return array The formatted scopes array.
     */
    private function formatScopes(array $scopes)
    {
        if (empty($scopes)) {
            return [null]; //use at least 1 null scope
        }

        array_walk(
            $scopes,
            function (&$scope) {
                if (is_array($scope)) {
                    $scope = implode(' ', $scope);
                }
            }
        );

        return $scopes;
    }

    private function validateContainer($container)
    {
        if (is_a($container, ArrayAccess::class)) {
            return $container;
        }

        if (method_exists($container, 'set')) {
            return $container;
        }

        throw new \InvalidArgumentException("\$container does not implement ArrayAccess or contain a 'set' method");
    }
}
