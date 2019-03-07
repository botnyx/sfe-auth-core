<?php


session_start();

use OAuth2\Storage;
use OAuth2\GrantType;

use Chadicus\Slim\OAuth2\Routes;
use Chadicus\Slim\OAuth2\Middleware;



/* Database initialization*/
$dboptions = array(
	PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
);

/*  make db connection.  */
try{
	//$pdo = new PDO($ini['database']['pdodsn']  );

	$pdo = new PDO(_SETTINGS['sfeAuth']['conn']['dsn'], _SETTINGS['sfeAuth']['conn']['dbuser'],_SETTINGS['sfeAuth']['conn']['dbpassword'],$dboptions );
	// set the default schema for the oauthserver.
	//$result = $pdo->exec('SET search_path TO oauth2'); # POSTGRESQL Schema support
}catch(Exception $e){
	die($e->getMessage());

}



/* setup storage and oauthserver */
$storage = new Storage\Pdo($pdo);


/* oAuth GrantType setup */
if( in_array('authorization_code',_SETTINGS['oauthdiscovery']['grant_types_supported']) ) {
	$oauthGrants[] = new GrantType\AuthorizationCode($storage);
}
if( in_array('client_credentials',_SETTINGS['oauthdiscovery']['grant_types_supported']) ) {
	$oauthGrants[] = new GrantType\ClientCredentials($storage);
}
if( in_array('password',_SETTINGS['oauthdiscovery']['grant_types_supported']) ) {
	$oauthGrants[] = new GrantType\UserCredentials($storage);
}
if( in_array('refresh_token',_SETTINGS['oauthdiscovery']['grant_types_supported']) ) {
	//$oauthGrants[] = new GrantType\RefreshToken($storage);
}




if( in_array('urn:ietf:params:oauth:grant-type:jwt-bearer',_SETTINGS['oauthdiscovery']['grant_types_supported']) ) {
	$oauthGrants[] = new GrantType\JwtBearer($storage, _SETTINGS['oauthdiscovery']['issuer']);
	$oauthUseJwt = true;

}else{
	$oauthUseJwt = false;
}
if( in_array('implicit',_SETTINGS['oauthdiscovery']['grant_types_supported']) ) {
	$oauthImplicit = true;
}else{
	$oauthImplicit = false;
}


/* Create the oAuth server */
$server = new OAuth2\Server(
    $storage,
    [
        'access_lifetime' => _SETTINGS['oauthsettings']['access_lifetime'],
		'use_jwt_access_tokens' => $oauthUseJwt,
		'allow_implicit' => $oauthImplicit,
		'allow_credentials_in_request_body' => false,
		'issuer' => _SETTINGS['oauthdiscovery']['issuer'],
		'always_issue_new_refresh_token' => false/*,

		'refresh_token_lifetime'         => 2419200,*/
    ],
    $oauthGrants
);




/* Dump database sql */
//die($storage->getBuildSql());
