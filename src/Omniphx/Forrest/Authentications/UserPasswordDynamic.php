<?php

namespace Omniphx\Forrest\Authentications;

use Omniphx\Forrest\Client as BaseAuthentication;
use Omniphx\Forrest\Interfaces\UserPasswordInterface;

class UserPasswordDynamic extends BaseAuthentication implements UserPasswordInterface
{
    /**
     * set credentials
     * @param array | $credentials
     * @return $this
     */
    public function setCredentials($credentials)
    {
        if (empty($credentials)) {
            return $this;
        }

        $credentialKeys = [
            'loginURL', 'consumerKey', 'consumerSecret', 'username', 'password', 'accessToken', 'refreshToken', 'instanceUrl', 'tokenType'
        ];

        foreach ($credentialKeys as $key) {
            if (isset($credentials[$key]) && !empty($credentials[$key])) {
                $this->credentials[$key] = $credentials[$key];
            }
        }

        return $this;
    }

    /**
     * authenticate
     * @param  array  $credentials authenticate credentials
     * @return bool
     */
    public function authenticate($credentials = [])
    {
        $this->setCredentials($credentials);

        if (isset($this->credentials['accessToken']) && !empty($this->credentials['accessToken'])) {
            $isNew = false;
            $authToken = [
                'access_token' => $this->credentials['accessToken'],
                'instance_url' => $this->credentials['instanceUrl'],
                'token_type' => $this->credentials['tokenType'] ?? 'Bearer'
            ];
            $this->tokenRepo->put($authToken);
            $this->instanceURLRepo->put($this->credentials['instanceUrl']);
        } else {
            $isNew = $this->checkAuthToken();
        }

        $this->checkVersion();

        return $isNew;
    }

    /**
     * get the tokenRepo
     * @return TokenRepository
     */
    public function getTokenRepo()
    {
        return $this->tokenRepo;
    }

    /**
     * get the stateRepo
     * @return StateRepository
     */
    public function getStateRepo()
    {
        return $this->stateRepo;
    }

    /**
     * get the versionRepo
     * @return VersionRepository
     */
    public function getVersionRepo()
    {
        return $this->versionRepo;
    }

    /**
     * get the resourceRepo
     * @return ResourceRepository
     */
    public function getResourceRepo()
    {
        return $this->resourceRepo;
    }
    
    /**
     * Refresh authentication token by re-authenticating.
     *
     * @return mixed
     */
    public function refresh()
    {
        $tokenURL = $this->credentials['loginURL'] . '/services/oauth2/token';
        $authToken = $this->requestAuthToken($tokenURL);

        $this->tokenRepo->put($authToken);

        if ($this->authRefreshCallback) {
            //$this->authRefreshCallback($authToken);
            call_user_func($this->authRefreshCallback, $authToken);
        }

        return $authToken;
    }

    public function getAuthToken($refresh = false)
    {
        if ($refresh || !$this->tokenRepo->has()) {
            $authToken = $this->refresh();
        } else {
            $authToken = $this->tokenRepo->get();
        }

        return $authToken;
    }

    /**
     * Revokes access token from Salesforce. Will not flush token from storage.
     *
     * @return mixed
     */
    public function revoke()
    {
        $accessToken = $this->tokenRepo->get();
        $url = $this->credentials['loginURL'].'/services/oauth2/revoke';

        $options['headers']['content-type'] = 'application/x-www-form-urlencoded';
        $options['form_params']['token'] = $accessToken;

        return $this->httpClient->request('post', $url, $options);
    }

    /**
     * @param  String $url
     * @param  Array $parameters
     * @return String
     */
    protected function requestAuthToken($url)
    {
        if (isset($this->credentials['refreshToken']) && !empty($this->credentials['refreshToken'])) {
            $parameters['form_params'] = [
                'grant_type'    => 'refresh_token',
                'client_id'     => $this->credentials['consumerKey'],
                //'client_secret' => $this->credentials['consumerSecret'],
                'refresh_token' => $this->credentials['refreshToken'],
            ];
        } else {
            $parameters['form_params'] = [
                'grant_type'    => 'password',
                'client_id'     => $this->credentials['consumerKey'],
                'client_secret' => $this->credentials['consumerSecret'],
                'username'      => $this->credentials['username'],
                'password'      => $this->credentials['password'],
            ];
        }

        // \Psr\Http\Message\ResponseInterface
        $response = $this->httpClient->request('post', $url, $parameters);

        $authTokenDecoded = json_decode($response->getBody(), true);

        $this->handleAuthenticationErrors($authTokenDecoded);

        return $authTokenDecoded;
    }

    /**
     * check auth token is cached or request one new
     * @return bool
     */
    protected function checkAuthToken()
    {
        $isNew = false;
        if (!$this->tokenRepo->has()) {
            $this->refresh();
            $isNew = true;
        }
        return $isNew;
    }

    /**
     * check api version.
     * @return void
     */
    protected function checkVersion()
    {
        $currentVersion = '';
        if ($this->versionRepo->has()) {
            $currentVersion = $this->versionRepo->get()['version'];
        }
        $configVersion = $this->settings['version'];
        
        if (empty($currentVersion) || (!empty($configVersion) && $configVersion != $currentVersion)) {
            $this->storeVersion();
        }
        if (!$this->resourceRepo->has()) {
            $this->storeResources();
        }
    }
}
