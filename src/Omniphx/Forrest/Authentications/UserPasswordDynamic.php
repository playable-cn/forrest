<?php

namespace Omniphx\Forrest\Authentications;

use Omniphx\Forrest\Client as BaseAuthentication;
use Omniphx\Forrest\Interfaces\UserPasswordInterface;

class UserPasswordDynamic extends BaseAuthentication implements UserPasswordInterface
{
    public function setCredentials($stateOptions)
    {
        if (empty($stateOptions)) {
            return;
        }

        $credentialKeys = [
            'loginURL', 'consumerKey', 'consumerSecret', 'username', 'password'
        ];

        foreach ($credentialKeys as $key) {
            if (isset($stateOptions[$key]) && !empty($stateOptions[$key])) {
                $this->credentials[$key] = $stateOptions[$key];
            }
        }
    }

    public function authenticate($stateOptions = [])
    {
        $this->setCredentials($stateOptions);

        $this->checkAuthToken();

        $this->checkVersion();
    }

    public function getTokenRepo()
    {
        return $this->tokenRepo;
    }

    public function getStateRepo()
    {
        return $this->stateRepo;
    }

    public function getVersionRepo()
    {
        return $this->versionRepo;
    }

    public function getResourceRepo()
    {
        return $this->resourceRepo;
    }
    
    /**
     * Refresh authentication token by re-authenticating.
     *
     * @return mixed $response
     */
    public function refresh()
    {
        $tokenURL = $this->credentials['loginURL'] . '/services/oauth2/token';
        $authToken = $this->getAuthToken($tokenURL);

        $this->tokenRepo->put($authToken);
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
     * @param  String $tokenURL
     * @param  Array $parameters
     * @return String
     */
    private function getAuthToken($url)
    {
        $parameters['form_params'] = [
            'grant_type'    => 'password',
            'client_id'     => $this->credentials['consumerKey'],
            'client_secret' => $this->credentials['consumerSecret'],
            'username'      => $this->credentials['username'],
            'password'      => $this->credentials['password'],
        ];

        // \Psr\Http\Message\ResponseInterface
        $response = $this->httpClient->request('post', $url, $parameters);

        $authTokenDecoded = json_decode($response->getBody(), true);

        $this->handleAuthenticationErrors($authTokenDecoded);

        return $authTokenDecoded;
    }

    private function checkAuthToken()
    {
        if (!$this->tokenRepo->has()) {
            $loginURL = $this->credentials['loginURL'];
            $loginURL .= '/services/oauth2/token';
            $authToken = $this->getAuthToken($loginURL);
            $this->tokenRepo->put($authToken);
        }
    }

    private function checkVersion()
    {
        $currentVersion = '';
        if ($this->versionRepo->has()) {
            $currentVersion = $this->versionRepo->get();
        }
        $configVersion = $this->settings['version'];
        
        if (empty($currentVersion) || (!empty($configVersion) && $configVersion != $currentVersion)) {
            $this->storeVersion();
            $this->storeResources();
        }
    }
}
