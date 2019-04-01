<?php

namespace OAuth2\Storage;

use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;

/**
 * redis storage for all storage types
 *
 * To use, install "predis/predis" via composer
 *
 * Register client:
 * <code>
 *  $storage = new OAuth2\Storage\Redis($redis);
 *  $storage->setClientDetails($app_id, $app_secret, $redirect_uri);
 * </code>
 */
class Redis implements AuthorizationCodeInterface,
    AccessTokenInterface,
    ClientCredentialsInterface,
    UserCredentialsInterface,
    RefreshTokenInterface,
    JwtBearerInterface,
    ScopeInterface,
    OpenIDAuthorizationCodeInterface
{

    private $cache;

    /* The redis client */
    protected $redis;

    /* Configuration array */
    protected $config;

    /**
     * Redis Storage!
     *
     * @param \Predis\Client $redis
     * @param array          $config
     */
    public function __construct($redis, $config=array())
    {
        $this->redis = $redis;
        $this->config = array_merge(array(
            'client_key' => 'oauth_apps:',
            'access_token_key' => 'oauth_access_tokens:',
            'refresh_token_key' => 'oauth_refresh_tokens:',
            'code_key' => 'oauth_authorization_codes:',
            'user_key' => 'oauth_users:',
            'jwt_key' => 'oauth_jwt:',
            'scope_key' => 'oauth_scopes:',
        ), $config);
    }

    protected function getValue($key)
    {
        if ( isset($this->cache[$key]) ) {
            return $this->cache[$key];
        }
        $value = $this->redis->get($key);
        if ( isset($value) ) {
            return json_decode($value, true);
        } else {
            return false;
        }
    }

    protected function setValue($key, $value, $expire=0)
    {
        $this->cache[$key] = $value;
        $str = json_encode($value);
        if ($expire > 0) {
            $seconds = $expire - time();
            $ret = $this->redis->setex($key, $seconds, $str);
        } else {
            $ret = $this->redis->set($key, $str);
        }

        // check that the key was set properly
        // if this fails, an exception will usually thrown, so this step isn't strictly necessary
        return is_bool($ret) ? $ret : $ret->getPayload() == 'OK';
    }

    protected function expireValue($key)
    {
        unset($this->cache[$key]);

        return $this->redis->del($key);
    }

    /* AuthorizationCodeInterface */
    public function getAuthorizationCode($code)
    {
        return $this->getValue($this->config['code_key'] . $code);
    }

    public function setAuthorizationCode($authorization_code, $app_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null)
    {
        return $this->setValue(
            $this->config['code_key'] . $authorization_code,
            compact('authorization_code', 'app_id', 'user_id', 'redirect_uri', 'expires', 'scope', 'id_token'),
            $expires
        );
    }

    public function expireAuthorizationCode($code)
    {
        $key = $this->config['code_key'] . $code;
        unset($this->cache[$key]);

        return $this->expireValue($key);
    }

    /* UserCredentialsInterface */
    public function checkUserCredentials($username, $password)
    {
        $user = $this->getUserDetails($username);

        return $user && $user['password'] === $password;
    }

    public function getUserDetails($username)
    {
        return $this->getUser($username);
    }

    public function getUser($username)
    {
        if (!$userInfo = $this->getValue($this->config['user_key'] . $username)) {
            return false;
        }

        // the default behavior is to use "username" as the user_id
        return array_merge(array(
            'user_id' => $username,
        ), $userInfo);
    }

    public function setUser($username, $password, $first_name = null, $last_name = null)
    {
        return $this->setValue(
            $this->config['user_key'] . $username,
            compact('username', 'password', 'first_name', 'last_name')
        );
    }

    /* ClientCredentialsInterface */
    public function checkClientCredentials($app_id, $app_secret = null)
    {
        if (!$client = $this->getClientDetails($app_id)) {
            return false;
        }

        return isset($client['app_secret'])
            && $client['app_secret'] == $app_secret;
    }

    public function isPublicClient($app_id)
    {
        if (!$client = $this->getClientDetails($app_id)) {
            return false;
        }

        return empty($client['app_secret']);
    }

    /* ClientInterface */
    public function getClientDetails($app_id)
    {
        return $this->getValue($this->config['client_key'] . $app_id);
    }

    public function setClientDetails($app_id, $app_secret = null, $redirect_uri = null, $grant_types = null, $scope = null, $user_id = null)
    {
        return $this->setValue(
            $this->config['client_key'] . $app_id,
            compact('app_id', 'app_secret', 'redirect_uri', 'grant_types', 'scope', 'user_id')
        );
    }

    public function checkRestrictedGrantType($app_id, $grant_type)
    {
        $details = $this->getClientDetails($app_id);
        if (isset($details['grant_types'])) {
            $grant_types = explode(' ', $details['grant_types']);

            return in_array($grant_type, (array) $grant_types);
        }

        // if grant_types are not defined, then none are restricted
        return true;
    }

    /* RefreshTokenInterface */
    public function getRefreshToken($refresh_token)
    {
        return $this->getValue($this->config['refresh_token_key'] . $refresh_token);
    }

    public function setRefreshToken($refresh_token, $app_id, $user_id, $expires, $scope = null)
    {
        return $this->setValue(
            $this->config['refresh_token_key'] . $refresh_token,
            compact('refresh_token', 'app_id', 'user_id', 'expires', 'scope'),
            $expires
        );
    }

    public function unsetRefreshToken($refresh_token)
    {
        $result = $this->expireValue($this->config['refresh_token_key'] . $refresh_token);

        return $result > 0;
    }

    /* AccessTokenInterface */
    public function getAccessToken($access_token)
    {
        return $this->getValue($this->config['access_token_key'].$access_token);
    }

    public function setAccessToken($access_token, $app_id, $user_id, $expires, $scope = null)
    {
        return $this->setValue(
            $this->config['access_token_key'].$access_token,
            compact('access_token', 'app_id', 'user_id', 'expires', 'scope'),
            $expires
        );
    }

    public function unsetAccessToken($access_token)
    {
        $result = $this->expireValue($this->config['access_token_key'] . $access_token);

        return $result > 0;
    }

    /* ScopeInterface */
    public function scopeExists($scope)
    {
        $scope = explode(' ', $scope);

        $result = $this->getValue($this->config['scope_key'].'supported:global');

        $supportedScope = explode(' ', (string) $result);

        return (count(array_diff($scope, $supportedScope)) == 0);
    }

    public function getDefaultScope($app_id = null)
    {
        if (is_null($app_id) || !$result = $this->getValue($this->config['scope_key'].'default:'.$app_id)) {
            $result = $this->getValue($this->config['scope_key'].'default:global');
        }

        return $result;
    }

    public function setScope($scope, $app_id = null, $type = 'supported')
    {
        if (!in_array($type, array('default', 'supported'))) {
            throw new \InvalidArgumentException('"$type" must be one of "default", "supported"');
        }

        if (is_null($app_id)) {
            $key = $this->config['scope_key'].$type.':global';
        } else {
            $key = $this->config['scope_key'].$type.':'.$app_id;
        }

        return $this->setValue($key, $scope);
    }

    /*JWTBearerInterface */
    public function getClientKey($app_id, $subject)
    {
        if (!$jwt = $this->getValue($this->config['jwt_key'] . $app_id)) {
            return false;
        }

        if (isset($jwt['subject']) && $jwt['subject'] == $subject) {
            return $jwt['key'];
        }

        return null;
    }

    public function setClientKey($app_id, $key, $subject = null)
    {
        return $this->setValue($this->config['jwt_key'] . $app_id, array(
            'key' => $key,
            'subject' => $subject
        ));
    }

    public function getClientScope($app_id)
    {
        if (!$clientDetails = $this->getClientDetails($app_id)) {
            return false;
        }

        if (isset($clientDetails['scope'])) {
            return $clientDetails['scope'];
        }

        return null;
    }

    public function getJti($app_id, $subject, $audience, $expiration, $jti)
    {
        //TODO: Needs redis implementation.
        throw new \Exception('getJti() for the Redis driver is currently unimplemented.');
    }

    public function setJti($app_id, $subject, $audience, $expiration, $jti)
    {
        //TODO: Needs redis implementation.
        throw new \Exception('setJti() for the Redis driver is currently unimplemented.');
    }
}
