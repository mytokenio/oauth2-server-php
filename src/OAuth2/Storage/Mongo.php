<?php

namespace OAuth2\Storage;

use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;

/**
 * Simple MongoDB storage for all storage types
 *
 * NOTE: This class is meant to get users started
 * quickly. If your application requires further
 * customization, extend this class or create your own.
 *
 * NOTE: Passwords are stored in plaintext, which is never
 * a good idea.  Be sure to override this for your application
 *
 * @author Julien Chaumond <chaumond@gmail.com>
 */
class Mongo implements AuthorizationCodeInterface,
    AccessTokenInterface,
    ClientCredentialsInterface,
    UserCredentialsInterface,
    RefreshTokenInterface,
    JwtBearerInterface,
    PublicKeyInterface,
    OpenIDAuthorizationCodeInterface
{
    protected $db;
    protected $config;

    public function __construct($connection, $config = array())
    {
        if ($connection instanceof \MongoDB) {
            $this->db = $connection;
        } else {
            if (!is_array($connection)) {
                throw new \InvalidArgumentException('First argument to OAuth2\Storage\Mongo must be an instance of MongoDB or a configuration array');
            }
            $server = sprintf('mongodb://%s:%d', $connection['host'], $connection['port']);
            $m = new \MongoClient($server);
            $this->db = $m->{$connection['database']};
        }

        $this->config = array_merge(array(
            'client_table' => 'oauth_apps',
            'access_token_table' => 'oauth_access_tokens',
            'refresh_token_table' => 'oauth_refresh_tokens',
            'code_table' => 'oauth_authorization_codes',
            'user_table' => 'oauth_users',
            'key_table' => 'oauth_keys',
            'jwt_table' => 'oauth_jwt',
        ), $config);
    }

    // Helper function to access a MongoDB collection by `type`:
    protected function collection($name)
    {
        return $this->db->{$this->config[$name]};
    }

    /* ClientCredentialsInterface */
    public function checkClientCredentials($app_id, $app_secret = null)
    {
        if ($result = $this->collection('client_table')->findOne(array('app_id' => $app_id))) {
            return $result['app_secret'] == $app_secret;
        }

        return false;
    }

    public function isPublicClient($app_id)
    {
        if (!$result = $this->collection('client_table')->findOne(array('app_id' => $app_id))) {
            return false;
        }

        return empty($result['app_secret']);
    }

    /* ClientInterface */
    public function getClientDetails($app_id)
    {
        $result = $this->collection('client_table')->findOne(array('app_id' => $app_id));

        return is_null($result) ? false : $result;
    }

    public function setClientDetails($app_id, $app_secret = null, $redirect_uri = null, $grant_types = null, $scope = null, $user_id = null)
    {
        if ($this->getClientDetails($app_id)) {
            $this->collection('client_table')->update(
                array('app_id' => $app_id),
                array('$set' => array(
                    'app_secret' => $app_secret,
                    'redirect_uri'  => $redirect_uri,
                    'grant_types'   => $grant_types,
                    'scope'         => $scope,
                    'user_id'       => $user_id,
                ))
            );
        } else {
            $client = array(
                'app_id'     => $app_id,
                'app_secret' => $app_secret,
                'redirect_uri'  => $redirect_uri,
                'grant_types'   => $grant_types,
                'scope'         => $scope,
                'user_id'       => $user_id,
            );
            $this->collection('client_table')->insert($client);
        }

        return true;
    }

    public function checkRestrictedGrantType($app_id, $grant_type)
    {
        $details = $this->getClientDetails($app_id);
        if (isset($details['grant_types'])) {
            $grant_types = explode(' ', $details['grant_types']);

            return in_array($grant_type, $grant_types);
        }

        // if grant_types are not defined, then none are restricted
        return true;
    }

    /* AccessTokenInterface */
    public function getAccessToken($access_token)
    {
        $token = $this->collection('access_token_table')->findOne(array('access_token' => $access_token));

        return is_null($token) ? false : $token;
    }

    public function setAccessToken($access_token, $app_id, $user_id, $expires, $scope = null)
    {
        // if it exists, update it.
        if ($this->getAccessToken($access_token)) {
            $this->collection('access_token_table')->update(
                array('access_token' => $access_token),
                array('$set' => array(
                    'app_id' => $app_id,
                    'expires' => $expires,
                    'user_id' => $user_id,
                    'scope' => $scope
                ))
            );
        } else {
            $token = array(
                'access_token' => $access_token,
                'app_id' => $app_id,
                'expires' => $expires,
                'user_id' => $user_id,
                'scope' => $scope
            );
            $this->collection('access_token_table')->insert($token);
        }

        return true;
    }

    public function unsetAccessToken($access_token)
    {
        $result = $this->collection('access_token_table')->remove(array(
            'access_token' => $access_token
        ), array('w' => 1));

        return $result['n'] > 0;
    }


    /* AuthorizationCodeInterface */
    public function getAuthorizationCode($code)
    {
        $code = $this->collection('code_table')->findOne(array('authorization_code' => $code));

        return is_null($code) ? false : $code;
    }

    public function setAuthorizationCode($code, $app_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null)
    {
        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            $this->collection('code_table')->update(
                array('authorization_code' => $code),
                array('$set' => array(
                    'app_id' => $app_id,
                    'user_id' => $user_id,
                    'redirect_uri' => $redirect_uri,
                    'expires' => $expires,
                    'scope' => $scope,
                    'id_token' => $id_token,
                ))
            );
        } else {
            $token = array(
                'authorization_code' => $code,
                'app_id' => $app_id,
                'user_id' => $user_id,
                'redirect_uri' => $redirect_uri,
                'expires' => $expires,
                'scope' => $scope,
                'id_token' => $id_token,
            );
            $this->collection('code_table')->insert($token);
        }

        return true;
    }

    public function expireAuthorizationCode($code)
    {
        $this->collection('code_table')->remove(array('authorization_code' => $code));

        return true;
    }

    /* UserCredentialsInterface */
    public function checkUserCredentials($username, $password)
    {
        if ($user = $this->getUser($username)) {
            return $this->checkPassword($user, $password);
        }

        return false;
    }

    public function getUserDetails($username)
    {
        if ($user = $this->getUser($username)) {
            $user['user_id'] = $user['username'];
        }

        return $user;
    }

    /* RefreshTokenInterface */
    public function getRefreshToken($refresh_token)
    {
        $token = $this->collection('refresh_token_table')->findOne(array('refresh_token' => $refresh_token));

        return is_null($token) ? false : $token;
    }

    public function setRefreshToken($refresh_token, $app_id, $user_id, $expires, $scope = null)
    {
        $token = array(
            'refresh_token' => $refresh_token,
            'app_id' => $app_id,
            'user_id' => $user_id,
            'expires' => $expires,
            'scope' => $scope
        );
        $this->collection('refresh_token_table')->insert($token);

        return true;
    }

    public function unsetRefreshToken($refresh_token)
    {
        $result = $this->collection('refresh_token_table')->remove(array(
            'refresh_token' => $refresh_token
        ), array('w' => 1));

        return $result['n'] > 0;
    }

    // plaintext passwords are bad!  Override this for your application
    protected function checkPassword($user, $password)
    {
        return $user['password'] == $password;
    }

    public function getUser($username)
    {
        $result = $this->collection('user_table')->findOne(array('username' => $username));

        return is_null($result) ? false : $result;
    }

    public function setUser($username, $password, $firstName = null, $lastName = null)
    {
        if ($this->getUser($username)) {
            $this->collection('user_table')->update(
                array('username' => $username),
                array('$set' => array(
                    'password' => $password,
                    'first_name' => $firstName,
                    'last_name' => $lastName
                ))
            );
        } else {
            $user = array(
                'username' => $username,
                'password' => $password,
                'first_name' => $firstName,
                'last_name' => $lastName
            );
            $this->collection('user_table')->insert($user);
        }

        return true;
    }

    public function getClientKey($app_id, $subject)
    {
        $result = $this->collection('jwt_table')->findOne(array(
            'app_id' => $app_id,
            'subject' => $subject
        ));

        return is_null($result) ? false : $result['key'];
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
        //TODO: Needs mongodb implementation.
        throw new \Exception('getJti() for the MongoDB driver is currently unimplemented.');
    }

    public function setJti($app_id, $subject, $audience, $expiration, $jti)
    {
        //TODO: Needs mongodb implementation.
        throw new \Exception('setJti() for the MongoDB driver is currently unimplemented.');
    }

    public function getPublicKey($app_id = null)
    {
        if ($app_id) {
            $result = $this->collection('key_table')->findOne(array(
                'app_id' => $app_id
            ));
            if ($result) {
                return $result['public_key'];
            }
        }

        $result = $this->collection('key_table')->findOne(array(
            'app_id' => null
        ));
        return is_null($result) ? false : $result['public_key'];
    }

    public function getPrivateKey($app_id = null)
    {
        if ($app_id) {
            $result = $this->collection('key_table')->findOne(array(
                'app_id' => $app_id
            ));
            if ($result) {
                return $result['private_key'];
            }
        }

        $result = $this->collection('key_table')->findOne(array(
            'app_id' => null
        ));
        return is_null($result) ? false : $result['private_key'];
    }

    public function getEncryptionAlgorithm($app_id = null)
    {
        if ($app_id) {
            $result = $this->collection('key_table')->findOne(array(
                'app_id' => $app_id
            ));
            if ($result) {
                return $result['encryption_algorithm'];
            }
        }

        $result = $this->collection('key_table')->findOne(array(
            'app_id' => null
        ));
        return is_null($result) ? 'RS256' : $result['encryption_algorithm'];
    }
}
