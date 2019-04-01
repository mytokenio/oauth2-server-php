<?php

namespace OAuth2\Storage;

/**
 * Implement this interface to specify where the OAuth2 Server
 * should get public/private key information
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
interface PublicKeyInterface
{
    /**
     * @param mixed $app_id
     * @return mixed
     */
    public function getPublicKey($app_id = null);

    /**
     * @param mixed $app_id
     * @return mixed
     */
    public function getPrivateKey($app_id = null);

    /**
     * @param mixed $app_id
     * @return mixed
     */
    public function getEncryptionAlgorithm($app_id = null);
}