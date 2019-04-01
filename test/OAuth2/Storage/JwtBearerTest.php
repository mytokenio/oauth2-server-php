<?php

namespace OAuth2\Storage;

class JwtBearerTest extends BaseTest
{
    /** @dataProvider provideStorage */
    public function testGetClientKey(JwtBearerInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        // nonexistant app_id
        $key = $storage->getClientKey('this-is-not-real', 'nor-is-this');
        $this->assertFalse($key);

        // valid app_id and subject
        $key = $storage->getClientKey('oauth_test_client', 'test_subject');
        $this->assertNotNull($key);
        $this->assertEquals($key, Bootstrap::getInstance()->getTestPublicKey());
    }
}
