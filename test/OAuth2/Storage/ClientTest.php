<?php

namespace OAuth2\Storage;

class ClientTest extends BaseTest
{
    /** @dataProvider provideStorage */
    public function testGetClientDetails(ClientInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        // nonexistant app_id
        $details = $storage->getClientDetails('fakeclient');
        $this->assertFalse($details);

        // valid app_id
        $details = $storage->getClientDetails('oauth_test_client');
        $this->assertNotNull($details);
        $this->assertArrayHasKey('app_id', $details);
        $this->assertArrayHasKey('app_secret', $details);
        $this->assertArrayHasKey('redirect_uri', $details);
    }

    /** @dataProvider provideStorage */
    public function testCheckRestrictedGrantType(ClientInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        // Check invalid
        $pass = $storage->checkRestrictedGrantType('oauth_test_client', 'authorization_code');
        $this->assertFalse($pass);

        // Check valid
        $pass = $storage->checkRestrictedGrantType('oauth_test_client', 'implicit');
        $this->assertTrue($pass);
    }

    /** @dataProvider provideStorage */
    public function testGetAccessToken(ClientInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        // nonexistant app_id
        $details = $storage->getAccessToken('faketoken');
        $this->assertFalse($details);

        // valid app_id
        $details = $storage->getAccessToken('testtoken');
        $this->assertNotNull($details);
    }

    /** @dataProvider provideStorage */
    public function testIsPublicClient(ClientInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        $publicAppId = 'public-client-'.rand();
        $confidentialAppId = 'confidential-client-'.rand();

        // create a new client
        $success1 = $storage->setClientDetails($publicAppId, '');
        $success2 = $storage->setClientDetails($confidentialAppId, 'some-secret');
        $this->assertTrue($success1);
        $this->assertTrue($success2);

        // assert isPublicClient for both
        $this->assertTrue($storage->isPublicClient($publicAppId));
        $this->assertFalse($storage->isPublicClient($confidentialAppId));
    }

    /** @dataProvider provideStorage */
    public function testSaveClient(ClientInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        $AppId = 'some-client-'.rand();

        // create a new client
        $success = $storage->setClientDetails($AppId, 'somesecret', 'http://test.com', 'client_credentials', 'clientscope1', 'brent@brentertainment.com');
        $this->assertTrue($success);

        // valid app_id
        $details = $storage->getClientDetails($AppId);
        $this->assertEquals($details['app_secret'], 'somesecret');
        $this->assertEquals($details['redirect_uri'], 'http://test.com');
        $this->assertEquals($details['grant_types'], 'client_credentials');
        $this->assertEquals($details['scope'], 'clientscope1');
        $this->assertEquals($details['user_id'], 'brent@brentertainment.com');
    }
}
