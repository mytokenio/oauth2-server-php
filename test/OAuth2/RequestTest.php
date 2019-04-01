<?php

namespace OAuth2;

use OAuth2\Request\TestRequest;
use OAuth2\Storage\Bootstrap;
use OAuth2\GrantType\AuthorizationCode;
use PHPUnit\Framework\TestCase;

class RequestTest extends TestCase
{
    public function testRequestOverride()
    {
        $request = new TestRequest();
        $server = $this->getTestServer();

        // Smoke test for override request class
        // $server->handleTokenRequest($request, $response = new Response());
        // $this->assertInstanceOf('Response', $response);
        // $server->handleAuthorizeRequest($request, $response = new Response(), true);
        // $this->assertInstanceOf('Response', $response);
        // $response = $server->verifyResourceRequest($request, $response = new Response());
        // $this->assertTrue(is_bool($response));

        /*** make some valid requests ***/

        // Valid Token Request
        $request->setPost(array(
            'grant_type' => 'authorization_code',
            'app_id'  => 'Test Client ID',
            'app_secret' => 'TestSecret',
            'code' => 'testcode',
        ));
        $server->handleTokenRequest($request, $response = new Response());
        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertNull($response->getParameter('error'));
        $this->assertNotNUll($response->getParameter('access_token'));
    }

    public function testHeadersReturnsValueByKey()
    {
        $request = new Request(
            array(),
            array(),
            array(),
            array(),
            array(),
            array(),
            array(),
            array('AUTHORIZATION' => 'Basic secret')
        );

        $this->assertEquals('Basic secret', $request->headers('AUTHORIZATION'));
    }

    public function testHeadersReturnsDefaultIfHeaderNotPresent()
    {
        $request = new Request();

        $this->assertEquals('Bearer', $request->headers('AUTHORIZATION', 'Bearer'));
    }

    public function testHeadersIsCaseInsensitive()
    {
        $request = new Request(
            array(),
            array(),
            array(),
            array(),
            array(),
            array(),
            array(),
            array('AUTHORIZATION' => 'Basic secret')
        );

        $this->assertEquals('Basic secret', $request->headers('Authorization'));
    }

    public function testRequestReturnsPostParamIfNoQueryParamAvailable()
    {
        $request = new Request(
            array(),
            array('app_id' => 'correct')
        );

        $this->assertEquals('correct', $request->query('app_id', $request->request('app_id')));
    }

    public function testRequestHasHeadersAndServerHeaders()
    {
        $request = new Request(
            array(),
            array(),
            array(),
            array(),
            array(),
            array('CONTENT_TYPE' => 'text/xml', 'PHP_AUTH_USER' => 'app_id', 'PHP_AUTH_PW' => 'client_pass'),
            null,
            array('CONTENT_TYPE' => 'application/json')
        );

        $this->assertSame('app_id', $request->headers('PHP_AUTH_USER'));
        $this->assertSame('client_pass', $request->headers('PHP_AUTH_PW'));
        $this->assertSame('application/json', $request->headers('CONTENT_TYPE'));
    }

    private function getTestServer($config = array())
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server($storage, $config);

        // Add the two types supported for authorization grant
        $server->addGrantType(new AuthorizationCode($storage));

        return $server;
    }
}
