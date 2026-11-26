<?php

require __DIR__ . '/../../vendor/autoload.php';

final class ConfigTest extends \Mockery\Adapter\Phpunit\MockeryTestCase
{
    private $server;

    protected function setUp(): void
    {
        parent::setUp();
        $this->server = $_SERVER;
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->server;
        parent::tearDown();
    }

    public function testReturnsHeaderValueUsingNormalizedServerKey()
    {
        $_SERVER['HTTP_X_CUSTOM_HEADER'] = 'header-value123';

        $this->assertSame('header-value123', \Ltb\Config::getValueFromHeader('X-Custom-Header'));
    }

    public function testReturnsEmptyStringWhenHeaderIsMissing()
    {
        unset($_SERVER['HTTP_X_MISSING_HEADER']);

        $this->assertSame('', \Ltb\Config::getValueFromHeader('X-Missing-Header'));
    }

    public function testRemovesCharactersNotAllowedInHeaderValue()
    {
        $_SERVER['HTTP_X_CUSTOM_HEADER'] = 'abc 123!DEF';

        $this->assertSame('abc123DEF', \Ltb\Config::getValueFromHeader('X-Custom-Header'));
    }
}
