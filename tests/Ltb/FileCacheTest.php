<?php

require __DIR__ . '/../../vendor/autoload.php';

final class FileCacheTest extends \Mockery\Adapter\Phpunit\MockeryTestCase
{

    public function test_construct(): void
    {
        $cacheInstance = new \Ltb\Cache\FileCache(
                                           "testCache",
                                           0,
                                           null
                                       );
        $this->assertTrue($cacheInstance->cache instanceof Symfony\Component\Cache\Adapter\FilesystemAdapter, "Error while initializing cache object");
    }

}
