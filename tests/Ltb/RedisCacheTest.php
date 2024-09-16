<?php

require __DIR__ . '/../../vendor/autoload.php';

final class RedisCacheTest extends \Mockery\Adapter\Phpunit\MockeryTestCase
{

    public function test_construct(): void
    {
        $redis_url = "dummy";
        $redis_connection = "redis_connection";
        $namespace = "ltbCache";
        $defaultLifetime = 0;

        $redisAdapterMock = Mockery::mock('overload:Symfony\Component\Cache\Adapter\RedisAdapter');

        $redisAdapterMock->shouldreceive('createConnection')
                         ->with( $redis_url )
                         ->andReturn( $redis_connection );

        $redisAdapterMock->shouldReceive('__construct')
                         ->once()
                         ->with(
                                 $redis_connection,
                                 $namespace,
                                 $defaultLifetime
                               );

        $cacheInstance = new \Ltb\Cache\RedisCache(
                                                      $redis_url,
                                                      $namespace,
                                                      $defaultLifetime
                                                  );
        $this->assertTrue($cacheInstance->cache instanceof Symfony\Component\Cache\Adapter\RedisAdapter, "Error while initializing Redis cache object");
    }


}
