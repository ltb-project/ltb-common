<?php namespace Ltb\Cache;

use Symfony\Component\Cache\Adapter\RedisAdapter;

class RedisCache extends \Ltb\Cache\Cache{

    public function __construct(
                          $redis_url,
                          $namespace = 'ltbCache',
                          $defaultLifetime = 0,
                      )
    {

        $redis_connection = RedisAdapter::createConnection( $redis_url );

        $this->cache = new RedisAdapter(
            $redis_connection,
            $namespace,
            $defaultLifetime,
        );

    }

}

?>
