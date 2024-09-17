<?php namespace Ltb\Cache;

use Symfony\Component\Cache\Adapter\FilesystemAdapter;

class FileCache extends \Ltb\Cache\Cache{

    public function __construct(
                          $namespace = 'ltbCache',
                          $defaultLifetime = 0,
                          $directory = null
                      )
    {

        $this->cache = new FilesystemAdapter(
            $namespace,
            $defaultLifetime,
            $directory
        );

        // Clean cache from expired entries
        $this->cache->prune();

    }

}

?>
