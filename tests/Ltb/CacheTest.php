<?php

require __DIR__ . '/../../vendor/autoload.php';

final class CacheTest extends \Mockery\Adapter\Phpunit\MockeryTestCase
{

    public function test_generate_form_token(): void
    {

        $cacheInstance = new \Ltb\Cache\FileCache(
                                           "testCache",
                                           0,
                                           null
                                       );

        $generated_token = "";

        $cacheInstance->cache = Mockery::mock('FilesystemAdapter');
        $cacheInstance->cache->shouldreceive('getItem')
                      ->andReturnUsing(
                          function($token) use (&$generated_token){
                              $generated_token = $token;

                              $cacheItem = Mockery::mock('CacheItem');

                              $cacheItem->shouldreceive('set')
                                            ->andReturnUsing(
                                                function($formtoken) use (&$token) {
                                                    $this->assertEquals($formtoken,
                                                                        $token,
                                                                        "Error: received token in set ($formtoken) is different from received token in getItem ($token)");
                                                }
                                            );

                              $cacheItem->shouldreceive('expiresAfter')
                                            ->with(120);

                              return $cacheItem;
                          }
                      );

        $cacheInstance->cache->shouldreceive('save');

        $receivedToken = $cacheInstance->generate_form_token(120);
        $this->assertEquals("$receivedToken",
                            $generated_token,
                            "Error: received token in generate_form_token ($receivedToken) is different from received token in getItem ($generated_token)");

    }

    public function test_verify_form_token_ok(): void
    {

        $generated_token = "e712b08e55f8977e2b9ecad35d5180ed24345e76607413411e90df66b9538fa1";

        $cacheInstance = new \Ltb\Cache\FileCache(
                                           "testCache",
                                           0,
                                           null
                                       );

        $cacheInstance->cache = Mockery::mock('FilesystemAdapter');
        $cacheInstance->cache->shouldreceive('getItem')
                      ->andReturnUsing(
                          function($token) use(&$generated_token) {
                              $cacheItem = Mockery::mock('CacheItem');

                              $cacheItem->shouldreceive('isHit')
                                        ->andReturn(true);

                              $cacheItem->shouldreceive('get')
                                        ->andReturn($generated_token);

                              return $cacheItem;
                          }
                      );

        $cacheInstance->cache->shouldreceive('deleteItem')
                                ->with($generated_token);

        $result = $cacheInstance->verify_form_token($generated_token);
        $this->assertEquals("",
                            $result,
                            "Error: invalid result: '$result' sent by verify_form_token");

    }

    public function test_verify_form_token_ko(): void
    {

        $generated_token = "e712b08e55f8977e2b9ecad35d5180ed24345e76607413411e90df66b9538fa1";

        $cacheInstance = new \Ltb\Cache\FileCache(
                                           "testCache",
                                           0,
                                           null
                                       );

        $cacheInstance->cache = Mockery::mock('FilesystemAdapter');
        $cacheInstance->cache->shouldreceive('getItem')
                      ->andReturnUsing(
                          function($token) use(&$generated_token) {
                              $cacheItem = Mockery::mock('CacheItem');

                              $cacheItem->shouldreceive('isHit')
                                        ->andReturn(false);

                              $cacheItem->shouldreceive('get')
                                        ->andReturn(null);

                              return $cacheItem;
                          }
                      );

        $result = $cacheInstance->verify_form_token($generated_token);
        $this->assertEquals("invalidformtoken",
                            $result,
                            "Error: expected 'invalidformtoken', but received result: '$result' in verify_form_token");

    }

    public function test_get_token_ok(): void
    {

        $tokenid = "e712b08e55f8977e2b9ecad35d5180ed24345e76607413411e90df66b9538fa1";
        $token_content = "test";

        $cacheInstance = new \Ltb\Cache\FileCache(
                                           "testCache",
                                           0,
                                           null
                                       );

        $cacheInstance->cache = Mockery::mock('FilesystemAdapter');
        $cacheInstance->cache->shouldreceive('getItem')
                      ->andReturnUsing(
                          function($token) use(&$token_content) {
                              $cacheItem = Mockery::mock('CacheItem');

                              $cacheItem->shouldreceive('isHit')
                                        ->andReturn(true);

                              $cacheItem->shouldreceive('get')
                                        ->andReturn($token_content);

                              return $cacheItem;
                          }
                      );

        $result = $cacheInstance->get_token($tokenid);
        $this->assertEquals($token_content,
                            $result,
                            "Unexpected token content: '$result' sent by get_token");

    }

    public function test_get_token_ko(): void
    {

        $tokenid = "e712b08e55f8977e2b9ecad35d5180ed24345e76607413411e90df66b9538fa1";
        $token_content = "test";

        $cacheInstance = new \Ltb\Cache\FileCache(
                                           "testCache",
                                           0,
                                           null
                                       );

        $cacheInstance->cache = Mockery::mock('FilesystemAdapter');
        $cacheInstance->cache->shouldreceive('getItem')
                      ->andReturnUsing(
                          function($token) use(&$token_content) {
                              $cacheItem = Mockery::mock('CacheItem');

                              $cacheItem->shouldreceive('isHit')
                                        ->andReturn(false);

                              $cacheItem->shouldreceive('get')
                                        ->andReturn(null);

                              return $cacheItem;
                          }
                      );

        $result = $cacheInstance->get_token($tokenid);
        $this->assertEquals(null,
                            $result,
                            "Unexpected not null token content: '$result' sent by get_token");

    }

    public function test_save_token_new(): void
    {

        $tokenid = "";
        $token_content = [
                           'param1' => 'value1',
                           'param2' => 'value2'
                         ];
        $cache_token_expiration = 3600;

        $cacheInstance = new \Ltb\Cache\FileCache(
                                           "testCache",
                                           0,
                                           null
                                       );

        $cacheInstance->cache = Mockery::mock('FilesystemAdapter');
        $cacheInstance->cache->shouldreceive('getItem')
                      ->andReturnUsing(
                          function($token) use(&$tokenid, &$token_content, &$cache_token_expiration) {
                              $tokenid = $token;
                              $cacheItem = Mockery::mock('CacheItem');

                              $cacheItem->shouldreceive('set')
                                        ->with($token_content);

                              $cacheItem->shouldreceive('expiresAfter')
                                        ->with($cache_token_expiration);

                              return $cacheItem;
                          }
                      );

        $cacheInstance->cache->shouldreceive('save');

        $result = $cacheInstance->save_token($token_content, null, $cache_token_expiration);
        $this->assertEquals($tokenid,
                            $result,
                            "Bad token id sent by save_token function");

    }

    public function test_save_token_existing(): void
    {

        $tokenid = "e712b08e55f8977e2b9ecad35d5180ed24345e76607413411e90df66b9538fa1";
        $token_content = [
                           'par1' => 'val1',
                           'par2' => 'val2'
                         ];
        $cache_token_expiration = 3600;

        $cacheInstance = new \Ltb\Cache\FileCache(
                                           "testCache",
                                           0,
                                           null
                                       );

        $cacheInstance->cache = Mockery::mock('FilesystemAdapter');
        $cacheInstance->cache->shouldreceive('getItem')
                      ->with($tokenid)
                      ->andReturnUsing(
                          function($token) use(&$tokenid, &$token_content, &$cache_token_expiration) {
                              $cacheItem = Mockery::mock('CacheItem');

                              $cacheItem->shouldreceive('set')
                                        ->with($token_content);

                              $cacheItem->shouldreceive('expiresAfter')
                                        ->with($cache_token_expiration);

                              return $cacheItem;
                          }
                      );

        $cacheInstance->cache->shouldreceive('save');

        $result = $cacheInstance->save_token($token_content, $tokenid, $cache_token_expiration);
        $this->assertEquals($tokenid,
                            $result,
                            "Bad token id sent by save_token function");

    }

    public function test_save_token_existing_noexpiration(): void
    {

        $tokenid = "e712b08e55f8977e2b9ecad35d5180ed24345e76607413411e90df66b9538fa1";
        $token_content = [
                           'par1' => 'val1',
                           'par2' => 'val2'
                         ];

        $cacheInstance = new \Ltb\Cache\FileCache(
                                           "testCache",
                                           0,
                                           null
                                       );

        $cacheInstance->cache = Mockery::mock('FilesystemAdapter');
        $cacheInstance->cache->shouldreceive('getItem')
                      ->with($tokenid)
                      ->andReturnUsing(
                          function($token) use(&$tokenid, &$token_content) {
                              $cacheItem = Mockery::mock('CacheItem');

                              $cacheItem->shouldreceive('set')
                                        ->with($token_content);

                              return $cacheItem;
                          }
                      );

        $cacheInstance->cache->shouldreceive('save');

        $result = $cacheInstance->save_token($token_content, $tokenid);
        $this->assertEquals($tokenid,
                            $result,
                            "Bad token id sent by save_token function");

    }
}
