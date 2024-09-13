<?php namespace Ltb;

use Symfony\Component\Cache\Adapter\FilesystemAdapter;

class Cache {

    // symfony cache instance
    public $cache = null;

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

    # Generate a cache entry containing a token,
    # expiring after $cache_form_expiration seconds
    function generate_form_token($cache_form_expiration)
    {
        $formtoken = hash('sha256', bin2hex(random_bytes(16)));
        $cachedToken = $this->cache->getItem($formtoken);
        $cachedToken->set($formtoken);
        $cachedToken->expiresAfter($cache_form_expiration);
        $this->cache->save($cachedToken);
        error_log("generated form token: " .
                  $formtoken .
                  " valid for $cache_form_expiration s");
        return $formtoken;
    }

    # Verify that give token exist in cache
    # and if it exists, remove it from cache
    function verify_form_token($formtoken)
    {
        $result = "";
        $cachedToken = $this->cache->getItem($formtoken);
        if( $cachedToken->isHit() && $cachedToken->get() == $formtoken )
        {
            # Remove token from cache entry
            $this->cache->deleteItem($formtoken);
        }
        else
        {
            error_log("Invalid form token: sent: $formtoken, stored: " .
                      $cachedToken->get());
            $result = "invalidformtoken";
        }
        return $result;
    }


    # Get a token from the cache
    # return the content of the content (can be an array, a string)
    function get_token($tokenid)
    {
        $cached_token = $this->cache->getItem($tokenid);
        $cached_token_content = $cached_token->get();

        if($cached_token->isHit())
        {
            return $cached_token_content;
        }
        else
        {
            return null;
        }
    }

    # Save a token to the cache
    function save_token($content, $tokenid = null, $cache_token_expiration = null)
    {
        $msg = "";
        if(is_null($tokenid))
        {
            $tokenid = hash('sha256', bin2hex(random_bytes(16)));
            $msg .= "Generated cache entry with id: $tokenid";
        }
        else
        {
            $msg .= "Saving existing cache entry with id: $tokenid";
        }

        $cached_token = $this->cache->getItem($tokenid);
        $cached_token->set( $content );

        if(!is_null($cache_token_expiration))
        {
            $cached_token->expiresAfter($cache_token_expiration);
            $msg .= ", valid for $cache_token_expiration s";
        }

        $this->cache->save($cached_token);
        error_log($msg);

        return $tokenid;
    }

}

?>
