<?php namespace Ltb;

/**             
 * Config helper functions
 */         
final class Config {

    static function getValueFromHeader(string $headerName) {

        $headerValue = "";

        if (isset($headerName)) {
            $headerKey = "HTTP_".strtoupper(str_replace('-','_',$headerName));
            if (array_key_exists($headerKey, $_SERVER)) {
                $headerValue = preg_replace("/[^a-zA-Z0-9-_]+/", "", filter_var($_SERVER[$headerKey], FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_HIGH));
            }
        }

        return $headerValue;
    }
}
