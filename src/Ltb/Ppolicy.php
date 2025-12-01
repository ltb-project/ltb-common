<?php namespace Ltb;

use ZxcvbnPhp\Zxcvbn;
use PwnedPasswords\PwnedPasswords;

/**
 * Password functions
 */
final class Ppolicy {

    # Check password strength
    # @param string password to check
    # @param string old password
    # @param array password policy configuration
    # @param string user identifier
    # @param array ldap entry
    # @param array of key/values : configuration of custom password fields to check
    # @return result code
    static function check_password_strength(   $password,
                                        $oldpassword,
                                        $pwd_policy_config,
                                        $login,
                                        $entry_array,
                                        $change_custompwdfield )
    {
        extract( $pwd_policy_config );

        $result = "";

        $length = mb_strlen($password, mb_detect_encoding($password));
        preg_match_all("/[a-z]/", $password, $lower_res);
        $lower = count( $lower_res[0] );
        preg_match_all("/[A-Z]/", $password, $upper_res);
        $upper = count( $upper_res[0] );
        preg_match_all("/[0-9]/", $password, $digit_res);
        $digit = count( $digit_res[0] );

        $special = 0;
        $special_at_ends = false;
        if ( isset($pwd_special_chars) && !empty($pwd_special_chars) ) {
            preg_match_all("/[$pwd_special_chars]/", $password, $special_res);
            $special = count( $special_res[0] );
            if ( $pwd_no_special_at_ends ) {
                $special_at_ends = preg_match(
                                       "/(^[$pwd_special_chars]|[$pwd_special_chars]$)/",
                                       $password,
                                       $special_res
                                   );
            }
        }

        $forbidden = 0;
        if ( isset($pwd_forbidden_chars) && !empty($pwd_forbidden_chars) ) {
            $escaped = preg_quote($pwd_forbidden_chars, '/');
            $pattern = '/[' . $escaped . ']/u';
            preg_match_all($pattern, $password, $forbidden_res);
            $forbidden = isset($forbidden_res[0]) ? count($forbidden_res[0]) : 0;
        }

        # Complexity: checks for lower, upper, special, digits
        if ( $pwd_complexity ) {
            $complex = 0;
            if ( $special > 0 ) { $complex++; }
            if ( $digit > 0 ) { $complex++; }
            if ( $lower > 0 ) { $complex++; }
            if ( $upper > 0 ) { $complex++; }
            if ( $complex < $pwd_complexity ) { $result="notcomplex"; }
        }

        # Minimal length
        if ( $pwd_min_length and $length < $pwd_min_length ) { $result="tooshort"; }

        # Maximal length
        if ( $pwd_max_length and $length > $pwd_max_length ) { $result="toobig"; }

        # Minimal lower chars
        if ( $pwd_min_lower and $lower < $pwd_min_lower ) { $result="minlower"; }

        # Minimal upper chars
        if ( $pwd_min_upper and $upper < $pwd_min_upper ) { $result="minupper"; }

        # Minimal digit chars
        if ( $pwd_min_digit and $digit < $pwd_min_digit ) { $result="mindigit"; }

        # Minimal special chars
        if ( $pwd_min_special and $special < $pwd_min_special ) { $result="minspecial"; }

        # Forbidden chars
        if ( $forbidden > 0 ) { $result="forbiddenchars"; }

        # Special chars at beginning or end
        if ( $special_at_ends > 0 && $special == 1 ) { $result="specialatends"; }

        # Same as old password?
        if ( $pwd_no_reuse and $password === $oldpassword ) { $result="sameasold"; }

        # Same as login?
        if ( $pwd_diff_login and $password === $login ) { $result="sameaslogin"; }

        if ( $pwd_diff_last_min_chars > 0 and strlen($oldpassword) > 0 ) {
            $similarities = similar_text($oldpassword, $password);
            $check_len    = strlen($oldpassword) < strlen($password) ?
                                strlen($oldpassword) :
                                strlen($password);
            $new_chars    = $check_len - $similarities;
            if ($new_chars <= $pwd_diff_last_min_chars) { $result = "diffminchars"; }
        }

        # Contains forbidden words?
        if ( !empty($pwd_forbidden_words) ) {
            foreach( $pwd_forbidden_words as $disallowed ) {
                if( stripos($password, $disallowed) !== false ) {
                    $result="forbiddenwords";
                    break;
                }
            }
        }

        # Contains values from forbidden ldap fields?
        if ( !empty($pwd_forbidden_ldap_fields) ) {
            foreach ( $pwd_forbidden_ldap_fields as $field ) {
                # if entry does not hold requested attribute, continue
                if ( array_key_exists($field,$entry_array) )
                {
                    $values = $entry_array[$field];
                    if (!is_array($values)) {
                        $values = array($values);
                    }
                    foreach ($values as $key => $value) {
                        if ($key === 'count') {
                            continue;
                        }
                        if (stripos($password, $value) !== false) {
                            $result = "forbiddenldapfields";
                            break 2;
                        }
                    }
                }
            }
        }

        # ensure that the new password is different from any other custom password field marked as unique
        foreach ( $change_custompwdfield as $custompwdfield) {
            if (isset($custompwdfield['pwd_policy_config']['pwd_unique_across_custom_password_fields']) &&
                $custompwdfield['pwd_policy_config']['pwd_unique_across_custom_password_fields']) {
                if (array_key_exists($custompwdfield['attribute'], $entry_array)) {
                    if ($custompwdfield['hash'] == 'auto') {
                        $matches = [];
                        if ( preg_match( '/^\{(\w+)\}/',
                                         $entry_array[$custompwdfield['attribute']][0],
                                         $matches ) )
                        {
                            $hash_for_custom_pwd = strtoupper($matches[1]);
                        }
                    } else {
                        $hash_for_custom_pwd = $custompwdfield['hash'];
                    }
                    if ( \Ltb\Password::check_password($password,
                                                       $entry_array[$custompwdfield['attribute']][0],
                                                       $hash_for_custom_pwd) )
                    {
                        $result = "sameascustompwd";
                    }
                }
            }
        }

        # pwned?
        if ($use_pwnedpasswords and version_compare(PHP_VERSION, '7.2.5') >= 0) {
            $pwned_passwords = new PwnedPasswords;
            $insecure = $pwned_passwords->isPwned($password);
            if ($insecure) { $result="pwned"; }
        }


        # check entropy
        $zxcvbn = new Zxcvbn();
        if( isset($pwd_check_entropy) && $pwd_check_entropy == true )
        {
            if( isset($pwd_min_entropy) && is_int($pwd_min_entropy) )
            {
                // force encoding to utf8, as iso-8859-1 is not supported by zxcvbn
                //$password = mb_convert_encoding($p, 'UTF-8', 'ISO-8859-1');
                error_log("checkEntropy: password taken directly");
                $entropy = $zxcvbn->passwordStrength("$password");
                $entropy_level = intval($entropy["score"]);
                $entropy_message = $entropy['feedback']['warning'] ? strval($entropy['feedback']['warning']) : "";
                error_log( "checkEntropy: level $entropy_level msg: $entropy_message" );
                if( is_int($entropy_level) && $entropy_level >= $pwd_min_entropy )
                {
                    ; // password entropy check ok
                }
                else
                {
                    error_log("checkEntropy: insufficient entropy: level = $entropy_level but minimal required = $pwd_min_entropy");
                    $result="insufficiententropy";
                }
            }
            else
            {
                error_log("checkEntropy: missing required parameter pwd_min_entropy");
                $result="insufficiententropy";
            }

        }

        return $result;
    }

    /* Check user password against zxcvbn library
       Input : new user base64-encoded password
       Output: JSON response: { "level" => int, "message" => "msg" } */

    static function checkEntropyJSON($password_base64)
    {
        $response_params = array();
        $zxcvbn = new Zxcvbn();

        if( ! isset($password_base64) || empty($password_base64))
        {
            error_log("checkEntropy: missing parameter password");
            $response_params["level"]   = "-1";
            $response_params["message"] = "missing parameter password";
            return json_encode($response_params);
        }

        $p = base64_decode($password_base64);
        // force encoding to utf8, as iso-8859-1 is not supported by zxcvbn
        $password = mb_convert_encoding($p, 'UTF-8', 'ISO-8859-1');

        $entropy = $zxcvbn->passwordStrength("$password");

        $response_params["level"] = strval($entropy["score"]);
        $response_params["message"] = $entropy['feedback']['warning'] ? strval($entropy['feedback']['warning']) : "";

        return json_encode($response_params);
    }

    static function smarty_assign_variable($smarty, $pwd_policy_config)
    {
        foreach ($pwd_policy_config as $param => $value) {
            if( isset($value) )
            {
                // only send password policy parameters
                // of type string to smarty template
                if( !is_array($value) )
                {
                    $smarty->assign($param, $value);
                }
            }
        }
    }

    static function smarty_assign_ppolicy($smarty, $pwd_show_policy_pos, $pwd_show_policy, $result, $pwd_policy_config )
    {
        if (isset($pwd_show_policy_pos)) {
            $smarty->assign('pwd_show_policy_pos', $pwd_show_policy_pos);
            $smarty->assign('pwd_show_policy', $pwd_show_policy);
            self::smarty_assign_variable($smarty, $pwd_policy_config);

            // send policy to a JSON object usable in javascript
            $smarty->assign('json_policy', base64_encode(json_encode( $pwd_policy_config )));
        }
    }
}
