<?php

require __DIR__ . '/../../vendor/autoload.php';

use PHPUnit\Framework\TestCase;

final class PpolicyTest extends \Mockery\Adapter\Phpunit\MockeryTestCase
{

    public function testCheckPasswordStrength()
    {

        # Password policy
        $pwd_policy_config = array(
            "pwd_show_policy"         => true,
            "pwd_min_length"          => 6,
            "pwd_max_length"          => 12,
            "pwd_min_lower"           => 1,
            "pwd_min_upper"           => 1,
            "pwd_min_digit"           => 1,
            "pwd_min_special"         => 1,
            "pwd_special_chars"       => "^a-zA-Z0-9",
            "pwd_forbidden_chars"     => "@",
            "pwd_no_reuse"            => true,
            "pwd_diff_last_min_chars" => 0,
            "pwd_diff_login"          => true,
            "pwd_complexity"          => 0,
            "use_pwnedpasswords"      => false,
            "pwd_no_special_at_ends"  => false,
            "pwd_forbidden_words"     => array(),
            "pwd_forbidden_ldap_fields"=> array(),
        );

        $login = "coudot";
        $oldpassword = "secret";
        $entry_array = array('cn' => array('common name'), 'sn' => array('surname'), 'customPasswordField' => array("{SSHA}7JWaNGUygodHyWt+DwPpOuYMDdKYJQQX"));
        $change_custompwdfield = array(
                                     array(
                                         'pwd_policy_config' => array(
                                             'pwd_no_reuse' => true,
                                             'pwd_unique_across_custom_password_fields' => true
                                         ),
                                         'attribute' => 'customPasswordField',
                                         'hash' => "auto"
                                     )
                                 );
        $change_custompwdfield2 = array(
                                      array(
                                          'pwd_policy_config' => array(
                                              'pwd_no_reuse' => true,
                                              'pwd_unique_across_custom_password_fields' => true
                                          ),
                                          'attribute' => 'customPasswordField',
                                          'hash' => "SSHA"
                                      )
                                  );

        $this->assertEquals("sameaslogin", \Ltb\Ppolicy::check_password_strength( "coudot", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("sameasold", \Ltb\Ppolicy::check_password_strength( "secret", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("forbiddenchars", \Ltb\Ppolicy::check_password_strength( "p@ssword", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("minspecial", \Ltb\Ppolicy::check_password_strength( "password", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("mindigit", \Ltb\Ppolicy::check_password_strength( "!password", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("minupper", \Ltb\Ppolicy::check_password_strength( "!1password", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("minlower", \Ltb\Ppolicy::check_password_strength( "!1PASSWORD", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("toobig", \Ltb\Ppolicy::check_password_strength( "!1verylongPassword", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("tooshort", \Ltb\Ppolicy::check_password_strength( "!1Pa", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("sameascustompwd", \Ltb\Ppolicy::check_password_strength( "!TestMe123!", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("sameascustompwd", \Ltb\Ppolicy::check_password_strength( "!TestMe123!", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield2 ) );


        $pwd_policy_config = array(
            "pwd_show_policy"         => true,
            "pwd_min_length"          => 6,
            "pwd_max_length"          => 12,
            "pwd_min_lower"           => 0,
            "pwd_min_upper"           => 0,
            "pwd_min_digit"           => 0,
            "pwd_min_special"         => 0,
            "pwd_special_chars"       => "^a-zA-Z0-9",
            "pwd_forbidden_chars"     => "@",
            "pwd_no_reuse"            => true,
            "pwd_diff_last_min_chars" => 3,
            "pwd_diff_login"          => true,
            "pwd_complexity"          => 3,
            "use_pwnedpasswords"      => false,
            "pwd_no_special_at_ends"  => true,
            "pwd_forbidden_words"     => array('companyname', 'trademark'),
            "pwd_forbidden_ldap_fields"=> array('cn', 'sn'),
        );

        $this->assertEquals("notcomplex", \Ltb\Ppolicy::check_password_strength( "simple", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("specialatends", \Ltb\Ppolicy::check_password_strength( "!simple", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("specialatends", \Ltb\Ppolicy::check_password_strength( "simple?", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("forbiddenwords", \Ltb\Ppolicy::check_password_strength( "companyname", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("forbiddenwords", \Ltb\Ppolicy::check_password_strength( "trademark", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("forbiddenwords", \Ltb\Ppolicy::check_password_strength( "working at companyname is fun", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("forbiddenldapfields", \Ltb\Ppolicy::check_password_strength( "common name", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("forbiddenldapfields", \Ltb\Ppolicy::check_password_strength( "my surname", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("diffminchars", \Ltb\Ppolicy::check_password_strength( "C0mplex", "C0mplexC0mplex", $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("", \Ltb\Ppolicy::check_password_strength( "C0mplex", "", $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("", \Ltb\Ppolicy::check_password_strength( "C0mplex", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("", \Ltb\Ppolicy::check_password_strength( "C0!mplex", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
        $this->assertEquals("", \Ltb\Ppolicy::check_password_strength( "%C0!mplex", $oldpassword, $pwd_policy_config, $login, $entry_array, $change_custompwdfield ) );
    }

    /**
     * Test check_password_strength function with pwned passwords
     */
    public function testCheckPasswordStrengthPwnedPasswords()
    {

        $login = "coudot";
        $oldpassword = "secret";

        if ( version_compare(PHP_VERSION, '7.2.5') >= 0 ) {
            $pwd_policy_config = array(
                "pwd_show_policy"         => true,
                "pwd_min_length"          => 6,
                "pwd_max_length"          => 12,
                "pwd_min_lower"           => 1,
                "pwd_min_upper"           => 1,
                "pwd_min_digit"           => 1,
                "pwd_min_special"         => 1,
                "pwd_special_chars"       => "^a-zA-Z0-9",
                "pwd_forbidden_chars"     => "@",
                "pwd_no_reuse"            => true,
                "pwd_diff_last_min_chars" => 0,
                "pwd_diff_login"          => true,
                "pwd_complexity"          => 0,
                "use_pwnedpasswords"      => true,
                "pwd_no_special_at_ends"  => false,
                "pwd_forbidden_words"     => array(),
                "pwd_forbidden_ldap_fields"=> array(),
            );

            $this->assertEquals("pwned", \Ltb\Ppolicy::check_password_strength( "!1Password", $oldpassword, $pwd_policy_config, $login, array(), array() ) );
        }

    }

    /**
     * Test check_password_strength function with weak entropy password
     */
    public function testCheckPasswordStrengthWeakEntropy()
    {

        $login = "johnsmith";
        $oldpassword = "secret";

        if ( version_compare(PHP_VERSION, '7.2.5') >= 0 ) {
            $pwd_policy_config = array(
                "pwd_show_policy"          => true,
                "pwd_min_length"           => 6,
                "pwd_max_length"           => 0,
                "pwd_min_lower"            => 0,
                "pwd_min_upper"            => 0,
                "pwd_min_digit"            => 0,
                "pwd_min_special"          => 0,
                "pwd_special_chars"        => "^a-zA-Z0-9",
                "pwd_forbidden_chars"      => "",
                "pwd_no_reuse"             => false,
                "pwd_diff_last_min_chars"  => 0,
                "pwd_diff_login"           => false,
                "pwd_complexity"           => 0,
                "use_pwnedpasswords"       => false,
                "pwd_no_special_at_ends"   => false,
                "pwd_forbidden_words"      => array(),
                "pwd_forbidden_ldap_fields"=> array(),
                "pwd_display_entropy"      => true,
                "pwd_check_entropy"        => true,
                "pwd_min_entropy"          => 3
            );

            $this->assertEquals("insufficiententropy", \Ltb\Ppolicy::check_password_strength( "secret", $oldpassword, $pwd_policy_config, $login, array(), array() ) );
        }

    }

    /**
     * Test check_password_strength function with strong entropy password
     */
    public function testCheckPasswordStrengthStrongEntropy()
    {

        $login = "johnsmith";
        $oldpassword = "secret";

        if ( version_compare(PHP_VERSION, '7.2.5') >= 0 ) {
            $pwd_policy_config = array(
                "pwd_show_policy"          => true,
                "pwd_min_length"           => 6,
                "pwd_max_length"           => 0,
                "pwd_min_lower"            => 0,
                "pwd_min_upper"            => 0,
                "pwd_min_digit"            => 0,
                "pwd_min_special"          => 0,
                "pwd_special_chars"        => "^a-zA-Z0-9",
                "pwd_forbidden_chars"      => "",
                "pwd_no_reuse"             => false,
                "pwd_diff_last_min_chars"  => 0,
                "pwd_diff_login"           => false,
                "pwd_complexity"           => 0,
                "use_pwnedpasswords"       => false,
                "pwd_no_special_at_ends"   => false,
                "pwd_forbidden_words"      => array(),
                "pwd_forbidden_ldap_fields"=> array(),
                "pwd_display_entropy"      => true,
                "pwd_check_entropy"        => true,
                "pwd_min_entropy"          => 3
            );

            $this->assertEquals("", \Ltb\Ppolicy::check_password_strength( "Th!Sis@Str0ngP@ss0rd", $oldpassword, $pwd_policy_config, $login, array(), array() ) );
        }

    }

    /**
     * Test checkEntropyJSON function
     */
    public function testCheckEntropyJSON()
    {

        $password_weak = "secret";
        $password_weak_base64 = base64_encode($password_weak);

        $password_strong = "jtK8hEhNgT3wwGiDY_z7XmI92fUbnemQ";
        $password_strong_base64 = base64_encode($password_strong);

        $result_error =  json_encode(
                             array(
                                 "level" => "-1",
                                 "message" => "missing parameter password"
                             )
                        );

        $result_weak =   json_encode(
                             array(
                                 "level" => "0",
                                 "message" => "This is a top-100 common password"
                             )
                        );

        $result_strong = json_encode(
                            array(
                                "level" => "4",
                                "message" => ""
                            )
                        );

        $this->assertEquals($result_error,  \Ltb\Ppolicy::checkEntropyJSON( "" ) );
        $this->assertEquals($result_weak,   \Ltb\Ppolicy::checkEntropyJSON( $password_weak_base64 ) );
        $this->assertEquals($result_strong, \Ltb\Ppolicy::checkEntropyJSON( $password_strong_base64 ) );

    }

    public function test_smarty_assign_variable()
    {

        # Password policy array
        $pwd_policy_config = array(
            "pwd_show_policy"           => "always",
            "pwd_min_length"            => 12,
            "pwd_max_length"            => 32,
            "pwd_min_lower"             => 1,
            "pwd_min_upper"             => 1,
            "pwd_min_digit"             => 0,
            "pwd_min_special"           => 0,
            "pwd_special_chars"         => "^a-zA-Z0-9",
            "pwd_forbidden_chars"       => null,
            "pwd_no_reuse"              => true,
            "pwd_diff_last_min_chars"   => 0,
            "pwd_diff_login"            => true,
            "pwd_complexity"            => 3,
            "use_pwnedpasswords"        => true,
            "pwd_no_special_at_ends"    => false,
            "pwd_forbidden_words"       => array("secret","password"),
            "pwd_forbidden_ldap_fields" => array(),
            "pwd_display_entropy"       => true,
            "pwd_check_entropy"         => true,
            "pwd_min_entropy"           => 3
        );

        $smarty = Mockery::mock('Smarty');

        foreach ($pwd_policy_config as $param => $value) {
            if( isset($value) )
            {
                // only send password policy parameters
                // of type string to smarty template
                if( !is_array($value) )
                {
                    $smarty->shouldreceive('assign')
                           ->once()
                           ->with($param, $value);
                }
            }
        }

        \Ltb\Ppolicy::smarty_assign_variable($smarty, $pwd_policy_config);

        $this->assertNotNull($smarty, "smarty variable is null while testing smarty_assign_variable" );

    }

    public function test_smarty_assign_ppolicy()
    {

        # Password policy array
        $pwd_policy_config = array(
            "pwd_show_policy"           => "always",
            "pwd_min_length"            => 12,
            "pwd_max_length"            => 32,
            "pwd_min_lower"             => 1,
            "pwd_min_upper"             => 1,
            "pwd_min_digit"             => 0,
            "pwd_min_special"           => 0,
            "pwd_special_chars"         => "^a-zA-Z0-9",
            "pwd_forbidden_chars"       => null,
            "pwd_no_reuse"              => true,
            "pwd_diff_last_min_chars"   => 0,
            "pwd_diff_login"            => true,
            "pwd_complexity"            => 3,
            "use_pwnedpasswords"        => true,
            "pwd_no_special_at_ends"    => false,
            "pwd_forbidden_words"       => array("secret","password"),
            "pwd_forbidden_ldap_fields" => array(),
            "pwd_display_entropy"       => true,
            "pwd_check_entropy"         => true,
            "pwd_min_entropy"           => 3
        );

        $smarty = Mockery::mock('Smarty');
        $pwd_show_policy_pos = "above";
        $pwd_show_policy = "always";
        $result = "";

        $smarty->shouldreceive('assign')
               ->once()
               ->with("pwd_show_policy_pos", $pwd_show_policy_pos );
        $smarty->shouldreceive('assign')
               ->once()
               ->with("pwd_show_policy", $pwd_show_policy );

        foreach ($pwd_policy_config as $param => $value) {
            if( isset($value) )
            {
                // only send password policy parameters
                // of type string to smarty template
                if( !is_array($value) )
                {
                    $smarty->shouldreceive('assign')
                           ->once()
                           ->with($param, $value);
                }
            }
        }

        $smarty->shouldreceive('assign')
               ->once()
               ->with("json_policy", base64_encode(json_encode( $pwd_policy_config )) );

        \Ltb\Ppolicy::smarty_assign_ppolicy($smarty, $pwd_show_policy_pos, $pwd_show_policy, $result, $pwd_policy_config);

        $this->assertNotNull($smarty, "smarty variable is null while testing smarty_assign_ppolicy" );

    }

}
