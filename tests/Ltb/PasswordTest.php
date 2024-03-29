<?php

require __DIR__ . '/../../vendor/autoload.php';

use PHPUnit\Framework\TestCase;

final class PasswordTest extends \Mockery\Adapter\Phpunit\MockeryTestCase
{

    function test_check_hash_algorithms() {
        $originalPassword = 'TestMe123!+*';

        $hash_algos = array("SSHA", "SSHA256", "SSHA384", "SSHA512", "SHA", "SHA256", "SHA384", "SHA512", "SMD5", "MD5", "CRYPT", "ARGON2", "clear");

        $hash_options=array('crypt_salt_length' => 10, 'crypt_salt_prefix' => "test");

        foreach ($hash_algos as $algo) {
            $hash = \Ltb\Password::make_password($originalPassword, $algo, $hash_options);

            $this->assertEquals(true, \Ltb\Password::check_password($originalPassword, $hash, $algo));
            $this->assertEquals(false, \Ltb\Password::check_password("notSamePassword", $hash, $algo));
            
            $this->assertEquals(true, \Ltb\Password::check_password($originalPassword, $hash, "auto"));
            $this->assertEquals(false, \Ltb\Password::check_password("notSamePassword", $hash, "auto"));
        }
        
        //and NTLM, where "auto" does not work:
        $hash = \Ltb\Password::make_md4_password($originalPassword);
        $this->assertEquals(true, \Ltb\Password::check_password($originalPassword, $hash, "NTLM"));
        $this->assertEquals(false, \Ltb\Password::check_password("notSamePassword", $hash, "NTLM"));
    }
    
    function test_make_ad_password() {
        $originalPassword = 'TestMe123!+*ä';
        $adpassword = \Ltb\Password::make_ad_password($originalPassword);
        $this->assertEquals(true, mb_check_encoding($adpassword, "UTF-16LE"));
        $this->assertEquals(pack("H*", '220054006500730074004d00650031003200330021002b002a00e4002200'), $adpassword);
    }
    
    function test_set_samba_data() {
        $password = 'TestMe123!+*ä';
        $time = 1711717971;
        $userdata = ["userPassword" => 'TestMe123!+*ä'];
        
        $samba_options_min_age = ['min_age' => 10];
        $expected_userdata_samba_min_age = [
            "userPassword" => 'TestMe123!+*ä',
            "sambaNTPassword" => \Ltb\Password::make_md4_password($password),
            "sambaPwdLastSet" => $time,
            "sambaPwdCanChange" => 1712581971
        ];
        $actual_userdata_samba_min_age = \Ltb\Password::set_samba_data($userdata, $samba_options_min_age, $password, $time);
        $this->assertEquals($expected_userdata_samba_min_age, $actual_userdata_samba_min_age);
        
        $samba_options_max_age = ['max_age' => 10];
        $expected_userdata_samba_max_age = [
            "userPassword" => 'TestMe123!+*ä',
            "sambaNTPassword" => \Ltb\Password::make_md4_password($password),
            "sambaPwdLastSet" => $time,
            "sambaPwdMustChange" => 1712581971
        ];
        $actual_userdata_samba_max_age = \Ltb\Password::set_samba_data($userdata, $samba_options_max_age, $password, $time);
        $this->assertEquals($expected_userdata_samba_max_age, $actual_userdata_samba_max_age);
        
        $samba_options_expire_days = ['expire_days' => 10];
        $expected_userdata_samba_expire_days = [
            "userPassword" => 'TestMe123!+*ä',
            "sambaNTPassword" => \Ltb\Password::make_md4_password($password),
            "sambaPwdLastSet" => $time,
            "sambaKickoffTime" => 1712581971
        ];
        $actual_userdata_samba_expire_days = \Ltb\Password::set_samba_data($userdata, $samba_options_expire_days, $password, $time);
        $this->assertEquals($expected_userdata_samba_expire_days, $actual_userdata_samba_expire_days);
    }
    
    function test_set_ad_data() {
        $password = \Ltb\Password::make_ad_password('TestMe123!+*ä');
        $userdata = [
            "userPassword" => 'TestMe123!+*ä',
            "sambaPwdCanChange" => 1712581971
        ];
        
        $ad_options_force_unlock = [
            "force_unlock" => true, 
            "force_pwd_change" => false
        ];
        $expected_userdata_force_unlock = [
            "userPassword" => 'TestMe123!+*ä',
            "sambaPwdCanChange" => 1712581971,
            "unicodePwd" => \Ltb\Password::make_ad_password('TestMe123!+*ä'),
            "lockoutTime" => 0
        ];
        $actual_userdata_force_unlock = \Ltb\Password::set_ad_data($userdata, $ad_options_force_unlock, $password);
        $this->assertEquals($expected_userdata_force_unlock, $actual_userdata_force_unlock);
        
        $ad_options_force_pwd_change = [
            "force_unlock" => false, 
            "force_pwd_change" => true
        ];
        $expected_userdata_force_pwd_change = [
            "userPassword" => 'TestMe123!+*ä',
            "sambaPwdCanChange" => 1712581971,
            "unicodePwd" => \Ltb\Password::make_ad_password('TestMe123!+*ä'),
            "pwdLastSet" => 0
        ];
        $actual_userdata_force_pwd_change = \Ltb\Password::set_ad_data($userdata, $ad_options_force_pwd_change, $password);
        $this->assertEquals($expected_userdata_force_pwd_change, $actual_userdata_force_pwd_change);
    }
    
    function test_set_shadow_data() {
        $time = 1711717971;
        $userdata = [
            "userPassword" => 'TestMe123!+*ä',
            "sambaNTPassword" => \Ltb\Password::make_md4_password('TestMe123!+*ä'),
            "sambaPwdLastSet" => $time,
            "sambaPwdCanChange" => 1712581971
        ];
        
        $shadow_options_update_shadowLastChange = [
            "update_shadowLastChange" => true,
            "update_shadowExpire" => false
        ];
        $expected_userdata_update_shadowLastChange = [
            "userPassword" => 'TestMe123!+*ä',
            "sambaNTPassword" => \Ltb\Password::make_md4_password('TestMe123!+*ä'),
            "sambaPwdLastSet" => $time,
            "sambaPwdCanChange" => 1712581971,
            "shadowLastChange" => 19811
        ];
        $actual_userdata_update_shadowLastChange = \Ltb\Password::set_shadow_data($userdata, $shadow_options_update_shadowLastChange, $time);
        $this->assertEquals($expected_userdata_update_shadowLastChange, $actual_userdata_update_shadowLastChange);
        
        $shadow_options_update_shadowExpire = [
            "update_shadowLastChange" => false,
            "update_shadowExpire" => true,
            "shadow_expire_days" => 10
        ];
        $expected_userdata_update_shadowExpire = [
            "userPassword" => 'TestMe123!+*ä',
            "sambaNTPassword" => \Ltb\Password::make_md4_password('TestMe123!+*ä'),
            "sambaPwdLastSet" => $time,
            "sambaPwdCanChange" => 1712581971,
            "shadowExpire" => 19821
        ];
        $actual_userdata_update_shadowExpire = \Ltb\Password::set_shadow_data($userdata, $shadow_options_update_shadowExpire, $time);
        $this->assertEquals($expected_userdata_update_shadowExpire, $actual_userdata_update_shadowExpire);
        
        $shadow_options_update_shadowExpire_negative = [
            "update_shadowLastChange" => false,
            "update_shadowExpire" => true,
            "shadow_expire_days" => -1
        ];
        $expected_userdata_update_shadowExpire_negative = [
            "userPassword" => 'TestMe123!+*ä',
            "sambaNTPassword" => \Ltb\Password::make_md4_password('TestMe123!+*ä'),
            "sambaPwdLastSet" => $time,
            "sambaPwdCanChange" => 1712581971,
            "shadowExpire" => -1
        ];
        $actual_userdata_update_shadowExpire_negative = \Ltb\Password::set_shadow_data($userdata, $shadow_options_update_shadowExpire_negative, $time);
        $this->assertEquals($expected_userdata_update_shadowExpire_negative, $actual_userdata_update_shadowExpire_negative);
        
        
    }
}
