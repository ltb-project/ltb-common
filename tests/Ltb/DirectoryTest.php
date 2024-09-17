<?php                                                        
                                                             
require __DIR__ . '/../../vendor/autoload.php';              
use PHPUnit\Framework\TestCase;

final class DirectoryTest extends \Mockery\Adapter\Phpunit\MockeryTestCase
{

    public function test_openldap_islocked_locked_forever(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => "000001010000Z",
                    ]
                ]
            ]
        ]);

        $isLocked = (new Ltb\Directory\OpenLDAP)->isLocked(null, null, null);
        $this->assertTrue($isLocked, "Account should be locked forever");
    }

    public function test_openldap_islocked_not_locked(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => null,
                    ]
                ]
            ]
        ]);

        $isLocked = (new Ltb\Directory\OpenLDAP)->isLocked(null, null, null);
        $this->assertFalse($isLocked, "Account should not be locked");
    }

    public function test_openldap_islocked_still_locked(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => (new DateTime)->format("Ymdhis\Z"),
                    ]
                ]
            ]
        ]);

        $isLocked = (new Ltb\Directory\OpenLDAP)->isLocked(null, null, array('lockout_duration' => 86400));
        $this->assertTrue($isLocked, "Account should still be locked");
    }

    public function test_openldap_islocked_no_more_locked(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => (new DateTime)->modify("-10 days")->format("Ymdhis\Z"),
                    ]
                ]
            ]
        ]);

        $isLocked = (new Ltb\Directory\OpenLDAP)->isLocked(null, null, array('lockout_duration' => 86400));
        $this->assertFalse($isLocked, "Account should no more be locked");
    }

    public function test_openldap_getlockdate_empty(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => null,
                    ]
                ]
            ]
        ]);

        $getLockDate = (new Ltb\Directory\OpenLDAP)->getLockDate(null, null);
        $this->assertNull($getLockDate, "Lock date should be null");
    }

    public function test_openldap_getlockdate_lock_forever(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => "000001010000Z",
                    ]
                ]
            ]
        ]);

        $getLockDate = (new Ltb\Directory\OpenLDAP)->getLockDate(null, null);
        $this->assertNull($getLockDate, "Lock date should be null if user is locked forever");
    }

    public function test_openldap_getlockdate_notempty(): void
    {
        $dt = new DateTime;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => $dt->format("Ymdhis\Z"),
                    ]
                ]
            ]
        ]);

        $getLockDate = (new Ltb\Directory\OpenLDAP)->getLockDate(null, null);
        $this->assertInstanceOf("DateTime", $getLockDate, "Lock date should be a PHP DateTime object");
        $this->assertEquals($dt->format("Y/m/d - h:i:s"), $getLockDate->format("Y/m/d - h:i:s"), "Lock date is correct");
    }

    public function test_openldap_getunlockdate_noduration(): void
    {
        $dt = new DateTime;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => $dt->format("Ymdhis\Z"),
                    ]
                ]
            ]
        ]);

        $unlockDate = (new Ltb\Directory\OpenLDAP)->getUnlockDate(null, null, array('lockout_duration' => 0));
        $this->assertNull($unlockDate, "Unkock date should be null");
    }

    public function test_openldap_getunlockdate_duration(): void
    {
        $dt = new DateTime;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => $dt->format("Ymdhis\Z"),
                    ]
                ]
            ]
        ]);

        $unlockDate = (new Ltb\Directory\OpenLDAP)->getUnlockDate(null, null, array('lockout_duration' => 86400));
        $this->assertInstanceOf("DateTime", $unlockDate, "Unlock date should be a PHP DateTime object");
        $this->assertEquals($dt->modify("+1 day")->format("Y/m/d - h:i:s"), $unlockDate->format("Y/m/d - h:i:s"), "Unlock date is correct");
    }

    public function test_openldap_isexpired_expired(): void
    {
        $dt = new DateTime;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdchangedtime' => [
                        'count' => 1,
                        0 => $dt->modify("-1 month")->format("Ymdhis\Z"),
                    ]
                ]
            ]
        ]);

        $isPasswordExpired = (new Ltb\Directory\OpenLDAP)->isPasswordExpired(null, null, array('password_max_age' => 86400));
        $this->assertTrue($isPasswordExpired, "Password should be expired");
    }

    public function test_openldap_isexpired_not_expired(): void
    {
        $dt = new DateTime;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdchangedtime' => [
                        'count' => 1,
                        0 => $dt->modify("-1 hour")->format("Ymdhis\Z"),
                    ]
                ]
            ]
        ]);

        $isPasswordExpired = (new Ltb\Directory\OpenLDAP)->isPasswordExpired(null, null, array('password_max_age' => 86400));
        $this->assertFalse($isPasswordExpired, "Password should not be expired");
    }

    public function test_openldap_getpasswordexpirationdate_empty(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdchangedtime' => [
                        'count' => 1,
                        0 => null,
                    ]
                ]
            ]
        ]);

        $passwordExpirationDate = (new Ltb\Directory\OpenLDAP)->getPasswordExpirationDate(null, null, null);
        $this->assertNull($passwordExpirationDate, "Password expiration date should be null");
    }

    public function test_openldap_getpasswordexpirationdate_notempty(): void
    {
        $dt = new DateTime;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdchangedtime' => [
                        'count' => 1,
                        0 => $dt->format("Ymdhis\Z"),
                    ]
                ]
            ]
        ]);

        $passwordExpirationDate = (new Ltb\Directory\OpenLDAP)->getPasswordExpirationDate(null, null, array('password_max_age' => 86400));
        $this->assertInstanceOf("DateTime", $passwordExpirationDate, "Password expiration date should be a PHP DateTime object");
        $this->assertEquals($dt->modify("+1 day")->format("Y/m/d - h:i:s"), $passwordExpirationDate->format("Y/m/d - h:i:s"), "Password expiration date is correct");
    }

    public function test_openldap_reset_true(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdreset' => [
                        'count' => 1,
                        0 => "TRUE",
                    ]
                ]
            ]
        ]);

        $reset = (new Ltb\Directory\OpenLDAP)->resetAtNextConnection(null, null);
        $this->assertTrue($reset, "Reset should be true");
    }

    public function test_openldap_reset_false(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdreset' => [
                        'count' => 1,
                        0 => "FALSE",
                    ]
                ]
            ]
        ]);

        $reset = (new Ltb\Directory\OpenLDAP)->resetAtNextConnection(null, null);
        $this->assertFalse($reset, "Reset should be false");
    }

    public function test_openldap_reset_false_empty(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdreset' => [
                        'count' => 1,
                        0 => null,
                    ]
                ]
            ]
        ]);

        $reset = (new Ltb\Directory\OpenLDAP)->resetAtNextConnection(null, null);
        $this->assertFalse($reset, "Reset should be false");
    }

    public function test_activedirectory_islocked_locked_forever(): void
    {
        $ad_date = ((int)time() + 11644473600) * 10000000;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'lockouttime' => [
                        'count' => 1,
                        0 => $ad_date
                    ]
                ]
            ]
        ]);

        $isLocked = (new Ltb\Directory\ActiveDirectory)->isLocked(null, null, array('lockout_duration' => 0));
        $this->assertTrue($isLocked, "Account should be locked forever");
    }

    public function test_activedirectory_islocked_not_locked(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'lockouttime' => [
                        'count' => 1,
                        0 => null
                    ]
                ]
            ]
        ]);

        $isLocked = (new Ltb\Directory\ActiveDirectory)->isLocked(null, null, array('lockout_duration' => 0));
        $this->assertFalse($isLocked, "Account should not be locked");
    }

    public function test_activedirectory_islocked_still_locked(): void
    {
        $ad_date = ((int)time() + 11644473600) * 10000000;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'lockouttime' => [
                        'count' => 1,
                        0 => $ad_date
                    ]
                ]
            ]
        ]);

        $isLocked = (new Ltb\Directory\ActiveDirectory)->isLocked(null, null, array('lockout_duration' => 86400));
        $this->assertTrue($isLocked, "Account should be still locked");
    }

    public function test_activedirectory_islocked_no_more_locked(): void
    {
        $ad_date = ((int)time() - 864000 + 11644473600) * 10000000;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'lockouttime' => [
                        'count' => 1,
                        0 => $ad_date
                    ]
                ]
            ]
        ]);

        $isLocked = (new Ltb\Directory\ActiveDirectory)->isLocked(null, null, array('lockout_duration' => 86400));
        $this->assertFalse($isLocked, "Account should no more be locked");
    }

    public function test_activedirectory_getlockdate_empty(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'lockouttime' => [
                        'count' => 1,
                        0 => null,
                    ]
                ]
            ]
        ]);

        $getLockDate = (new Ltb\Directory\ActiveDirectory)->getLockDate(null, null);
        $this->assertNull($getLockDate, "Lock date should be null");
    }

    public function test_activedirectory_getlockdate_notempty(): void
    {
        $dt = new DateTime;
        $ad_date = ((int)$dt->getTimestamp() + 11644473600) * 10000000;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'lockouttime' => [
                        'count' => 1,
                        0 => $ad_date,
                    ]
                ]
            ]
        ]);

        $getLockDate = (new Ltb\Directory\ActiveDirectory)->getLockDate(null, null);
        $this->assertInstanceOf("DateTime", $getLockDate, "Lock date should be a PHP DateTime object");
        $this->assertEquals($dt->format("Y/m/d - h:i:s"), $getLockDate->format("Y/m/d - h:i:s"), "Lock date is correct");
    }

    public function test_activedirectory_getunlockdate_noduration(): void
    {
        $ad_date = ((int)time() + 11644473600) * 10000000;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'lockouttime' => [
                        'count' => 1,
                        0 => $ad_date,
                    ]
                ]
            ]
        ]);

        $unlockDate = (new Ltb\Directory\ActiveDirectory)->getUnlockDate(null, null, array('lockout_duration' => 0));
        $this->assertNull($unlockDate, "Unock date should be null");
    }

    public function test_activedirectory_getunlockdate_duration(): void
    {
        $dt = new DateTime;
        $ad_date = ((int)$dt->getTimestamp() + 11644473600) * 10000000;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'lockouttime' => [
                        'count' => 1,
                        0 => $ad_date,
                    ]
                ]
            ]
        ]);

        $unlockDate = (new Ltb\Directory\ActiveDirectory)->getUnlockDate(null, null, array('lockout_duration' => 86400));
        $this->assertInstanceOf("DateTime", $unlockDate, "Unlock date should be a PHP DateTime object");
        $this->assertEquals($dt->modify("+1 day")->format("Y/m/d - h:i:s"), $unlockDate->format("Y/m/d - h:i:s"), "Unlock date is correct");
    }

    public function test_activedirectory_isexpired_expired(): void
    {
        $dt = new DateTime;
        $ad_date = ((int)$dt->modify("-1 month")->getTimestamp() + 11644473600) * 10000000;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdlastset' => [
                        'count' => 1,
                        0 => $ad_date,
                    ]
                ]
            ]
        ]);

        $isPasswordExpired = (new Ltb\Directory\ActiveDirectory)->isPasswordExpired(null, null, array('password_max_age' => 86400));
        $this->assertTrue($isPasswordExpired, "Password should be expired");
    }

    public function test_activedirectory_isexpired_not_expired(): void
    {
        $dt = new DateTime;
        $ad_date = ((int)$dt->modify("-1 hour")->getTimestamp() + 11644473600) * 10000000;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdlastset' => [
                        'count' => 1,
                        0 => $ad_date,
                    ]
                ]
            ]
        ]);

        $isPasswordExpired = (new Ltb\Directory\ActiveDirectory)->isPasswordExpired(null, null, array('password_max_age' => 86400));
        $this->assertFalse($isPasswordExpired, "Password should not be expired");
    }

    public function test_activedirectory_getpasswordexpirationdate_empty(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdlastset' => [
                        'count' => 1,
                        0 => null,
                    ]
                ]
            ]
        ]);

        $getPasswordExpirationDate = (new Ltb\Directory\ActiveDirectory)->getPasswordExpirationDate(null, null, null);
        $this->assertNull($getPasswordExpirationDate, "Password expiration date should be null");
    }

    public function test_activedirectory_getpasswordexpirationdate_notempty(): void
    {
        $dt = new DateTime;
        $ad_date = ((int)$dt->getTimestamp() + 11644473600) * 10000000;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdlastset' => [
                        'count' => 1,
                        0 => $ad_date,
                    ]
                ]
            ]
        ]);

        $passwordExpirationDate = (new Ltb\Directory\ActiveDirectory)->getPasswordExpirationDate(null, null, array('password_max_age' => 86400));
        $this->assertInstanceOf("DateTime", $passwordExpirationDate, "Password expiration date should be a PHP DateTime object");
        $this->assertEquals($dt->modify("+1 day")->format("Y/m/d - h:i:s"), $passwordExpirationDate->format("Y/m/d - h:i:s"), "Password expiration date is correct");
    }

    public function test_activedirectory_reset_true(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdlastset' => [
                        'count' => 1,
                        0 => 0,
                    ]
                ]
            ]
        ]);

        $reset = (new Ltb\Directory\ActiveDirectory)->resetAtNextConnection(null, null);
        $this->assertTrue($reset, "Reset should be true");
    }

    public function test_activedirectory_reset_false(): void
    {
        $dt = new DateTime;
        $ad_date = ((int)$dt->getTimestamp() + 11644473600) * 10000000;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdlastset' => [
                        'count' => 1,
                        0 => $ad_date,
                    ]
                ]
            ]
        ]);

        $reset = (new Ltb\Directory\ActiveDirectory)->resetAtNextConnection(null, null);
        $this->assertFalse($reset, "Reset should be false");
    }

    public function test_activedirectory_reset_false_empty(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdlastset' => [
                        'count' => 1,
                        0 => null,
                    ]
                ]
            ]
        ]);

        $reset = (new Ltb\Directory\ActiveDirectory)->resetAtNextConnection(null, null);
        $this->assertFalse($reset, "Reset should be false");
    }

}
