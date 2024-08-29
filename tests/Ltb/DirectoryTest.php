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

}
