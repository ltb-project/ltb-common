<?php

require __DIR__ . '/../../vendor/autoload.php';
use PHPUnit\Framework\TestCase;

final class DirectoryTest extends \Mockery\Adapter\Phpunit\MockeryTestCase
{

    public function test_openldap_islocked_locked_forever(): void
    {
        $entry = [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => "000001010000Z"
                    ]
                 ];

        $isLocked = (new Ltb\Directory\OpenLDAP)->isLocked($entry, null);
        $this->assertTrue($isLocked, "Account should be locked forever");
    }

    public function test_openldap_islocked_not_locked(): void
    {
        $entry = [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => null
                    ]
                 ];

        $isLocked = (new Ltb\Directory\OpenLDAP)->isLocked($entry, null);
        $this->assertFalse($isLocked, "Account should not be locked");
    }

    public function test_openldap_islocked_still_locked(): void
    {
        $entry = [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => (new DateTime)->format("Ymdhis\Z")
                    ]
                ];

        $isLocked = (new Ltb\Directory\OpenLDAP)->isLocked($entry, array('lockout_duration' => 86400));
        $this->assertTrue($isLocked, "Account should still be locked");
    }

    public function test_openldap_islocked_no_more_locked(): void
    {
        $entry = [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => (new DateTime)->modify("-10 days")->format("Ymdhis\Z")
                    ]
                 ];

        $isLocked = (new Ltb\Directory\OpenLDAP)->isLocked($entry, array('lockout_duration' => 86400));
        $this->assertFalse($isLocked, "Account should no more be locked");
    }

    public function test_openldap_getlockdate_empty(): void
    {
        $entry = [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => null
                    ]
                 ];

        $getLockDate = (new Ltb\Directory\OpenLDAP)->getLockDate($entry, null);
        $this->assertNull($getLockDate, "Lock date should be null");
    }

    public function test_openldap_getlockdate_lock_forever(): void
    {
        $entry = [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => "000001010000Z"
                    ]
                 ];

        $getLockDate = (new Ltb\Directory\OpenLDAP)->getLockDate($entry, null);
        $this->assertNull($getLockDate, "Lock date should be null if user is locked forever");
    }

    public function test_openldap_getlockdate_notempty(): void
    {
        $dt = new DateTime;
        $entry = [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => $dt->format("Ymdhis\Z")
                    ]
                 ];

        $getLockDate = (new Ltb\Directory\OpenLDAP)->getLockDate($entry, null);
        $this->assertInstanceOf("DateTime", $getLockDate, "Lock date should be a PHP DateTime object");
        $this->assertEquals($dt->format("Y/m/d - h:i:s"), $getLockDate->format("Y/m/d - h:i:s"), "Lock date is correct");
    }

    public function test_openldap_getunlockdate_noduration(): void
    {
        $dt = new DateTime;
        $entry = [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => $dt->format("Ymdhis\Z")
                    ]
                 ];

        $unlockDate = (new Ltb\Directory\OpenLDAP)->getUnlockDate($entry, array('lockout_duration' => 0));
        $this->assertNull($unlockDate, "Unkock date should be null");
    }

    public function test_openldap_getunlockdate_duration(): void
    {
        $dt = new DateTime;
        $entry = [
                    'pwdaccountlockedtime' => [
                        'count' => 1,
                        0 => $dt->format("Ymdhis\Z")
                    ]
                 ];

        $unlockDate = (new Ltb\Directory\OpenLDAP)->getUnlockDate($entry, array('lockout_duration' => 86400));
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

    public function test_openldap_isvalid_nodate(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 0,
            ]
        ]);

        $isAccountValid = (new Ltb\Directory\OpenLDAP)->isAccountValid(null, null);
        $this->assertTrue($isAccountValid, "Account should be valid");
    }

    public function test_openldap_isvalid_startdate_before(): void
    {
        $dt = new DateTime;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdstarttime' => [
                        'count' => 1,
                        0 => $dt->modify("-1 week")->format("Ymdhis\Z"),
                    ]
                ]
            ]
        ]);

        $isAccountValid = (new Ltb\Directory\OpenLDAP)->isAccountValid(null, null);
        $this->assertTrue($isAccountValid, "Account should be valid");
    }

    public function test_openldap_isvalid_startdate_after(): void
    {
        $dt = new DateTime;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdstarttime' => [
                        'count' => 1,
                        0 => $dt->modify("+1 week")->format("Ymdhis\Z"),
                    ]
                ]
            ]
        ]);

        $isAccountValid = (new Ltb\Directory\OpenLDAP)->isAccountValid(null, null);
        $this->assertFalse($isAccountValid, "Account should not be valid");
    }

    public function test_openldap_isvalid_enddate_before(): void
    {
        $dt = new DateTime;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdendtime' => [
                        'count' => 1,
                        0 => $dt->modify("-1 week")->format("Ymdhis\Z"),
                    ]
                ]
            ]
        ]);

        $isAccountValid = (new Ltb\Directory\OpenLDAP)->isAccountValid(null, null);
        $this->assertFalse($isAccountValid, "Account should not be valid");
    }

    public function test_openldap_isvalid_enddate_after(): void
    {
        $dt = new DateTime;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdendtime' => [
                        'count' => 1,
                        0 => $dt->modify("+1 week")->format("Ymdhis\Z"),
                    ]
                ]
            ]
        ]);

        $isAccountValid = (new Ltb\Directory\OpenLDAP)->isAccountValid(null, null);
        $this->assertTrue($isAccountValid, "Account should be valid");
    }

    public function test_openldap_isvalid_bothdate(): void
    {
        $dt = new DateTime;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'pwdstarttime' => [
                        'count' => 1,
                        0 => $dt->modify("-1 week")->format("Ymdhis\Z"),
                    ],
                    'pwdendtime' => [
                        'count' => 1,
                        0 => $dt->modify("+2 week")->format("Ymdhis\Z"),
                    ]
                ]
            ]
        ]);

        $isAccountValid = (new Ltb\Directory\OpenLDAP)->isAccountValid(null, null);
        $this->assertTrue($isAccountValid, "Account should be valid");
    }

    public function test_activedirectory_islocked_locked_forever(): void
    {
        $ad_date = ((int)time() + 11644473600) * 10000000;
        $entry = [
                    'lockouttime' => [
                        'count' => 1,
                        0 => $ad_date
                    ]
                 ];

        $isLocked = (new Ltb\Directory\ActiveDirectory)->isLocked($entry, array('lockout_duration' => 0));
        $this->assertTrue($isLocked, "Account should be locked forever");
    }

    public function test_activedirectory_islocked_not_locked(): void
    {
        $entry = [
                    'lockouttime' => [
                        'count' => 1,
                        0 => null
                    ]
                 ];

        $isLocked = (new Ltb\Directory\ActiveDirectory)->isLocked($entry, array('lockout_duration' => 0));
        $this->assertFalse($isLocked, "Account should not be locked");
    }

    public function test_activedirectory_islocked_still_locked(): void
    {
        $ad_date = ((int)time() + 11644473600) * 10000000;
        $entry = [
                    'lockouttime' => [
                        'count' => 1,
                        0 => $ad_date
                    ]
                ];

        $isLocked = (new Ltb\Directory\ActiveDirectory)->isLocked($entry, array('lockout_duration' => 86400));
        $this->assertTrue($isLocked, "Account should be still locked");
    }

    public function test_activedirectory_islocked_no_more_locked(): void
    {
        $ad_date = ((int)time() - 864000 + 11644473600) * 10000000;
        $entry = [
                    'lockouttime' => [
                        'count' => 1,
                        0 => $ad_date
                    ]
                 ];

        $isLocked = (new Ltb\Directory\ActiveDirectory)->isLocked($entry, array('lockout_duration' => 86400));
        $this->assertFalse($isLocked, "Account should no more be locked");
    }

    public function test_activedirectory_getlockdate_empty(): void
    {
        $entry = [
                    'lockouttime' => [
                        'count' => 1,
                        0 => null,
                    ]
                 ];

        $getLockDate = (new Ltb\Directory\ActiveDirectory)->getLockDate($entry, null);
        $this->assertNull($getLockDate, "Lock date should be null");
    }

    public function test_activedirectory_getlockdate_notempty(): void
    {
        $dt = new DateTime;
        $ad_date = ((int)$dt->getTimestamp() + 11644473600) * 10000000;
        $entry = [
                    'lockouttime' => [
                        'count' => 1,
                        0 => $ad_date,
                    ]
                 ];


        $getLockDate = (new Ltb\Directory\ActiveDirectory)->getLockDate($entry, null);
        $this->assertInstanceOf("DateTime", $getLockDate, "Lock date should be a PHP DateTime object");
        $this->assertEquals($dt->format("Y/m/d - h:i:s"), $getLockDate->format("Y/m/d - h:i:s"), "Lock date is correct");
    }

    public function test_activedirectory_getunlockdate_noduration(): void
    {
        $ad_date = ((int)time() + 11644473600) * 10000000;
        $entry = [
                    'lockouttime' => [
                        'count' => 1,
                        0 => $ad_date,
                    ]
                 ];


        $unlockDate = (new Ltb\Directory\ActiveDirectory)->getUnlockDate($entry, array('lockout_duration' => 0));
        $this->assertNull($unlockDate, "Unock date should be null");
    }

    public function test_activedirectory_getunlockdate_duration(): void
    {
        $dt = new DateTime;
        $ad_date = ((int)$dt->getTimestamp() + 11644473600) * 10000000;
        $entry = [
                    'lockouttime' => [
                        'count' => 1,
                        0 => $ad_date,
                    ]
                 ];

        $unlockDate = (new Ltb\Directory\ActiveDirectory)->getUnlockDate($entry, array('lockout_duration' => 86400));
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

    public function test_activedirectory_isenabled_true(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'useraccountcontrol' => [
                        'count' => 1,
                        0 => 512,
                    ]
                ]
            ]
        ]);

        $accountEnabled = (new Ltb\Directory\ActiveDirectory)->isAccountEnabled(null, null);
        $this->assertTrue($accountEnabled, "Account should be enabled");
    }

    public function test_activedirectory_isenabled_false(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'useraccountcontrol' => [
                        'count' => 1,
                        0 => 514,
                    ]
                ]
            ]
        ]);

        $accountEnabled = (new Ltb\Directory\ActiveDirectory)->isAccountEnabled(null, null);
        $this->assertFalse($accountEnabled, "Account should be disabled");
    }

    public function test_openldap_isenabled_true(): void
    {

        $ldap = "ldap_connection";
        $dn = "cn=dummy,dc=my-domain,dc=com";
        $search_result = "search_result";

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_read')
                    ->with($ldap, $dn, "(objectClass=*)", array('pwdAccountDisabled'))
                    ->andReturn($search_result);

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with($ldap)
                    ->andReturn(false);

        $phpLDAPMock->shouldreceive('ldap_get_entries')
                    ->with($ldap, $search_result)
                    ->andReturn([
                                    'count' => 1,
                                    0 => [
                                        'count' => 0,
                                        'dn' => 'uid=test,ou=people,dc=my-domain,dc=com',
                                    ]
                                ]);

        $accountEnabled = (new Ltb\Directory\OpenLDAP)->isAccountEnabled($ldap, $dn);
        $this->assertTrue($accountEnabled, "OpenLDAP account should be enabled");
    }

    public function test_openldap_isenabled_false(): void
    {

        $ldap = "ldap_connection";
        $dn = "cn=dummy,dc=my-domain,dc=com";
        $search_result = "search_result";

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_read')
                    ->with($ldap, $dn, "(objectClass=*)", array('pwdAccountDisabled'))
                    ->andReturn($search_result);

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with($ldap)
                    ->andReturn(false);

        $phpLDAPMock->shouldreceive('ldap_get_entries')
                    ->with($ldap, $search_result)
                    ->andReturn(
                                   [
                                       'count' => 1,
                                       0 =>
                                       [
                                           'pwdaccountdisabled' =>
                                           [
                                               'count' => 1,
                                               0 => '00000101000000Z',
                                           ],
                                           0 => 'pwdaccountdisabled',
                                           'count' => 1,
                                           'dn' => 'uid=test,ou=people,dc=my-domain,dc=com',
                                       ],
                                   ]
                               );

        $accountEnabled = (new Ltb\Directory\OpenLDAP)->isAccountEnabled($ldap, $dn);
        $this->assertFalse($accountEnabled, "OpenLDAP account should be disabled");
    }

    public function test_openldap_isenabled_error(): void
    {

        $ldap = "ldap_connection";
        $dn = "invaliddn";
        $search_result = "search_result";

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_read')
                    ->with($ldap, $dn, "(objectClass=*)", array('pwdAccountDisabled'))
                    ->andReturn($search_result);

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with($ldap)
                    ->andReturn(34);

        $phpLDAPMock->shouldreceive('ldap_error')
                    ->with($ldap)
                    ->andReturn("Invalid DN syntax");


        $accountEnabled = (new Ltb\Directory\OpenLDAP)->isAccountEnabled($ldap, $dn);
        $this->assertFalse($accountEnabled, "OpenLDAP account should be considered disabled while error is encountered");
    }

    public function test_openldap_enable_account_ok(): void
    {
        $ldap = "ldap_connection";
        $dn = "cn=dummy,dc=my-domain,dc=com";
        $update_result = "update_result";

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_mod_replace')
                    ->with($ldap, $dn, [ 'pwdAccountDisabled' => [] ])
                    ->andReturn($update_result);

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with($ldap)
                    ->andReturn(0);

        $enableAccountResult = (new Ltb\Directory\OpenLDAP)->enableAccount($ldap, $dn);
        $this->assertTrue($enableAccountResult, "Error while enabling OpenLDAP account");
    }

    public function test_openldap_enable_account_ko(): void
    {
        $ldap = "ldap_connection";
        $dn = "cn=dummy,dc=my-domain,dc=com";
        $update_result = "update_result";

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_mod_replace')
                    ->with($ldap, $dn, [ 'pwdAccountDisabled' => [] ])
                    ->andReturn($update_result);

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with($ldap)
                    ->andReturn(50);

        $phpLDAPMock->shouldreceive('ldap_error')
                    ->with($ldap)
                    ->andReturn("Insufficient rights");

        $enableAccountResult = (new Ltb\Directory\OpenLDAP)->enableAccount($ldap, $dn);
        $this->assertFalse($enableAccountResult, "Should have encountered error while enabling OpenLDAP account");
    }

    public function test_openldap_disable_account_ok(): void
    {
        $ldap = "ldap_connection";
        $dn = "cn=dummy,dc=my-domain,dc=com";
        $update_result = "update_result";

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_mod_replace')
                    ->with(
                              $ldap,
                              $dn,
                              \Mockery::on(function ($mod) {
                                  if( preg_match('/^[0-9]{14}Z$/', $mod['pwdAccountDisabled'][0]) )
                                      return true;
                                  else
                                      return false;
                              })
                          )
                    ->andReturn($update_result);

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with($ldap)
                    ->andReturn(0);

        $disableAccountResult = (new Ltb\Directory\OpenLDAP)->disableAccount($ldap, $dn);
        $this->assertTrue($disableAccountResult, "Error while disabling OpenLDAP account");
    }

    public function test_openldap_disable_account_ko(): void
    {
        $ldap = "ldap_connection";
        $dn = "cn=dummy,dc=my-domain,dc=com";
        $update_result = "update_result";

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_mod_replace')
                    ->with(
                              $ldap,
                              $dn,
                              \Mockery::on(function ($mod) {
                                  if( preg_match('/^[0-9]{14}Z$/', $mod['pwdAccountDisabled'][0]) )
                                      return true;
                                  else
                                      return false;
                              })
                          )
                    ->andReturn($update_result);

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with($ldap)
                    ->andReturn(50);

        $phpLDAPMock->shouldreceive('ldap_error')
                    ->with($ldap)
                    ->andReturn("Insufficient rights");

        $disableAccountResult = (new Ltb\Directory\OpenLDAP)->disableAccount($ldap, $dn);
        $this->assertFalse($disableAccountResult, "Should have encountered error while disabling OpenLDAP account");
    }

    public function test_activedirectory_isvalid_nodate(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 0,
            ]
        ]);

        $isAccountValid = (new Ltb\Directory\ActiveDirectory)->isAccountValid(null, null);
        $this->assertTrue($isAccountValid, "Account should be valid");
    }

    public function test_activedirectory_isvalid_enddate_before(): void
    {
        $dt = new DateTime;
        $ad_date = ((int)$dt->modify("-1 week")->getTimestamp() + 11644473600) * 10000000;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'accountexpires' => [
                        'count' => 1,
                        0 => $ad_date,
                    ]
                ]
            ]
        ]);

        $isAccountValid = (new Ltb\Directory\ActiveDirectory)->isAccountValid(null, null);
        $this->assertFalse($isAccountValid, "Account should not be valid");
    }

    public function test_activedirectory_isvalid_enddate_after(): void
    {
        $dt = new DateTime;
        $ad_date = ((int)$dt->modify("+1 week")->getTimestamp() + 11644473600) * 10000000;
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'accountexpires' => [
                        'count' => 1,
                        0 => $ad_date,
                    ]
                ]
            ]
        ]);

        $isAccountValid = (new Ltb\Directory\ActiveDirectory)->isAccountValid(null, null);
        $this->assertTrue($isAccountValid, "Account should be valid");
    }

    public function test_activedirectory_isvalid_enddate_zero(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'accountexpires' => [
                        'count' => 1,
                        0 => 0,
                    ]
                ]
            ]
        ]);

        $isAccountValid = (new Ltb\Directory\ActiveDirectory)->isAccountValid(null, null);
        $this->assertTrue($isAccountValid, "Account should be valid");
    }

    public function test_activedirectory_isvalid_enddate_full(): void
    {
        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
            'ldap_read' => null,
            'ldap_errno' => 0,
            'ldap_get_entries' => [
                'count' => 1,
                0 => [
                    'accountexpires' => [
                        'count' => 1,
                        0 => 9223372036854775807,
                    ]
                ]
            ]
        ]);

        $isAccountValid = (new Ltb\Directory\ActiveDirectory)->isAccountValid(null, null);
        $this->assertTrue($isAccountValid, "Account should be valid");
    }
}
