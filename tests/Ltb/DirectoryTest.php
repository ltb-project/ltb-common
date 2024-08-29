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

}
