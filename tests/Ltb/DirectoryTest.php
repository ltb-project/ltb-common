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

}
