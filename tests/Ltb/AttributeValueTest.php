<?php

require __DIR__ . '/../../vendor/autoload.php';
use PHPUnit\Framework\TestCase;

final class AttributeValueTest extends \Mockery\Adapter\Phpunit\MockeryTestCase
{

    public function test_ldap_get_first_available_value(): void
    {

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
                                      'ldap_get_attributes' => ['cn'],
                                      'ldap_get_values' => [
                                                             'count' => 3,
                                                             0 => 'test1',
                                                             1 => 'test2',
                                                             2 => 'test3'
                                                           ]
                                    ]);

        $ent = Ltb\AttributeValue::ldap_get_first_available_value(null, null, ['cn']);
        $this->assertEquals("cn", $ent->attribute, "not getting attribute cn");
        $this->assertEquals("test1", $ent->value, "not getting value test1 as cn first value");
        
    }

    public function test_ldap_get_first_available_value_empty(): void
    {

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
                                      'ldap_get_attributes' => ['cn'],
                                      'ldap_get_values' => [
                                                             'count' => 0
                                                           ]
                                    ]);

        $ent = Ltb\AttributeValue::ldap_get_first_available_value(null, null, ['cn']);
        $this->assertFalse($ent, "not getting false result whereas no value has been returned");
        
    }

    public function test_ldap_get_mail_for_notification(): void
    {

        // global variable for ldap_get_mail_for_notification function
        $mail_attributes = array("mail");

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
                                      'ldap_get_attributes' => ['mail'],
                                      'ldap_get_values' => [
                                                             'count' => 2,
                                                             0 => 'test1@domain.com',
                                                             1 => 'test2@domain.com'
                                                           ]
                                    ]);

        # Test ldap_get_mail_for_notification
        $mail = Ltb\AttributeValue::ldap_get_mail_for_notification(null, null, $mail_attributes);
        $this->assertEquals('test1@domain.com', $mail, "not getting test1@domain.com as mail for notification");
    }

    public function test_ldap_get_proxy_for_notification(): void
    {

        // global variable for ldap_get_mail_for_notification function
        $mail_attributes = array("proxyAddresses");

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');
        $phpLDAPMock->shouldreceive([
                                      'ldap_get_attributes' => ['proxyAddresses'],
                                      'ldap_get_values' => [
                                                             'count' => 2,
                                                             0 => 'smtp:test1@domain.com',
                                                             1 => 'smtp:test2@domain.com'
                                                           ]
                                    ]);

        # Test ldap_get_mail_for_notification
        $mail = Ltb\AttributeValue::ldap_get_mail_for_notification(null, null, $mail_attributes);
        $this->assertEquals('test1@domain.com', $mail, "not getting test1@domain.com as proxyAddress for notification");
    }

}
