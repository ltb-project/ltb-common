<?php

require __DIR__ . '/../../vendor/autoload.php';
use PHPUnit\Framework\TestCase;

// global variable for ldap_get_mail_for_notification function
$GLOBALS['mail_attributes'] = array("mail");

final class IntegrationTest extends TestCase
{

    public $host = "ldap://127.0.0.1:33389/";
    public $managerDN = "cn=admin,dc=fusioniam,dc=org";
    public $managerPW = "secret";
    public $attributes = array("cn");
    public $context = "dc=fusioniam,dc=org";

    public $adminDN = "cn=lemonldapng,ou=dsa,o=admin,dc=fusioniam,dc=org";
    public $adminPW = "secret";

    public $user_branch = "ou=users,o=acme,dc=fusioniam,dc=org";
    public $ldap_entry_dn1 = "uid=test,ou=users,o=acme,dc=fusioniam,dc=org";
    public $ldap_entry1 = [
        "objectclass" => array("inetOrgPerson", "organizationalPerson", "person"),
        "cn" => array("test1", "test2", "test3"),
        "sn" => "test",
        "uid" => "test",
        "userPassword" => "secret",
        "mail" => array("test1@domain.com", "test2@domain.com"),
        "pwdPolicySubentry" => "cn=ppolicy1,ou=ppolicies,o=acme,dc=fusioniam,dc=org"
    ];
    public $ppolicy_branch = "ou=ppolicies,o=acme,dc=fusioniam,dc=org";
    public $ldap_ppolicy_dn1 = "cn=ppolicy1,ou=ppolicies,o=acme,dc=fusioniam,dc=org";
    public $ldap_ppolicy1 = [
        "objectclass" => array("organizationalRole", "pwdPolicy"),
        "cn" => array("ppolicy1"),
        "pwdAttribute" => "userPassword",
        "pwdAllowUserChange" => "TRUE",
        "pwdInHistory" => "5",
        "pwdLockout" => "TRUE"
    ];

    /*
       Function setting up the environement, executed before each test
       add a test entry
    */
    protected function setUp(): void
    {

        error_reporting(E_ALL);

        $ldap = ldap_connect($this->host);
        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);

        // binding to ldap server
        $ldapbind = ldap_bind($ldap, $this->managerDN, $this->managerPW);

        // search for ldap entry
        $sr = ldap_search($ldap, $this->user_branch, "(uid=test)", $this->attributes);
        if( $sr )
        {
            $info = ldap_get_entries($ldap, $sr);
            if( $info["count"] == 0)
            {
                // if it does not exist, add the entry
                $r = ldap_add($ldap, $this->ldap_ppolicy_dn1, $this->ldap_ppolicy1);
                $r = ldap_add($ldap, $this->ldap_entry_dn1, $this->ldap_entry1);
            }
        }

        ldap_unbind($ldap);
    }

    /*
       Function cleaning up the environement, executed after each test
       remove the test entry created during setup
    */
    protected function tearDown(): void
    {

        $ldap = ldap_connect($this->host);
        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);

        // binding to ldap server
        $ldapbind = ldap_bind($ldap, $this->managerDN, $this->managerPW);

        // search for ldap entry
        $sr = ldap_search($ldap, $this->user_branch, "(uid=test)", $this->attributes);
        if( $sr )
        {
            $info = ldap_get_entries($ldap, $sr);
            if( $info["count"] == 1)
            {
                // if it exists, delete the entry
                $r = ldap_delete($ldap, $this->ldap_entry_dn1);
                $r = ldap_delete($ldap, $this->ldap_ppolicy_dn1);
            }
        }

        ldap_unbind($ldap);
    }


    public function test_ldap_get_first_available_value(): void
    {

        $ldap = ldap_connect($this->host);
        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);

        // binding to ldap server
        $ldapbind = ldap_bind($ldap, $this->adminDN, $this->adminPW);

        // search for added entry
        $sr = ldap_search($ldap, $this->ldap_entry_dn1, "(objectClass=*)", $this->attributes);
        $entry = ldap_first_entry($ldap, $sr);

        # Test ldap_get_first_available_value
        $ent = Ltb\AttributeValue::ldap_get_first_available_value($ldap, $entry, $this->attributes);
        $this->assertEquals("cn", $ent->attribute, "not getting attribute cn");
        $this->assertEquals("test1", $ent->value, "not getting value test1 as cn first value");
    }

    public function test_ldap_get_mail_for_notification(): void
    {
        $mail_attributes = array("mail");

        $ldap = ldap_connect($this->host);
        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);

        // binding to ldap server
        $ldapbind = ldap_bind($ldap, $this->adminDN, $this->adminPW);

        // search for added entry
        $sr = ldap_search($ldap, $this->ldap_entry_dn1, "(objectClass=*)", $GLOBALS['mail_attributes']);
        $entry = ldap_first_entry($ldap, $sr);

        # Test ldap_get_first_available_value
        $mail = Ltb\AttributeValue::ldap_get_mail_for_notification($ldap, $entry, $mail_attributes);
        $this->assertEquals('test1@domain.com', $mail, "not getting test1@domain.com as mail for notification");

    }

    public function test_connect(): void
    {

        $ldapInstance = new \Ltb\Ldap(
                                         $this->host,
                                         false,
                                         $this->adminDN,
                                         $this->adminPW,
                                         10,
                                         null,
                                         null,
                                         null
                                     );
        list($ldap, $msg) = $ldapInstance->connect();

        $this->assertNotFalse($ldap, "Error while connecting to LDAP server");
        $this->assertFalse($msg, "Error message returned while connecting to LDAP server");
    }

    public function test_get_list(): void
    {

        $ldapInstance = new \Ltb\Ldap(
                                         $this->host,
                                         false,
                                         $this->adminDN,
                                         $this->adminPW,
                                         10,
                                         $this->user_branch,
                                         0,
                                         null
                                     );

        list($ldap, $msg) = $ldapInstance->connect();

        // return hashmap: [ cn_value => sn_value ]
        $result = $ldapInstance->get_list($this->user_branch, "(uid=test)", "cn","sn");

        $this->assertEquals('test1', array_keys($result)[0], "not getting test1 as key in get_list function");
        $this->assertEquals('test', $result["test1"], "not getting test as value in get_list function");

    }

    public function test_modify_attributes_using_ppolicy_failure(): void
    {

        $userdata1 = [ # first modification => accepted
                       "userPassword" => "secret2",
                     ];
        $userdata2 = [ # second modification => refused because already present in history
                       "userPassword" => "secret",
                     ];


        $ldapInstance = new \Ltb\Ldap(
                                         $this->host,
                                         false,
                                         $this->adminDN,
                                         $this->adminPW,
                                         10,
                                         $this->user_branch,
                                         0,
                                         null
                                     );

        list($ldap, $msg) = $ldapInstance->connect();


        # Modify the password a first time
        list($error_code, $error_msg, $ppolicy_error_code) =
            $ldapInstance->modify_attributes_using_ppolicy(
                                             $this->ldap_entry_dn1,
                                             $userdata1
                                         );

        $this->assertEquals(0, $error_code, 'Weird error code returned while modifying userPassword');
        $this->assertEquals('', $error_msg, 'Weird msg returned while modifying userPassword');
        $this->assertFalse($ppolicy_error_code, 'Weird ppolicy_error_code returned while modifying userPassword');

        # Modify the password a second time with failure
        list($error_code, $error_msg, $ppolicy_error_code) =
            $ldapInstance->modify_attributes_using_ppolicy(
                                             $this->ldap_entry_dn1,
                                             $userdata2
                                         );

        $this->assertEquals(19, $error_code, 'Weird error code returned in modify_attributes_using_ppolicy with failure');
        $this->assertEquals('Password is in history of old passwords', $error_msg, 'Weird msg returned in modify_attributes_using_ppolicy with failure');
        $this->assertEquals(8, $ppolicy_error_code, 'Weird ppolicy_error_code returned in modify_attributes_using_ppolicy with failure');

    }

}
