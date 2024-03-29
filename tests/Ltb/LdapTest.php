<?php

require __DIR__ . '/../../vendor/autoload.php';

// global variable for ldap_get_mail_for_notification function
$GLOBALS['mail_attributes'] = array("mail");

final class LdapTest extends \Mockery\Adapter\Phpunit\MockeryTestCase
{

    public function test_connect(): void
    {

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_connect')
                    ->with("ldap://test.my-domain.com")
                    ->andReturn("ldap_connection");

        $phpLDAPMock->shouldreceive('ldap_set_option')
                    ->andReturn(null);

        $phpLDAPMock->shouldreceive('ldap_bind')
                    ->with("ldap_connection", "cn=test,dc=my-domain,dc=com","secret")
                    ->andReturn(true);

        list($ldap, $msg) = Ltb\Ldap::connect("ldap://test.my-domain.com", false, "cn=test,dc=my-domain,dc=com", "secret", 10, null);

        $this->assertNotFalse($ldap, "Error while connecting to LDAP server");
        $this->assertFalse($msg, "Error message returned while connecting to LDAP server");
    }

    public function test_get_list(): void
    {

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_search')
                    ->with("ldap_connection", "ou=people,dc=my-domain,dc=com", "(uid=test)", array("cn", "sn"))
                    ->andReturn("ldap_search_result");

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with("ldap_connection")
                    ->andReturn(false);

        $phpLDAPMock->shouldreceive('ldap_get_entries')
                    ->with("ldap_connection","ldap_search_result")
                    ->andReturn([
                                    'count' => 2,
                                    0 => [
                                        'count' => 2,
                                        0 => 'cn',
                                        1 => 'sn',
                                        'cn' => [
                                            'count' => 1,
                                            0 => 'testcn1'
                                        ],
                                        'sn' => [
                                            'count' => 1,
                                            0 => 'testsn1'
                                        ]
                                    ],
                                    1 => [
                                        'count' => 2,
                                        0 => 'cn',
                                        1 => 'sn',
                                        'cn' => [
                                            'count' => 1,
                                            0 => 'testcn2'
                                        ],
                                        'sn' => [
                                            'count' => 1,
                                            0 => 'testsn2'
                                        ]
                                    ]
                                ]);

        // return hashmap: [ cn_value => sn_value ]
        $result = Ltb\Ldap::get_list("ldap_connection", "ou=people,dc=my-domain,dc=com", "(uid=test)", "cn","sn");

        $this->assertEquals('testcn1', array_keys($result)[0], "not getting testcn1 as key in get_list function");
        $this->assertEquals('testsn1', $result["testcn1"], "not getting testsn1 as value in get_list function");

        $this->assertEquals('testcn2', array_keys($result)[1], "not getting testcn2 as key in get_list function");
        $this->assertEquals('testsn2', $result["testcn2"], "not getting testsn2 as value in get_list function");

    }

    public function test_ldapSort(): void
    {

        $entries = [
            'count' => 2,
            0 => [
                'count' => 2,
                0 => 'cn',
                1 => 'sn',
                'cn' => [
                    'count' => 1,
                    0 => 'testcn1'
                ],
                'sn' => [
                    'count' => 1,
                    0 => 'zzzz'
                ]
            ],
            1 => [
                'count' => 2,
                0 => 'cn',
                1 => 'sn',
                'cn' => [
                    'count' => 1,
                    0 => 'testcn2'
                ],
                'sn' => [
                    'count' => 1,
                    0 => 'aaaa'
                ]
            ]
        ];

        $return = Ltb\Ldap::ldapSort($entries, "sn");

        $this->assertTrue($return, "Weird value returned by ldapSort function");
        $this->assertEquals('testcn2', $entries[0]['cn'][0], "testcn2 has not been ordered correctly in entries array");
        $this->assertEquals('testcn1', $entries[1]['cn'][0], "testcn1 has not been ordered correctly in entries array");
    }

    public function test_sorted_search_with_sort_control(): void
    {

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_read')
                    ->with("ldap_connection", '', '(objectClass=*)', ['supportedControl'])
                    ->andReturn("check");

        $phpLDAPMock->shouldreceive('ldap_get_entries')
                    ->andReturnUsing( function ($ldap, $ldap_result)
                                      {
                                          if ($ldap_result == "check") {
                                              return [
                                                         'count' => 1,
                                                         0 => [
                                                             'count' => 1,
                                                             0 => 'supportedcontrol',
                                                             'supportedcontrol' => [
                                                                 'count' => 1,
                                                                 0 => LDAP_CONTROL_SORTREQUEST
                                                             ]
                                                         ]
                                                     ];
                                          }
                                          elseif($ldap_result == "ldap_search_result")
                                          {
                                              return [
                                                         'count' => 2,
                                                         0 => [
                                                             'count' => 2,
                                                             0 => 'cn',
                                                             1 => 'sn',
                                                             'cn' => [
                                                                 'count' => 1,
                                                                 0 => 'testcn2'
                                                             ],
                                                             'sn' => [
                                                                 'count' => 1,
                                                                 0 => 'aaaa'
                                                             ]
                                                         ],
                                                         1 => [
                                                             'count' => 2,
                                                             0 => 'cn',
                                                             1 => 'sn',
                                                             'cn' => [
                                                                 'count' => 1,
                                                                 0 => 'testcn1'
                                                             ],
                                                             'sn' => [
                                                                 'count' => 1,
                                                                 0 => 'zzzz'
                                                             ]
                                                         ]
                                                     ];

                                          }
                                          else
                                          {
                                              return "ldap_get_entries_error";
                                          }
                                      }
                                    );

        $phpLDAPMock->shouldreceive('ldap_search')
                    ->with("ldap_connection",
                           "ou=people,dc=my-domain,dc=com",
                           "(objectClass=InetOrgPerson)",
                           ["cn", "sn"],
                           0,
                           1000,
                           -1,
                           LDAP_DEREF_NEVER,
                           [['oid' => LDAP_CONTROL_SORTREQUEST, 'value' => [['attr'=>'sn']]]]
                          )
                    ->andReturn("ldap_search_result");

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with("ldap_connection")
                    ->andReturn(0);

        list($ldap_result,$errno,$entries) = Ltb\Ldap::sorted_search("ldap_connection",
                                                                     "ou=people,dc=my-domain,dc=com",
                                                                     "(objectClass=InetOrgPerson)",
                                                                     ["cn", "sn"],
                                                                     "sn",
                                                                     1000
                                                                    );

        $this->assertEquals("ldap_search_result", $ldap_result, "error while getting ldap_search sorted result");
        $this->assertEquals(0, $errno, "error code invalid while getting ldap_search sorted result");
        $this->assertEquals('testcn2', $entries[0]['cn'][0], "error while getting ldap_search sorted result: first entry is not testcn2");
        $this->assertEquals('testcn1', $entries[1]['cn'][0], "error while getting ldap_search sorted result: second entry is not testcn1");

    }

    public function test_sorted_search_without_sort_control(): void
    {

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_read')
                    ->with("ldap_connection", '', '(objectClass=*)', ['supportedControl'])
                    ->andReturn("check");

        $phpLDAPMock->shouldreceive('ldap_get_entries')
                    ->andReturnUsing( function ($ldap, $ldap_result)
                                      {
                                          if ($ldap_result == "check") {
                                              return [
                                                         'count' => 1,
                                                         0 => [
                                                             'count' => 1,
                                                             0 => 'supportedcontrol',
                                                             'supportedcontrol' => [
                                                                 'count' => 1,
                                                                 0 => LDAP_CONTROL_VLVREQUEST
                                                             ]
                                                         ]
                                                     ];
                                          }
                                          elseif($ldap_result == "ldap_search_result")
                                          {
                                              return [
                                                         'count' => 2,
                                                         0 => [
                                                             'count' => 2,
                                                             0 => 'cn',
                                                             1 => 'sn',
                                                             'cn' => [
                                                                 'count' => 1,
                                                                 0 => 'testcn1'
                                                             ],
                                                             'sn' => [
                                                                 'count' => 1,
                                                                 0 => 'zzzz'
                                                             ]
                                                         ],
                                                         1 => [
                                                             'count' => 2,
                                                             0 => 'cn',
                                                             1 => 'sn',
                                                             'cn' => [
                                                                 'count' => 1,
                                                                 0 => 'testcn2'
                                                             ],
                                                             'sn' => [
                                                                 'count' => 1,
                                                                 0 => 'aaaa'
                                                             ]
                                                         ],
                                                     ];

                                          }
                                          else
                                          {
                                              return "ldap_get_entries_error";
                                          }
                                      }
                                    );

        $phpLDAPMock->shouldreceive('ldap_search')
                    ->with("ldap_connection",
                           "ou=people,dc=my-domain,dc=com",
                           "(objectClass=InetOrgPerson)",
                           ["cn", "sn"],
                           0,
                           1000
                          )
                    ->andReturn("ldap_search_result");

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with("ldap_connection")
                    ->andReturn(0);

        list($ldap_result,$errno,$entries) = Ltb\Ldap::sorted_search("ldap_connection",
                                                                     "ou=people,dc=my-domain,dc=com",
                                                                     "(objectClass=InetOrgPerson)",
                                                                     ["cn", "sn"],
                                                                     "sn",
                                                                     1000
                                                                    );

        $this->assertEquals("ldap_search_result", $ldap_result, "error while getting ldap_search sorted result");
        $this->assertEquals(0, $errno, "error code invalid while getting ldap_search sorted result");
        $this->assertEquals('testcn2', $entries[0]['cn'][0], "error while getting ldap_search sorted result: first entry is not testcn2");
        $this->assertEquals('testcn1', $entries[1]['cn'][0], "error while getting ldap_search sorted result: second entry is not testcn1");

    }

    public function test_get_password_value(): void
    {

        $ldap_connection = "ldap_connection";
        $dn = "uid=test,ou=people,dc=my-domain,dc=com";
        $pwdattribute = "userPassword";
        $expectedValues = [
                              "count" => 1,
                              0 => 'secret'
                          ];

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_read')
                    ->with($ldap_connection, $dn, '(objectClass=*)', [ $pwdattribute ])
                    ->andReturn("ldap_result");

        $phpLDAPMock->shouldreceive('ldap_first_entry')
                    ->with($ldap_connection, "ldap_result")
                    ->andReturn("result_entry");

        $phpLDAPMock->shouldreceive('ldap_get_values')
                    ->with($ldap_connection, "result_entry", $pwdattribute)
                    ->andReturn($expectedValues);

        $values = Ltb\Ldap::get_password_values(
                                                  $ldap_connection,
                                                  $dn,
                                                  $pwdattribute
                                              );

        $this->assertEquals(1, $values['count'], "error while getting cardinal of password values in get_password_value");
        $this->assertEquals('secret', $values[0], "wrong password value in get_password_value");

    }

    public function test_get_password_value_with_dummy_pwdattribute(): void
    {

        $ldap_connection = "ldap_connection";
        $dn = "uid=test,ou=people,dc=my-domain,dc=com";
        $pwdattribute = false;

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_read')
                    ->with($ldap_connection, $dn, '(objectClass=*)', [ $pwdattribute ])
                    ->andReturn(false);

        $values = Ltb\Ldap::get_password_values(
                                                   $ldap_connection,
                                                   $dn,
                                                   $pwdattribute
                                               );
        $this->assertFalse($values, 'Weird returned value in get_password_value while sending dummy $pwdattribute');

    }

  /** runInSeparateProcess is needed for \Ltb\Password
   *  not interfering with other tests
   * @runInSeparateProcess
   */
    #[RunInSeparateProcess]
    public function test_change_ad_password_as_user(): void
    {

        $ldap_connection = "ldap_connection";
        $dn = "uid=test,ou=people,dc=my-domain,dc=com";
        $old_password = "old";
        $hased_old_password = "hashed";
        $new_password = "new";
        $modifications = array(
            array(
                "attrib" => "unicodePwd",
                "modtype" => LDAP_MODIFY_BATCH_REMOVE,
                "values" => array($hased_old_password),
            ),
            array(
                "attrib" => "unicodePwd",
                "modtype" => LDAP_MODIFY_BATCH_ADD,
                "values" => array($new_password),
            )
        );

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_modify_batch')
                    ->with($ldap_connection, $dn, $modifications)
                    ->andReturn(true);

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with($ldap_connection)
                    ->andReturn(0);

        $phpLDAPMock->shouldreceive('ldap_error')
                    ->with($ldap_connection)
                    ->andReturn("ok");


        $passwordMock = Mockery::mock('overload:\Ltb\Password');

        $passwordMock->shouldreceive('make_ad_password')
                     ->with($old_password)
                     ->andReturn($hased_old_password);


        list($error_code, $error_msg) =
            Ltb\Ldap::change_ad_password_as_user(
                                                    $ldap_connection,
                                                    $dn,
                                                    $old_password,
                                                    $new_password
                                                );

        $this->assertEquals(0, $error_code, 'Weird error code returned in change_ad_password_as_user');
        $this->assertEquals("ok", $error_msg, 'Weird msg returned in change_ad_password_as_user');

    }


    public function test_get_ppolicy_error_code(): void
    {
        // method get_ppolicy_error_code cannot be tested as it is protected (and Ldap class is final)

        $this->assertTrue(method_exists("\Ltb\Ldap",'get_ppolicy_error_code'), 'No method get_ppolicy_error_code in class');

    }

    public function test_change_password_with_exop_noppolicy(): void
    {

        $ldap_connection = "ldap_connection";
        $dn = "uid=test,ou=people,dc=my-domain,dc=com";
        $old_password = "old";
        $new_password = "new";
        $ppolicy = false;
        $res = true; // ldap_exop_passwd result is string|bool (new password if omitted from args else true or false)

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_exop_passwd')
                    ->with($ldap_connection, $dn, $old_password, $new_password)
                    ->andReturn($res);

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with($ldap_connection)
                    ->andReturn(0);

        $phpLDAPMock->shouldreceive('ldap_error')
                    ->with($ldap_connection)
                    ->andReturn("ok");

        list($error_code, $error_msg, $ppolicy_error_code) =
            Ltb\Ldap::change_password_with_exop(
                                             $ldap_connection,
                                             $dn,
                                             $old_password,
                                             $new_password,
                                             $ppolicy
                                         );

        $this->assertEquals(0, $error_code, 'Weird error code returned in change_password_with_exop');
        $this->assertEquals("ok", $error_msg, 'Weird msg returned in change_password_with_exop');
        $this->assertFalse($ppolicy_error_code, 'Weird ppolicy_error_code returned in change_password_with_exop');

    }

    public function test_change_password_with_exop_ppolicy(): void
    {

        $ldap_connection = "ldap_connection";
        $dn = "uid=test,ou=people,dc=my-domain,dc=com";
        $old_password = "old";
        $new_password = "new";
        $ppolicy = true;
        $res = true; // ldap_exop_passwd result is string|bool (new password if omitted from args else true or false)

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_exop_passwd')
                    ->with($ldap_connection, $dn, $old_password, $new_password, array())
                    ->andReturn($res);

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with($ldap_connection)
                    ->andReturn(0);

        $phpLDAPMock->shouldreceive('ldap_error')
                    ->with($ldap_connection)
                    ->andReturn("ok");

        list($error_code, $error_msg, $ppolicy_error_code) =
            Ltb\Ldap::change_password_with_exop(
                                             $ldap_connection,
                                             $dn,
                                             $old_password,
                                             $new_password,
                                             $ppolicy
                                         );

        $this->assertEquals(0, $error_code, 'Weird error code returned in change_password_with_exop with policy');
        $this->assertEquals("ok", $error_msg, 'Weird msg returned in change_password_with_exop with policy');
        $this->assertFalse($ppolicy_error_code, 'Weird ppolicy_error_code returned in change_password_with_exop with policy');

    }

    public function test_change_password_with_exop_ppolicy_fail(): void
    {

        $ldap_connection = "ldap_connection";
        $dn = "uid=test,ou=people,dc=my-domain,dc=com";
        $old_password = "old";
        $new_password = "new";
        $ppolicy = true;
        $res = false; // ldap_exop_passwd result is string|bool (new password if omitted from args else true or false)

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_exop_passwd')
                    ->with($ldap_connection, $dn, $old_password, $new_password, array())
                    ->andReturn($res);

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with($ldap_connection)
                    ->andReturn(49);

        $phpLDAPMock->shouldreceive('ldap_error')
                    ->with($ldap_connection)
                    ->andReturn("Invalid credentials");

        list($error_code, $error_msg, $ppolicy_error_code) =
            Ltb\Ldap::change_password_with_exop(
                                             $ldap_connection,
                                             $dn,
                                             $old_password,
                                             $new_password,
                                             $ppolicy
                                         );

        $this->assertEquals(49, $error_code, 'Weird error code returned in failing change_password_with_exop with policy');
        $this->assertEquals("Invalid credentials", $error_msg, 'Weird msg returned in failing change_password_with_exop with policy');
        $this->assertFalse($ppolicy_error_code, 'Weird ppolicy_error_code returned in failing change_password_with_exop with policy');

    }

    public function test_modify_attributes_using_ppolicy(): void
    {

        $ldap_connection = "ldap_connection";
        $dn = "uid=test,ou=people,dc=my-domain,dc=com";
        $userdata = [
                       "mail" => [ 'test1@domain.com', 'test2@domain.com'],
                       "userPassword" => "secret",
                       "description" => array()
                    ];
        $ctrls = [['oid' => LDAP_CONTROL_PASSWORDPOLICYREQUEST]];
        $res = true; // result of ldap_mod_replace_ext operation

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_mod_replace_ext')
                    ->with($ldap_connection, $dn, $userdata, $ctrls)
                    ->andReturn($res);

        $phpLDAPMock->shouldreceive('ldap_parse_result')
                    ->with($ldap_connection, $res, "", null, "", null, array())
                    ->andReturn($res);


        list($error_code, $error_msg, $ppolicy_error_code) =
            Ltb\Ldap::modify_attributes_using_ppolicy(
                                             $ldap_connection,
                                             $dn,
                                             $userdata
                                         );

        $this->assertEquals("", $error_code, 'Weird error code returned in modify_attributes_using_ppolicy');
        $this->assertEquals("", $error_msg, 'Weird msg returned in modify_attributes_using_ppolicy');
        $this->assertFalse($ppolicy_error_code, 'Weird ppolicy_error_code returned in modify_attributes_using_ppolicy');

    }

    public function test_modify_attributes(): void
    {

        $ldap_connection = "ldap_connection";
        $dn = "uid=test,ou=people,dc=my-domain,dc=com";
        $userdata = [
                       "mail" => [ 'test1@domain.com', 'test2@domain.com'],
                       "userPassword" => "secret",
                       "description" => array()
                    ];
        $res = true; // result of ldap_mod_replace_ext operation

        $phpLDAPMock = Mockery::mock('overload:\Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_mod_replace')
                    ->with($ldap_connection, $dn, $userdata)
                    ->andReturn($res);

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with($ldap_connection)
                    ->andReturn(0);

        $phpLDAPMock->shouldreceive('ldap_error')
                    ->with($ldap_connection)
                    ->andReturn("ok");

        list($error_code, $error_msg) =
            Ltb\Ldap::modify_attributes(
                                           $ldap_connection,
                                           $dn,
                                           $userdata
                                       );

        $this->assertEquals(0, $error_code, 'Weird error code returned in modify_attributes');
        $this->assertEquals("ok", $error_msg, 'Weird msg returned in modify_attributes');

    }

    public function setUp(): void
    {
        // Turn on error reporting
        //error_reporting(E_ALL);
    }

}
