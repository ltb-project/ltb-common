<?php

require __DIR__ . '/../../vendor/autoload.php';

use PHPUnit\Framework\Attributes\RunInSeparateProcess;

final class LdapTest extends \Mockery\Adapter\Phpunit\MockeryTestCase
{

    // connection variables
    public $ldap_url = "ldap://test.my-domain.com";
    public $ldap_starttls = false;
    public $ldap_binddn = "cn=test,dc=my-domain,dc=com";
    public $ldap_bindpw = "secret";
    public $ldap_network_timeout = 10;
    public $ldap_user_base = "ou=people,dc=my-domain,dc=com";
    public $ldap_size_limit = 1000;
    public $ldap_krb5ccname = null;

    public function test_construct(): void
    {
        $ldapInstance = new \Ltb\Ldap(
                                         $this->ldap_url,
                                         $this->ldap_starttls,
                                         $this->ldap_binddn,
                                         $this->ldap_bindpw,
                                         $this->ldap_network_timeout,
                                         $this->ldap_user_base,
                                         $this->ldap_size_limit,
                                         $this->ldap_krb5ccname
                                     );
        $this->assertEquals($this->ldap_url, $ldapInstance->ldap_url, "Error while initializing ldap_url");
        $this->assertEquals($this->ldap_starttls, $ldapInstance->ldap_starttls, "Error while initializing ldap_starttls");
        $this->assertEquals($this->ldap_binddn, $ldapInstance->ldap_binddn, "Error while initializing ldap_binddn");
        $this->assertEquals($this->ldap_bindpw, $ldapInstance->ldap_bindpw, "Error while initializing ldap_bindpw");
        $this->assertEquals($this->ldap_network_timeout, $ldapInstance->ldap_network_timeout, "Error while initializing ldap_network_timeout");
        $this->assertEquals($this->ldap_user_base, $ldapInstance->ldap_user_base, "Error while initializing ldap_user_base");
        $this->assertEquals($this->ldap_size_limit, $ldapInstance->ldap_size_limit, "Error while initializing ldap_size_limit");
        $this->assertEquals($this->ldap_krb5ccname, $ldapInstance->ldap_krb5ccname, "Error while initializing ldap_krb5ccname");
    }

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

        $ldapInstance = new \Ltb\Ldap(
                                         $this->ldap_url,
                                         $this->ldap_starttls,
                                         $this->ldap_binddn,
                                         $this->ldap_bindpw,
                                         $this->ldap_network_timeout,
                                         $this->ldap_user_base,
                                         $this->ldap_size_limit,
                                         $this->ldap_krb5ccname
                                     );
        list($ldap, $msg) = $ldapInstance->connect();

        $this->assertNotFalse($ldap, "Error while connecting to LDAP server");
        $this->assertFalse($msg, "Error message returned while connecting to LDAP server");
    }



    public function test_search(): void
    {

        $ldap_filter = "(objectClass=inetOrgPerson)";
        $attributes = array("cn", "sn");
        $attributes_map = array(
            'authtimestamp' => array( 'attribute' => 'authtimestamp', 'faclass' => 'lock', 'type' => 'date' ),
            'businesscategory' => array( 'attribute' => 'businesscategory', 'faclass' => 'briefcase', 'type' => 'text' ),
            'carlicense' => array( 'attribute' => 'carlicense', 'faclass' => 'car', 'type' => 'text' ),
            'created' => array( 'attribute' => 'createtimestamp', 'faclass' => 'clock-o', 'type' => 'date' ),
            'description' => array( 'attribute' => 'description', 'faclass' => 'info-circle', 'type' => 'text' ),
            'displayname' => array( 'attribute' => 'displayname', 'faclass' => 'user-circle', 'type' => 'text' ),
            'employeenumber' => array( 'attribute' => 'employeenumber', 'faclass' => 'hashtag', 'type' => 'text' ),
            'employeetype' => array( 'attribute' => 'employeetype', 'faclass' => 'id-badge', 'type' => 'text' ),
            'fax' => array( 'attribute' => 'facsimiletelephonenumber', 'faclass' => 'fax', 'type' => 'tel' ),
            'firstname' => array( 'attribute' => 'givenname', 'faclass' => 'user-o', 'type' => 'text' ),
            'fullname' => array( 'attribute' => 'cn', 'faclass' => 'user-circle', 'type' => 'text' ),
            'identifier' => array( 'attribute' => 'uid', 'faclass' => 'user-o', 'type' => 'text' ),
            'l' => array( 'attribute' => 'l', 'faclass' => 'globe', 'type' => 'text' ),
            'lastname' => array( 'attribute' => 'sn', 'faclass' => 'user-o', 'type' => 'text' ),
            'mail' => array( 'attribute' => 'mail', 'faclass' => 'envelope-o', 'type' => 'mailto' ),
            'mailquota' => array( 'attribute' => 'gosamailquota', 'faclass' => 'pie-chart', 'type' => 'bytes' ),
            'manager' => array( 'attribute' => 'manager', 'faclass' => 'user-circle-o', 'type' => 'dn_link' ),
            'mobile' => array( 'attribute' => 'mobile', 'faclass' => 'mobile', 'type' => 'tel' ),
            'modified' => array( 'attribute' => 'modifytimestamp', 'faclass' => 'clock-o', 'type' => 'date' ),
            'organization' => array( 'attribute' => 'o', 'faclass' => 'building', 'type' => 'text' ),
            'organizationalunit' => array( 'attribute' => 'ou', 'faclass' => 'building-o', 'type' => 'text' ),
            'pager' => array( 'attribute' => 'pager', 'faclass' => 'mobile', 'type' => 'tel' ),
            'phone' => array( 'attribute' => 'telephonenumber', 'faclass' => 'phone', 'type' => 'tel' ),
            'postaladdress' => array( 'attribute' => 'postaladdress', 'faclass' => 'map-marker', 'type' => 'address' ),
            'postalcode' => array( 'attribute' => 'postalcode', 'faclass' => 'globe', 'type' => 'text' ),
            'pwdaccountlockedtime' => array( 'attribute' => 'pwdaccountlockedtime', 'faclass' => 'lock', 'type' => 'date' ),
            'pwdchangedtime' => array( 'attribute' => 'pwdchangedtime', 'faclass' => 'lock', 'type' => 'date' ),
            'pwdfailuretime' => array( 'attribute' => 'pwdfailuretime', 'faclass' => 'lock', 'type' => 'date' ),
            'pwdlastsuccess' => array( 'attribute' => 'pwdlastsuccess', 'faclass' => 'lock', 'type' => 'date' ),
            'pwdreset' => array( 'attribute' => 'pwdreset', 'faclass' => 'lock', 'type' => 'boolean' ),
            'secretary' => array( 'attribute' => 'secretary', 'faclass' => 'user-circle-o', 'type' => 'dn_link' ),
            'state' => array( 'attribute' => 'st', 'faclass' => 'globe', 'type' => 'text' ),
            'street' => array( 'attribute' => 'street', 'faclass' => 'map-marker', 'type' => 'text' ),
            'title' => array( 'attribute' => 'title', 'faclass' => 'certificate', 'type' => 'text' ),
        );
        $search_result_title = "fullname";
        $search_result_sortby = "lastname";
        $search_result_items = array('identifier', 'mail', 'mobile');
        $search_scope = "sub";

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
                               0 => 'zzzzzz'
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
                               0 => 'aaaaaa'
                           ]
                       ]
        ];

        $phpLDAPMock = Mockery::mock('overload:\Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_connect')
                    ->with($this->ldap_url)
                    ->andReturn("ldap_connection");

        $phpLDAPMock->shouldreceive('ldap_set_option')
                    ->andReturn(null);

        $phpLDAPMock->shouldreceive('ldap_bind')
                    ->with("ldap_connection", $this->ldap_binddn, $this->ldap_bindpw)
                    ->andReturn(true);

        $phpLDAPMock->shouldreceive('ldap_search')
                    ->with("ldap_connection",
                           $this->ldap_user_base,
                           "(objectClass=inetOrgPerson)",
                           [0 => 'cn', 1 => 'sn', 2 => 'uid', 3 => 'mail', 4 => 'mobile', 5 => 'cn', 6 => 'sn'],
                           0,
                           $this->ldap_size_limit,
                           -1,
                           0,
                           null
                          )
                    ->andReturn("ldap_search_result");

        $phpLDAPMock->shouldreceive('ldap_parse_result')
                    ->with("ldap_connection", "ldap_search_result", null, null, null, null, null);

        $phpLDAPMock->shouldreceive('ldap_count_entries')
                    ->with("ldap_connection", "ldap_search_result")
                    ->andReturn(2);

        $phpLDAPMock->shouldreceive('ldap_get_entries')
                    ->with("ldap_connection","ldap_search_result")
                    ->andReturn($entries);

        $ldapInstance = new \Ltb\Ldap(
                                         $this->ldap_url,
                                         $this->ldap_starttls,
                                         $this->ldap_binddn,
                                         $this->ldap_bindpw,
                                         $this->ldap_network_timeout,
                                         $this->ldap_user_base,
                                         $this->ldap_size_limit,
                                         $this->ldap_krb5ccname
                                     );
        list($ldap, $msg) = $ldapInstance->connect();

        list($ldap,$result,$nb_entries,$res_entries,$size_limit_reached) = 
                  $ldapInstance->search( $ldap_filter,
                                         $attributes,
                                         $attributes_map,
                                         $search_result_title,
                                         $search_result_sortby,
                                         $search_result_items,
                                         $search_scope
                                       );

        $this->assertEquals("ldap_connection", $ldap, "Error while getting ldap_connection in search function");
        $this->assertFalse($result, "Error message returned while connecting to LDAP server in search function");
        $this->assertEquals(2, $nb_entries, "Wrong number of entries returned by search function");
        $this->assertEquals("testcn2", $res_entries[0]["cn"][0], "Wrong cn received in first entry. Entries may have not been sorted?");
        $this->assertEquals("testcn1", $res_entries[1]["cn"][0], "Wrong cn received in second entry. Entries may have not been sorted?");
        $this->assertFalse($size_limit_reached, "Unexpected size limit reached in search function");
    }


    public function test_search_with_page_size(): void
    {

        $ldap_page_size = 1;
        $control1 = [[
                         'oid' => LDAP_CONTROL_PAGEDRESULTS,
                         'value' => [
                             'size' => $ldap_page_size,
                             'cookie' => ""
                         ]
                    ]];

        $cookie_page2 = "cookie_page2";
        $control2 = [[
                         'oid' => LDAP_CONTROL_PAGEDRESULTS,
                         'value' => [
                             'size' => $ldap_page_size,
                             'cookie' => $cookie_page2
                         ]
                    ]];

        $returnedcontrol1 = [
                                LDAP_CONTROL_PAGEDRESULTS =>
                                    [
                                        'cookie' =>
                                            [
                                                'value' => $cookie_page2
                                            ]
                                    ]
                            ];
        $returnedcontrol2 = [ LDAP_CONTROL_PAGEDRESULTS => [ ] ];

        $ldap_filter = "(objectClass=inetOrgPerson)";
        $attributes = array("cn", "sn");
        $attributes_map = array(
            'authtimestamp' => array( 'attribute' => 'authtimestamp', 'faclass' => 'lock', 'type' => 'date' ),
            'businesscategory' => array( 'attribute' => 'businesscategory', 'faclass' => 'briefcase', 'type' => 'text' ),
            'carlicense' => array( 'attribute' => 'carlicense', 'faclass' => 'car', 'type' => 'text' ),
            'created' => array( 'attribute' => 'createtimestamp', 'faclass' => 'clock-o', 'type' => 'date' ),
            'description' => array( 'attribute' => 'description', 'faclass' => 'info-circle', 'type' => 'text' ),
            'displayname' => array( 'attribute' => 'displayname', 'faclass' => 'user-circle', 'type' => 'text' ),
            'employeenumber' => array( 'attribute' => 'employeenumber', 'faclass' => 'hashtag', 'type' => 'text' ),
            'employeetype' => array( 'attribute' => 'employeetype', 'faclass' => 'id-badge', 'type' => 'text' ),
            'fax' => array( 'attribute' => 'facsimiletelephonenumber', 'faclass' => 'fax', 'type' => 'tel' ),
            'firstname' => array( 'attribute' => 'givenname', 'faclass' => 'user-o', 'type' => 'text' ),
            'fullname' => array( 'attribute' => 'cn', 'faclass' => 'user-circle', 'type' => 'text' ),
            'identifier' => array( 'attribute' => 'uid', 'faclass' => 'user-o', 'type' => 'text' ),
            'l' => array( 'attribute' => 'l', 'faclass' => 'globe', 'type' => 'text' ),
            'lastname' => array( 'attribute' => 'sn', 'faclass' => 'user-o', 'type' => 'text' ),
            'mail' => array( 'attribute' => 'mail', 'faclass' => 'envelope-o', 'type' => 'mailto' ),
            'mailquota' => array( 'attribute' => 'gosamailquota', 'faclass' => 'pie-chart', 'type' => 'bytes' ),
            'manager' => array( 'attribute' => 'manager', 'faclass' => 'user-circle-o', 'type' => 'dn_link' ),
            'mobile' => array( 'attribute' => 'mobile', 'faclass' => 'mobile', 'type' => 'tel' ),
            'modified' => array( 'attribute' => 'modifytimestamp', 'faclass' => 'clock-o', 'type' => 'date' ),
            'organization' => array( 'attribute' => 'o', 'faclass' => 'building', 'type' => 'text' ),
            'organizationalunit' => array( 'attribute' => 'ou', 'faclass' => 'building-o', 'type' => 'text' ),
            'pager' => array( 'attribute' => 'pager', 'faclass' => 'mobile', 'type' => 'tel' ),
            'phone' => array( 'attribute' => 'telephonenumber', 'faclass' => 'phone', 'type' => 'tel' ),
            'postaladdress' => array( 'attribute' => 'postaladdress', 'faclass' => 'map-marker', 'type' => 'address' ),
            'postalcode' => array( 'attribute' => 'postalcode', 'faclass' => 'globe', 'type' => 'text' ),
            'pwdaccountlockedtime' => array( 'attribute' => 'pwdaccountlockedtime', 'faclass' => 'lock', 'type' => 'date' ),
            'pwdchangedtime' => array( 'attribute' => 'pwdchangedtime', 'faclass' => 'lock', 'type' => 'date' ),
            'pwdfailuretime' => array( 'attribute' => 'pwdfailuretime', 'faclass' => 'lock', 'type' => 'date' ),
            'pwdlastsuccess' => array( 'attribute' => 'pwdlastsuccess', 'faclass' => 'lock', 'type' => 'date' ),
            'pwdreset' => array( 'attribute' => 'pwdreset', 'faclass' => 'lock', 'type' => 'boolean' ),
            'secretary' => array( 'attribute' => 'secretary', 'faclass' => 'user-circle-o', 'type' => 'dn_link' ),
            'state' => array( 'attribute' => 'st', 'faclass' => 'globe', 'type' => 'text' ),
            'street' => array( 'attribute' => 'street', 'faclass' => 'map-marker', 'type' => 'text' ),
            'title' => array( 'attribute' => 'title', 'faclass' => 'certificate', 'type' => 'text' ),
        );
        $search_result_title = "fullname";
        $search_result_sortby = "lastname";
        $search_result_items = array('identifier', 'mail', 'mobile');
        $search_scope = "sub";

        $entries1 = [
                       'count' => 1,
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
                               0 => 'zzzzzz'
                           ]
                       ]
        ];

        $entries2 = [
                       'count' => 1,
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
                               0 => 'aaaaaa'
                           ]
                       ]
        ];

        $phpLDAPMock = Mockery::mock('overload:\Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_connect')
                    ->with($this->ldap_url)
                    ->andReturn("ldap_connection");

        $phpLDAPMock->shouldreceive('ldap_set_option')
                    ->andReturn(null);

        $phpLDAPMock->shouldreceive('ldap_bind')
                    ->with("ldap_connection", $this->ldap_binddn, $this->ldap_bindpw)
                    ->andReturn(true);

        $phpLDAPMock->shouldreceive('ldap_search')
                    ->with("ldap_connection",
                           $this->ldap_user_base,
                           "(objectClass=inetOrgPerson)",
                           [0 => 'cn', 1 => 'sn', 2 => 'uid', 3 => 'mail', 4 => 'mobile', 5 => 'cn', 6 => 'sn'],
                           0,
                           $this->ldap_size_limit,
                           -1,
                           0,
                           $control1
                          )
                    ->andReturn("ldap_search_result1");

        $phpLDAPMock->shouldreceive('ldap_search')
                    ->with("ldap_connection",
                           $this->ldap_user_base,
                           "(objectClass=inetOrgPerson)",
                           [0 => 'cn', 1 => 'sn', 2 => 'uid', 3 => 'mail', 4 => 'mobile', 5 => 'cn', 6 => 'sn'],
                           0,
                           $this->ldap_size_limit,
                           -1,
                           0,
                           $control2
                          )
                    ->andReturn("ldap_search_result2");

        $phpLDAPMock->shouldreceive('ldap_parse_result')
                    ->with("ldap_connection", "ldap_search_result1", null, null, null, null,
                           \Mockery::on(function(&$control) use(&$returnedcontrol1, &$returnedcontrol2, &$control1, &$control2){
                               $cookie = $control[0]['value']['cookie'];
                               switch ($cookie) {
                                   case $control1[0]['value']['cookie']:
                                       $control = $returnedcontrol1;
                                       return true;
                                   case $control2[0]['value']['cookie']:
                                       $control = $returnedcontrol2;
                                       return true;
                                   default:
                                       return false;
                               }
                           })
                    );

        $phpLDAPMock->shouldreceive('ldap_count_entries')
                    ->with("ldap_connection", "ldap_search_result1")
                    ->andReturn(1);

        $phpLDAPMock->shouldreceive('ldap_count_entries')
                    ->with("ldap_connection", "ldap_search_result2")
                    ->andReturn(1);

        $phpLDAPMock->shouldreceive('ldap_get_entries')
                    ->with("ldap_connection","ldap_search_result1")
                    ->andReturn($entries1);

        $phpLDAPMock->shouldreceive('ldap_get_entries')
                    ->with("ldap_connection","ldap_search_result2")
                    ->andReturn($entries2);

        $ldapInstance = new \Ltb\Ldap(
                                         $this->ldap_url,
                                         $this->ldap_starttls,
                                         $this->ldap_binddn,
                                         $this->ldap_bindpw,
                                         $this->ldap_network_timeout,
                                         $this->ldap_user_base,
                                         $this->ldap_size_limit,
                                         $this->ldap_krb5ccname,
                                         $ldap_page_size
                                     );
        list($ldap, $msg) = $ldapInstance->connect();

        list($ldap,$result,$nb_entries,$res_entries,$size_limit_reached) =
                  $ldapInstance->search( $ldap_filter,
                                         $attributes,
                                         $attributes_map,
                                         $search_result_title,
                                         $search_result_sortby,
                                         $search_result_items,
                                         $search_scope
                                       );

        $this->assertEquals("ldap_connection", $ldap, "Error while getting ldap_connection in search function");
        $this->assertFalse($result, "Error message returned while connecting to LDAP server in search function");
        $this->assertEquals(1, $nb_entries, "Wrong number of entries returned by search function");
        #$this->assertEquals(2, $nb_entries, "Wrong number of entries returned by search function");
        $this->assertEquals("testcn1", $res_entries[0]["cn"][0], "Wrong cn received in first entry.");
        #$this->assertEquals("testcn2", $res_entries[0]["cn"][0], "Wrong cn received in first entry. Entries may have not been sorted?");
        #$this->assertEquals("testcn1", $res_entries[1]["cn"][0], "Wrong cn received in second entry. Entries may have not been sorted?");
        $this->assertFalse($size_limit_reached, "Unexpected size limit reached in search function");
    }

    public function test_search_with_error(): void
    {

        $ldap_filter = "(objectClass=inetOrgPerson)";
        $attributes = array("cn", "sn");
        $attributes_map = array(
            'authtimestamp' => array( 'attribute' => 'authtimestamp', 'faclass' => 'lock', 'type' => 'date' ),
            'businesscategory' => array( 'attribute' => 'businesscategory', 'faclass' => 'briefcase', 'type' => 'text' ),
            'carlicense' => array( 'attribute' => 'carlicense', 'faclass' => 'car', 'type' => 'text' ),
            'created' => array( 'attribute' => 'createtimestamp', 'faclass' => 'clock-o', 'type' => 'date' ),
            'description' => array( 'attribute' => 'description', 'faclass' => 'info-circle', 'type' => 'text' ),
            'displayname' => array( 'attribute' => 'displayname', 'faclass' => 'user-circle', 'type' => 'text' ),
            'employeenumber' => array( 'attribute' => 'employeenumber', 'faclass' => 'hashtag', 'type' => 'text' ),
            'employeetype' => array( 'attribute' => 'employeetype', 'faclass' => 'id-badge', 'type' => 'text' ),
            'fax' => array( 'attribute' => 'facsimiletelephonenumber', 'faclass' => 'fax', 'type' => 'tel' ),
            'firstname' => array( 'attribute' => 'givenname', 'faclass' => 'user-o', 'type' => 'text' ),
            'fullname' => array( 'attribute' => 'cn', 'faclass' => 'user-circle', 'type' => 'text' ),
            'identifier' => array( 'attribute' => 'uid', 'faclass' => 'user-o', 'type' => 'text' ),
            'l' => array( 'attribute' => 'l', 'faclass' => 'globe', 'type' => 'text' ),
            'lastname' => array( 'attribute' => 'sn', 'faclass' => 'user-o', 'type' => 'text' ),
            'mail' => array( 'attribute' => 'mail', 'faclass' => 'envelope-o', 'type' => 'mailto' ),
            'mailquota' => array( 'attribute' => 'gosamailquota', 'faclass' => 'pie-chart', 'type' => 'bytes' ),
            'manager' => array( 'attribute' => 'manager', 'faclass' => 'user-circle-o', 'type' => 'dn_link' ),
            'mobile' => array( 'attribute' => 'mobile', 'faclass' => 'mobile', 'type' => 'tel' ),
            'modified' => array( 'attribute' => 'modifytimestamp', 'faclass' => 'clock-o', 'type' => 'date' ),
            'organization' => array( 'attribute' => 'o', 'faclass' => 'building', 'type' => 'text' ),
            'organizationalunit' => array( 'attribute' => 'ou', 'faclass' => 'building-o', 'type' => 'text' ),
            'pager' => array( 'attribute' => 'pager', 'faclass' => 'mobile', 'type' => 'tel' ),
            'phone' => array( 'attribute' => 'telephonenumber', 'faclass' => 'phone', 'type' => 'tel' ),
            'postaladdress' => array( 'attribute' => 'postaladdress', 'faclass' => 'map-marker', 'type' => 'address' ),
            'postalcode' => array( 'attribute' => 'postalcode', 'faclass' => 'globe', 'type' => 'text' ),
            'pwdaccountlockedtime' => array( 'attribute' => 'pwdaccountlockedtime', 'faclass' => 'lock', 'type' => 'date' ),
            'pwdchangedtime' => array( 'attribute' => 'pwdchangedtime', 'faclass' => 'lock', 'type' => 'date' ),
            'pwdfailuretime' => array( 'attribute' => 'pwdfailuretime', 'faclass' => 'lock', 'type' => 'date' ),
            'pwdlastsuccess' => array( 'attribute' => 'pwdlastsuccess', 'faclass' => 'lock', 'type' => 'date' ),
            'pwdreset' => array( 'attribute' => 'pwdreset', 'faclass' => 'lock', 'type' => 'boolean' ),
            'secretary' => array( 'attribute' => 'secretary', 'faclass' => 'user-circle-o', 'type' => 'dn_link' ),
            'state' => array( 'attribute' => 'st', 'faclass' => 'globe', 'type' => 'text' ),
            'street' => array( 'attribute' => 'street', 'faclass' => 'map-marker', 'type' => 'text' ),
            'title' => array( 'attribute' => 'title', 'faclass' => 'certificate', 'type' => 'text' ),
        );
        $search_result_title = "fullname";
        $search_result_sortby = "lastname";
        $search_result_items = array('identifier', 'mail', 'mobile');
        $search_scope = "sub";

        $phpLDAPMock = Mockery::mock('overload:\Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_connect')
                    ->with($this->ldap_url)
                    ->andReturn("ldap_connection");

        $phpLDAPMock->shouldreceive('ldap_set_option')
                    ->andReturn(null);

        $phpLDAPMock->shouldreceive('ldap_bind')
                    ->with("ldap_connection", $this->ldap_binddn, $this->ldap_bindpw)
                    ->andReturn(true);

        $phpLDAPMock->shouldreceive('ldap_search')
                    ->with("ldap_connection",
                           $this->ldap_user_base,
                           "(objectClass=inetOrgPerson)",
                           [0 => 'cn', 1 => 'sn', 2 => 'uid', 3 => 'mail', 4 => 'mobile', 5 => 'cn', 6 => 'sn'],
                           0,
                           $this->ldap_size_limit,
                           -1,
                           0,
                           null
                          )
                    ->andReturn(false);

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with("ldap_connection")
                    ->andReturn(32);

        $phpLDAPMock->shouldreceive('ldap_error')
                    ->with("ldap_connection")
                    ->andReturn("No such object");

        $ldapInstance = new \Ltb\Ldap(
                                         $this->ldap_url,
                                         $this->ldap_starttls,
                                         $this->ldap_binddn,
                                         $this->ldap_bindpw,
                                         $this->ldap_network_timeout,
                                         $this->ldap_user_base,
                                         $this->ldap_size_limit,
                                         $this->ldap_krb5ccname
                                     );
        list($ldap, $msg) = $ldapInstance->connect();

        list($ldap,$result,$nb_entries,$res_entries,$size_limit_reached) =
                  $ldapInstance->search( $ldap_filter,
                                         $attributes,
                                         $attributes_map,
                                         $search_result_title,
                                         $search_result_sortby,
                                         $search_result_items,
                                         $search_scope
                                       );

        $this->assertEquals("ldap_connection", $ldap, "Error while getting ldap_connection in search function");
        $this->assertEquals("ldaperror", $result, "Wrong result (expected error) returned by search function");
        $this->assertEquals(0, $nb_entries, "Wrong number of entries returned by search function");
        $this->assertEquals([], $res_entries, "Wrong entries (not empty) returned by search function");
        $this->assertFalse($size_limit_reached, "Unexpected size limit reached in search function");
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

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = "ldap_connection";
        // return hashmap: [ cn_value => sn_value ]
        $result = $ldapInstance->get_list("ou=people,dc=my-domain,dc=com", "(uid=test)", "cn","sn");

        $this->assertEquals('testcn1', array_keys($result)[0], "not getting testcn1 as key in get_list function");
        $this->assertEquals('testsn1', $result["testcn1"], "not getting testsn1 as value in get_list function");

        $this->assertEquals('testcn2', array_keys($result)[1], "not getting testcn2 as key in get_list function");
        $this->assertEquals('testsn2', $result["testcn2"], "not getting testsn2 as value in get_list function");

    }

    public function test_search_with_scope(): void
    {

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_search')
                    ->with("ldap_connection", "ou=people,dc=my-domain,dc=com", "(uid=test)", array("cn", "sn"))
                    ->andReturn(array("ldap_search_result"));

        $phpLDAPMock->shouldreceive('ldap_list')
                    ->with("ldap_connection", "ou=people,dc=my-domain,dc=com", "(uid=test)", array("cn", "sn"))
                    ->andReturn(array("ldap_list_result"));

        $phpLDAPMock->shouldreceive('ldap_read')
                    ->with("ldap_connection", "ou=people,dc=my-domain,dc=com", "(uid=test)", array("cn", "sn"))
                    ->andReturn(array("ldap_read_result"));

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = "ldap_connection";

        $result_search = $ldapInstance->search_with_scope("sub", "ou=people,dc=my-domain,dc=com", "(uid=test)", array("cn","sn"));
        $result_list = $ldapInstance->search_with_scope("one", "ou=people,dc=my-domain,dc=com", "(uid=test)", array("cn","sn"));
        $result_read = $ldapInstance->search_with_scope("base", "ou=people,dc=my-domain,dc=com", "(uid=test)", array("cn","sn"));
        $result_unknown = $ldapInstance->search_with_scope("unknown", "ou=people,dc=my-domain,dc=com", "(uid=test)", array("cn","sn"));

        $this->assertEquals(array('ldap_search_result'), $result_search, "function ldap_search not correctly called");
        $this->assertEquals(array('ldap_list_result'), $result_list, "function ldap_list not correctly called");
        $this->assertEquals(array('ldap_read_result'), $result_read, "function ldap_list not correctly called");
        $this->assertFalse($result_unknown, "weird return code in function ldap_read for scope=unknown");

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

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = "ldap_connection";
        $return = $ldapInstance->ldapSort($entries, "sn");

        $this->assertTrue($return, "Weird value returned by ldapSort function");
        $this->assertEquals('testcn2', $entries[0]['cn'][0], "testcn2 has not been ordered correctly in entries array");
        $this->assertEquals('testcn1', $entries[1]['cn'][0], "testcn1 has not been ordered correctly in entries array");
    }

    public function test_compare_text(): void
    {

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = "ldap_connection";
        $returnAsc = $ldapInstance->compare_text("test1", "test2");
        $returnEq = $ldapInstance->compare_text("test", "test");
        $returnDesc = $ldapInstance->compare_text("test4", "test3");

        $this->assertTrue($returnAsc < 0, "compare_text: test1 should be < to test2");
        $this->assertTrue($returnEq == 0, "compare_text: test should be = to test");
        $this->assertTrue($returnDesc > 0, "compare_text: test1 should be > to test2");
    }

    public function test_compare_bytes(): void
    {

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = "ldap_connection";
        $returnAsc = $ldapInstance->compare_bytes("4096", "2097152");
        $returnEq = $ldapInstance->compare_bytes("1024", "1024");
        $returnDesc = $ldapInstance->compare_bytes("1073741824", "2048");

        $this->assertTrue($returnAsc < 0, "compare_bytes: 4096 should be < to 2097152");
        $this->assertTrue($returnEq == 0, "compare_bytes: 1024 should be = to 1024");
        $this->assertTrue($returnDesc > 0, "compare_bytes: 1073741824 should be > to 2048");
    }

    public function test_compareValue(): void
    {

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = "ldap_connection";
        $returnBytes = $ldapInstance->compareValue("256", "1024", "bytes");
        $returnText = $ldapInstance->compareValue("test1", "test2", "this-is-a-dummy-type");

        $this->assertTrue($returnBytes < 0, "compareValue: 256 should be < to 1024 for bytes type");
        $this->assertTrue($returnText < 0, "compareValue: test1 should be < to test2 for default text type");
    }
    public function test_compareEntries(): void
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

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = "ldap_connection";
        $compareSnAscText = $ldapInstance->compareEntries("sn", "asc", "text")($entries[0], $entries[1]);
        $compareSnDescText = $ldapInstance->compareEntries("sn", "desc", "text")($entries[0], $entries[1]);
        $compareCnAscText = $ldapInstance->compareEntries("cn", "asc", "text")($entries[0], $entries[1]);
        $compareCnDescText = $ldapInstance->compareEntries("cn", "desc", "text")($entries[0], $entries[1]);

        $this->assertTrue($compareSnAscText > 0, "compareEntries: testcn1 has not been compared correctly to testcn2 for ascending text comparison of sn");
        $this->assertTrue($compareSnDescText < 0, "compareEntries: testcn1 has not been compared correctly to testcn2 for descending text comparison of sn");
        $this->assertTrue($compareCnAscText < 0, "compareEntries: testcn1 has not been compared correctly to testcn2 for ascending text comparison of cn");
        $this->assertTrue($compareCnDescText > 0, "compareEntries: testcn1 has not been compared correctly to testcn2 for descending text comparison of cn");
    }

    public function test_sortEntries(): void
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

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = "ldap_connection";
        $return = $ldapInstance->sortEntries($entries, "sn", "asc", "text");

        $this->assertTrue($return, "Weird value returned by sortEntries function");
        $this->assertEquals('testcn2', $entries[0]['cn'][0], "sortEntries: testcn2 has not been ordered correctly in entries array");
        $this->assertEquals('testcn1', $entries[1]['cn'][0], "sortEntries: testcn1 has not been ordered correctly in entries array");
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

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = "ldap_connection";
        list($ldap_result,$errno,$entries) = $ldapInstance->sorted_search(
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

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = "ldap_connection";
        list($ldap_result,$errno,$entries) = $ldapInstance->sorted_search(
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

    public function test_get_attribute_values(): void
    {

        $ldap_connection = "ldap_connection";
        $dn = "uid=test,ou=people,dc=my-domain,dc=com";
        $pwdhistory = "pwdHistory";
        $expectedValues = [
                              "count" => 2,
			      0 => 'secret',
			      1 => 'testpassword'
                          ];

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_read')
                    ->with($ldap_connection, $dn, '(objectClass=*)', [ $pwdhistory ])
                    ->andReturn("ldap_result");

        $phpLDAPMock->shouldreceive('ldap_first_entry')
                    ->with($ldap_connection, "ldap_result")
                    ->andReturn("result_entry");

        $phpLDAPMock->shouldreceive('ldap_get_values')
                    ->with($ldap_connection, "result_entry", $pwdhistory)
                    ->andReturn($expectedValues);

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = $ldap_connection;
        $value = $ldapInstance->get_attribute_values(
                                                       $dn,
                                                       $pwdhistory
                                                  );

        $this->assertEquals(["count" => 2, 'secret', 'testpassword'] , $value, "incorrect array of attribute values returned by get_attribute_values");
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

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = $ldap_connection;
        $value = $ldapInstance->get_password_value(
                                                       $dn,
                                                       $pwdattribute
                                                  );

        $this->assertEquals('secret', $value, "wrong password value in get_password_value");

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

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = $ldap_connection;
        $value = $ldapInstance->get_password_value(
                                                       $dn,
                                                       $pwdattribute
                                                   );
        $this->assertFalse($value, 'Weird returned value in get_password_value while sending dummy $pwdattribute');

    }

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


        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = $ldap_connection;
        list($error_code, $error_msg) =
            $ldapInstance->change_ad_password_as_user(
                                                         $dn,
                                                         $old_password,
                                                         $new_password
                                                     );

        $this->assertEquals(0, $error_code, 'Weird error code returned in change_ad_password_as_user');
        $this->assertEquals("ok", $error_msg, 'Weird msg returned in change_ad_password_as_user');

    }


    public function test_get_ppolicy_error_code(): void
    {
        // method get_ppolicy_error_code cannot be tested as it is protected

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

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = $ldap_connection;
        list($error_code, $error_msg, $ppolicy_error_code) =
            $ldapInstance->change_password_with_exop(
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

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = $ldap_connection;
        list($error_code, $error_msg, $ppolicy_error_code) =
            $ldapInstance->change_password_with_exop(
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

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = $ldap_connection;
        list($error_code, $error_msg, $ppolicy_error_code) =
            $ldapInstance->change_password_with_exop(
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


        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = $ldap_connection;
        list($error_code, $error_msg, $ppolicy_error_code) =
            $ldapInstance->modify_attributes_using_ppolicy(
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

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = $ldap_connection;
        list($error_code, $error_msg) =
            $ldapInstance->modify_attributes(
                                                $dn,
                                                $userdata
                                            );

        $this->assertEquals(0, $error_code, 'Weird error code returned in modify_attributes');
        $this->assertEquals("ok", $error_msg, 'Weird msg returned in modify_attributes');

    }

    public function test_get_first_value(): void
    {

        $ldap_connection = "ldap_connection";
        $ldap_base = "uid=test,ou=people,dc=my-domain,dc=com";
        $ldap_scope = "base";
        $ldap_filter = '(objectClass=inetOrgPerson)';
        $attribute = "mail,cn";
        $search_result = "search_result";
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
                               0 => 'zzzzzz'
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
                               0 => 'aaaaaa'
                           ]
                       ]
        ];


        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_read')
                    ->with($ldap_connection, $ldap_base, $ldap_filter, explode(",", $attribute))
                    ->andReturn($search_result);

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with($ldap_connection)
                    ->andReturn(0);

        $phpLDAPMock->shouldreceive('ldap_get_entries')
                    ->with($ldap_connection, $search_result)
                    ->andReturn($entries);

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = $ldap_connection;
        $value = $ldapInstance->get_first_value($ldap_base, $ldap_scope, $ldap_filter, $attribute);

        $this->assertEquals("testcn1", $value, 'Weird value returned by get_first_value method');

    }

    public function test_get_first_value_error(): void
    {

        $ldap_connection = "ldap_connection";
        $ldap_base = "DUMMY";
        $ldap_scope = "base";
        $ldap_filter = '(objectClass=inetOrgPerson)';
        $attribute = "mail,cn";
        $search_result = "search_result";
        $errno = 34;
        $error_msg = "invalidDNSyntax";

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_read')
                    ->with($ldap_connection, $ldap_base, $ldap_filter, explode(",", $attribute))
                    ->andReturn($search_result);

        $phpLDAPMock->shouldreceive('ldap_errno')
                    ->with($ldap_connection)
                    ->andReturn($errno);

        $phpLDAPMock->shouldreceive('ldap_error')
                    ->with($ldap_connection)
                    ->andReturn($error_msg);

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = $ldap_connection;
        $value = $ldapInstance->get_first_value($ldap_base, $ldap_scope, $ldap_filter, $attribute);

        $this->assertEquals("", $value, 'Weird value returned by get_first_value method called with an invalid DN');

    }

    public function test_matchDn(): void
    {

        $phpLDAPMock = Mockery::mock('overload:Ltb\PhpLDAP');

        $phpLDAPMock->shouldreceive('ldap_search')
                    ->with("ldap_connection", "ou=people,dc=my-domain,dc=com", "(&(objectClass=inetOrgPerson)(entryDn=uid=test,ou=people,dc=my-domain,dc=com))", [1.1])
                    ->andReturn(array("ldap_search_result"));

        $phpLDAPMock->shouldreceive('ldap_count_entries')
                    ->with("ldap_connection", array("ldap_search_result"))
                    ->andReturn(1);

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = "ldap_connection";

        $result_match = $ldapInstance->matchDn("uid=test,ou=people,dc=my-domain,dc=com", "entryDn", "(objectClass=inetOrgPerson)", "ou=people,dc=my-domain,dc=com", "sub");

        $this->assertTrue($result_match, "DN match");

    }

    public function setUp(): void
    {
        // Turn on error reporting
        //error_reporting(E_ALL);
    }

    public function test_sortEntryAscending()
    {
        $entry = [
            'foo' => ['count' => 3, 2, 1, 3],
        ];
        $attributes_map = [
            ['attribute' => 'foo', 'sort' => 'ascending'],
        ];

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = "ldap_connection";

        $sorted = $ldapInstance->sortEntry($entry, $attributes_map);
        $this->assertEquals([1,2,3], array_values($sorted['foo']));
    }

    public function test_sortEntryDescending()
    {
        $entry = [
            'foo' => ['count' => 3, 2, 1, 3],
        ];
        $attributes_map = [
            ['attribute' => 'foo', 'sort' => 'descending'],
        ];

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = "ldap_connection";

        $sorted = $ldapInstance->sortEntry($entry, $attributes_map);
        $this->assertEquals([3,2,1], array_values($sorted['foo']));
    }

    public function test_sortEntryNoSortParam()
    {
        $entry = [
            'foo' => ['count' => 3, 2, 1, 3],
        ];
        $attributes_map = [
            ['attribute' => 'foo'],
        ];

        $ldapInstance = new \Ltb\Ldap( null, null, null, null, null, null, null, null );
        $ldapInstance->ldap = "ldap_connection";

        $sorted = $ldapInstance->sortEntry($entry, $attributes_map);
        $this->assertEquals([1,2,3], array_values($sorted['foo']));
    }

}
