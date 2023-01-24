<?php

namespace Ltb;

require __DIR__ . '/../../vendor/autoload.php';

# if autoload fails :
# require __DIR__ . '/../../src/Ltb/AttributeValue.php';

# $ldap_connection = Ldap::connect('ldap://127.0.0.1',false,'cn=admin','binpwd',10);
# \LDAP\Connection::....
$ldap_connection = array( false , false);
$ldap=$ldap_connection[0];
$result = $ldap_connection[1];

$entry = false;
$attributes = false;
try {
    AttributeValue::ldap_get_first_available_value($ldap, $entry, $attributes);
} catch (\Exception $e) {
    echo 'Got Exception : ',  $e->getMessage(), "\n";
}catch (\TypeError $e) {
    # expected  Got Exception : ldap_get_attributes(): Argument #1 ($ldap) must be of type LDAP\Connection, bool given
    echo 'Got Exception : ',  $e->getMessage(), "\n";
}

$mail_attributes = false;

try {
    AttributeValue::ldap_get_mail_for_notification($ldap, $entry);
} catch (\TypeError $e) {
    # expected  Got Exception : ldap_get_attributes(): Argument #1 ($ldap) must be of type LDAP\Connection, bool given
    echo 'Got Exception : ',  $e->getMessage(), "\n";
}


