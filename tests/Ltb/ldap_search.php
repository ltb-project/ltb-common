<?php

namespace Ltb;

# require __DIR__ . '/../../vendor/autoload.php';

require __DIR__ . '/../../src/Ltb/Ldap.php';

$searched_control=LDAP_CONTROL_SORTREQUEST;

$supportedcontrols_array=[
    "1.2.840.113556.1.4.1413",
    "1.3.6.1.1.22",
    "1.2.840.113556.1.4.1339",
    "1.2.840.113556.1.4.319",
    "1.2.826.0.1.3344810.2.3",
    "1.3.6.1.1.13.2",
    "1.2.840.113556.1.4.473"
];
    
var_dump($searched_control, $supportedcontrols_array);

if (! in_array($searched_control, $supportedcontrols_array,false)) {
    print('in_array error');
    exit(1);
}



$array = [
    'count' => 6,
    [ "count" => 0, "dn" => "ou=People,dc=company,dc=example"],
    [ "count" => 1, "uid" => ["count"=>1, 0 => "jho"], 0 => "uid", "dn" => "uid=jho,ou=People,dc=company,dc=example" ],
    [ "count" => 1, "uid" => ["count"=>1, 0 => "bfranck"], 0 => "uid", "dn" => "uid=bfrank,ou=People,dc=company,dc=example" ],
    [ "count" => 1, "uid" => ["count"=>1, 0 => "nkeith"], 0 =>"uid","dn" => "uid=nkeith,ou=People,dc=company,dc=example" ],
    [ "count" => 1, "uid" => ["count"=>1, 0 => "amorton"], 0 =>"uid","dn" => "uid=amorton,ou=People,dc=company,dc=example" ],
    [ "count" => 1, "uid" => ["count"=>1, 0 => "irangel"], 0 =>"uid","dn" => "uid=irangel,ou=People,dc=company,dc=example" ]
];


var_dump($array);

Ldap::ldapSort($array,'uid');

# dump ...
var_dump($array);

