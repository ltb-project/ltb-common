<?php

namespace Ltb;

# require __DIR__ . '/../../vendor/autoload.php';


require __DIR__ . '/../../src/Ltb/Ldap.php';

Ldap::connect('ldap://127.0.0.1',false,'cn=admin','binpwd',10);
