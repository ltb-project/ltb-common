<?php

namespace Ltb;

interface Directory
{
    public function isLocked($ldap, $dn, $config);
}
