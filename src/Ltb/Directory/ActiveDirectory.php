<?php

namespace Ltb\Directory;

class ActiveDirectory implements \Ltb\Directory
{
    public function isLocked($ldap, $dn, $config) {

        $isLocked = false;

        # Get entry
        $search = ldap_read($ldap, $dn, "(objectClass=*)", array('useraccountcontrol'));
        $errno = ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return $isLocked;
        } else {
            $entry = ldap_get_entries($ldap, $search);
        }

        # Check userAccountControl
        $userAccountControl = $entry[0]['useraccountcontrol'][0];

        if ($userAccountControl & 2) { $isLocked = true; }

        return $isLocked;
    }
}
