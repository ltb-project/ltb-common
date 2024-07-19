<?php

namespace Ltb\Directory;

class OpenLDAP implements \Ltb\Directory
{
    public function isLocked($ldap, $dn, $config) {

        $isLocked = false;

        # Get entry
        $search = ldap_read($ldap, $dn, "(objectClass=*)", array('pwdaccountlockedtime'));
        $errno = ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return $isLocked;
        } else {
            $entry = ldap_get_entries($ldap, $search);
        }

        # Get ppolicy entry
        # Get entry
        $ppolicy_search = ldap_read($ldap, $config['pwdPolicy'], "(objectClass=*)", array('pwdlockout', 'pwdlockoutduration'));
        $errno = ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return $isLocked;
        } else {
            $ppolicy_entry = ldap_get_entries($ldap, $ppolicy_search);
        }

        $pwdLockout = strtolower($ppolicy_entry[0]['pwdlockout'][0]) == "true" ? true : false;
        $pwdLockoutDuration = $ppolicy_entry[0]['pwdlockoutduration'][0];
        $pwdAccountLockedTime = $entry[0]['pwdaccountlockedtime'][0];

        if ( $pwdAccountLockedTime === "000001010000Z" ) {
            $isLocked = true;
        } else if (isset($pwdAccountLockedTime)) {
            if (isset($pwdLockoutDuration) and ($pwdLockoutDuration > 0)) {
                $lockDate = \Ltb\Date::ldapDate2phpDate($pwdAccountLockedTime);
                $unlockDate = date_add( $lockDate, new DateInterval('PT'.$pwdLockoutDuration.'S'));
                if ( time() <= $unlockDate->getTimestamp() ) {
                    $isLocked = true;
                }
            } else {
                $isLocked = true;
            }
        }

        return $isLocked;
    }
}
