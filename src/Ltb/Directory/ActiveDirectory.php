<?php

namespace Ltb\Directory;
use \DateTime;

class ActiveDirectory implements \Ltb\Directory
{
    public function isLocked($ldap, $dn, $config) : bool {

        # Get entry
        $search = ldap_read($ldap, $dn, "(objectClass=*)", array('lockouttime'));
        $errno = ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return false;
        } else {
            $entry = ldap_get_entries($ldap, $search);

        }

        # Get lockoutTime
        $lockoutTime = $entry[0]['lockouttime'][0];

        # Get unlock date
        $unlockDate = $this->getUnlockDate($ldap, $dn, $config);

        if ($lockoutTime > 0 and !$unlockDate) {
            return true;
        }

        if ($unlockDate and time() <= $unlockDate->getTimestamp()) {
            return true;
        }

        return false;
    }

    public function getUnlockDate($ldap, $dn, $config) : ?DateTime {

        $unlockDate = NULL;

        # Get entry
        $search = ldap_read($ldap, $dn, "(objectClass=*)", array('lockouttime'));
        $errno = ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return $unlockDate;
        } else {
            $entry = ldap_get_entries($ldap, $search);
        }

        # Get lockoutTime
        $lockoutTime = $entry[0]['lockouttime'][0];

        if ( !$lockoutTime or $lockoutTime == 0) {
            return $unlockDate;
        }

        # Get lockoutDuration
        $lockoutDuration = $config["lockoutDuration"];

        # Compute unlock date
        if ($lockoutDuration) {
            $adUnlockDate = $lockoutTime + ($lockoutDuration * 10000000);
            $unlockDate = \Ltb\Date::adDate2phpDate($adUnlockDate);
        }

        return $unlockDate;
    }

    public function getLockoutDuration($ldap, $dn, $config) : ?int {
        return $config['lockoutDuration'];
    }

    public function canLockAccount($ldap, $dn, $config) : bool {
        return true;
    }
}
