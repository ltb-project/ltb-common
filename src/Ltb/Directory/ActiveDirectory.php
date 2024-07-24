<?php

namespace Ltb\Directory;
use \DateTime;

class ActiveDirectory implements \Ltb\Directory
{
    public function isLocked($ldap, $dn, $config) : bool {

        # Get entry
        $search = \Ltb\PhpLDAP::ldap_read($ldap, $dn, "(objectClass=*)", array('lockouttime'));
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return false;
        } else {
            $entry = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search);

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
        $search = \Ltb\PhpLDAP::ldap_read($ldap, $dn, "(objectClass=*)", array('lockouttime'));
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return $unlockDate;
        } else {
            $entry = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search);
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

    public function isPasswordExpired($ldap, $dn, $config) : bool {

        # Get entry
        $search = \Ltb\PhpLDAP::ldap_read($ldap, $dn, "(objectClass=*)", array('pwdlastset'));
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return false;
        } else {
            $entry = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search);

        }

        # Get pwdLastSet
        $pwdLastSet = $entry[0]['pwdlastset'][0];

        if (!$pwdLastSet) {
            return false;
        }

        # Get password expiration date
        $expirationDate = $this->getPasswordExpirationDate($ldap, $dn, $config);

        if (!$expirationDate) {
            return false;
        }

        if ($expirationDate and time() >= $expirationDate->getTimestamp()) {
            return true;
        }

        return false;
    }

    public function getPasswordExpirationDate($ldap, $dn, $config) : ?DateTime {

        $expirationDate = NULL;

        # Get entry
        $search = \Ltb\PhpLDAP::ldap_read($ldap, $dn, "(objectClass=*)", array('pwdlastset'));
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return $expirationDate;
        } else {
            $entry = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search);
        }

        # Get pwdLastSet
        $pwdLastSet = $entry[0]['pwdlastset'][0];

        if ( !$pwdLastSet or $pwdLastSet == 0) {
            return $expirationDate;
        }

        # Get pwdMaxAge
        $pwdMaxAge = $config["pwdMaxAge"];

        # Compute expiration date
        if ($pwdMaxAge) {
            $adExpirationDate = $pwdLastSet + ($pwdMaxAge * 10000000);
            $expirationDate = \Ltb\Date::adDate2phpDate($adExpirationDate);
        }

        return $expirationDate;
    }

    public function getPasswordMaxAge($ldap, $dn, $config) : ?int {
        return $config['pwdMaxAge'];
    }

}
