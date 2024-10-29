<?php

namespace Ltb\Directory;
use \DateTime;
use \DateInterval;

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
        $lockoutTime = $entry[0]['lockouttime'][0] ?? 0;

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

    public function getLockDate($ldap, $dn) : ?DateTime {

        $lockDate = NULL;

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
        $lockoutTime = $entry[0]['lockouttime'][0] ?? 0;

        if ( !$lockoutTime or $lockoutTime === 0) {
            return $lockDate;
        }

        $lockDate = \Ltb\Date::adDate2phpDate($lockoutTime);
        return $lockDate;
    }

    public function getUnlockDate($ldap, $dn, $config) : ?DateTime {

        $unlockDate = NULL;

        # Get lock date
        $lockDate = $this->getLockDate($ldap, $dn);

        if ( !$lockDate ) {
            return $unlockDate;
        }

        # Get lockout duration
        $lockoutDuration = $config["lockout_duration"];

        # Compute unlock date
        if (isset($lockoutDuration) and ($lockoutDuration > 0)) {
            $unlockDate = date_add( $lockDate, new DateInterval('PT'.$lockoutDuration.'S'));
        }

        return $unlockDate;
    }

    public function lockAccount($ldap, $dn) : bool {

        // Not supported by AD
        return false;
    }

    public function unlockAccount($ldap, $dn) : bool {

        $modification = \Ltb\PhpLdap::ldap_mod_replace($ldap, $dn, array("lockoutTime" => array("0")));
        $errno = ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Unlock account error $errno  (".ldap_error($ldap).")");
            return false;
        } else {
            return true;
        }
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
        $pwdLastSet = $entry[0]['pwdlastset'][0] ?? null;

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
        $pwdLastSet = $entry[0]['pwdlastset'][0] ?? null;

        if ( !$pwdLastSet or $pwdLastSet === 0) {
            return $expirationDate;
        }

        # Get pwdMaxAge
        $pwdMaxAge = $config["password_max_age"];

        # Compute expiration date
        if ($pwdMaxAge) {
            $adExpirationDate = $pwdLastSet + ($pwdMaxAge * 10000000);
            $expirationDate = \Ltb\Date::adDate2phpDate($adExpirationDate);
        }

        return $expirationDate;
    }

    public function modifyPassword($ldap, $dn, $password, $forceReset) : bool {

        $adPassword = \Ltb\Password::make_ad_password($password);
        $changes = array('unicodePwd' => $adPassword);

        if ($forceReset) {
            $changes['pwdLastSet'] = 0;
        }

        $update = \Ltb\PhpLDAP::ldap_mod_replace($ldap, $dn, $changes);
        $errno = ldap_errno($ldap);

        if ($errno) {
            error_log("LDAP - Modify password error $errno  (".ldap_error($ldap).")");
            return false;
        } else {
            return true;
        }
    }

    public function resetAtNextConnection($ldap, $dn) : bool {

        # Get entry
        $search = \Ltb\PhpLDAP::ldap_read($ldap, $dn, "(objectClass=*)", array('pwdlastset'));
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return false;
        } else {
            $entry = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search);
        }

        $pwdlastset = $entry[0]['pwdlastset'][0] ?? null;
        if ( isset($pwdlastset) and $pwdlastset === 0) {
            return true;
        } else {
            return false;
        }
    }

    public function enableAccount($ldap, $dn) : bool {

        # Get entry
        $search = \Ltb\PhpLDAP::ldap_read($ldap, $dn, "(objectClass=*)", array('userAccountControl'));
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return false;
        } else {
            $entry = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search);
        }

        if ($entry[0]['useraccountcontrol'] and ( $entry[0]['useraccountcontrol'][0] & 2)) {
            $newUAC = $entry[0]['useraccountcontrol'][0] & ~2;
            $update = \Ltb\PhpLDAP::ldap_mod_replace($ldap, $dn, array( "userAccountControl" => $newUAC));
            $errno = ldap_errno($ldap);

            if ($errno) {
                error_log("LDAP - Modify userAccountControl error $errno  (".ldap_error($ldap).")");
                return false;
            } else {
              return true;
            }
        } else {
            return true;
        }
    }

    public function disableAccount($ldap, $dn) : bool {

        # Get entry
        $search = \Ltb\PhpLDAP::ldap_read($ldap, $dn, "(objectClass=*)", array('userAccountControl'));
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return false;
        } else {
            $entry = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search);
        }

        if ($entry[0]['useraccountcontrol'] and ( $entry[0]['useraccountcontrol'][0] ^ 2)) {
            $newUAC = $entry[0]['useraccountcontrol'][0] | 2;
            $update = \Ltb\PhpLDAP::ldap_mod_replace($ldap, $dn, array( "userAccountControl" => $newUAC));
            $errno = ldap_errno($ldap);

            if ($errno) {
                error_log("LDAP - Modify userAccountControl error $errno  (".ldap_error($ldap).")");
                return false;
            } else {
              return true;
            }
        } else {
            return true;
        }

    }

    public function isAccountEnabled($ldap, $dn) : bool {

        # Get entry
        $search = \Ltb\PhpLDAP::ldap_read($ldap, $dn, "(objectClass=*)", array('userAccountControl'));
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return false;
        } else {
            $entry = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search);
        }

        if ($entry[0]['useraccountcontrol'] and ( $entry[0]['useraccountcontrol'][0] & 2)) {
            return false;
        } else {
            return true;
        }
    }

    public function getLdapDate($date) : string {
        return \Ltb\Date::timestamp2adDate( $date->getTimeStamp() );
    }

    public function getPwdPolicyConfiguration($ldap, $entry_dn, $default_ppolicy_dn) : Array {

        $ppolicyConfig = array();

        # Get values from default ppolicy
        $search = \Ltb\PhpLDAP::ldap_read($ldap, $default_ppolicy_dn, "(objectClass=*)", array('lockoutDuration', 'maxPwdAge'));
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return $ppolicyConfig;
        } else {
            $entry = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search);
        }

        $ppolicyConfig["dn"] = $entry[0]["dn"];
        $lockoutduration = $entry[0]["lockoutduration"][0] ?? 0;
        $ppolicyConfig["lockout_duration"] = $lockoutduration / -10000000 ;
        $password_max_age = $entry[0]["maxpwdage"][0] ?? 0;
        $ppolicyConfig["password_max_age"] = $password_max_age / -10000000;
        $ppolicyConfig["lockout_enabled"] = false;

        return $ppolicyConfig;
    }

    public function getDnAttribute() : string {
        return "distinguishedName";
    }
}
