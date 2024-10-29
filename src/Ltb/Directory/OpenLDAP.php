<?php

namespace Ltb\Directory;
use \DateTime;
use \DateInterval;

class OpenLDAP implements \Ltb\Directory
{
    public function isLocked($ldap, $dn, $config) : bool {

        # Get entry
        $search = \Ltb\PhpLDAP::ldap_read($ldap, $dn, "(objectClass=*)", array('pwdaccountlockedtime'));
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return false;
        } else {
            $entry = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search);
        }

        # Get pwdAccountLockedTime
        $pwdAccountLockedTime = $entry[0]['pwdaccountlockedtime'][0] ?? null;

        if (!$pwdAccountLockedTime) {
            return false;
        }

        if ( $pwdAccountLockedTime === "000001010000Z" ) {
            return true;
        }

        $unlockDate = $this->getUnlockDate($ldap, $dn, $config);

        if ( $unlockDate and time() <= $unlockDate->getTimestamp() ) {
            return true;
        }

        return false;
    }

    public function getLockDate($ldap, $dn) : ?DateTime {

        $lockDate = NULL;

        # Get entry
        $search = \Ltb\PhpLDAP::ldap_read($ldap, $dn, "(objectClass=*)", array('pwdaccountlockedtime'));
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return $lockDate;
        } else {
            $entry = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search);
        }

        # Get pwdAccountLockedTime
        $pwdAccountLockedTime = $entry[0]['pwdaccountlockedtime'][0] ?? null;

        if (!$pwdAccountLockedTime or $pwdAccountLockedTime === "000001010000Z") {
            return $lockDate;
        }

        $lockDate = \Ltb\Date::ldapDate2phpDate($pwdAccountLockedTime);
        return $lockDate;
    }

    public function getUnlockDate($ldap, $dn, $config) : ?DateTime {

        $unlockDate = NULL;

        # Get lock date
        $lockDate = $this->getLockDate($ldap, $dn);

        if (!$lockDate) {
            return $unlockDate;
        }

        # Get lockout duration
        $lockoutDuration = $config["lockout_duration"];

        if (isset($lockoutDuration) and ($lockoutDuration > 0)) {
            $unlockDate = date_add( $lockDate, new DateInterval('PT'.$lockoutDuration.'S'));
        }

        return $unlockDate;
    }

    public function lockAccount($ldap, $dn) : bool {

        $modification = \Ltb\PhpLdap::ldap_mod_replace($ldap, $dn, array("pwdAccountLockedTime" => array("000001010000Z")));
        $errno = ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Lock account error $errno  (".ldap_error($ldap).")");
            return false;
        } else {
            return true;
        }
    }

    public function unlockAccount($ldap, $dn) : bool {

        $modification = \Ltb\PhpLdap::ldap_mod_replace($ldap, $dn, array("pwdAccountLockedTime" => array()));
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
        $search = \Ltb\PhpLDAP::ldap_read($ldap, $dn, "(objectClass=*)", array('pwdchangedtime'));
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return false;
        } else {
            $entry = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search);

        }

        # Get pwdChangedTime
        $pwdChangedTime = $entry[0]['pwdchangedtime'][0] ?? null;

        if (!$pwdChangedTime) {
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
        $search = \Ltb\PhpLDAP::ldap_read($ldap, $dn, "(objectClass=*)", array('pwdchangedtime'));
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return $expirationDate;
        } else {
            $entry = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search);
        }

        # Get pwdChangedTime
        $pwdChangedTime = $entry[0]['pwdchangedtime'][0] ?? null;

        if (!$pwdChangedTime) {
            return $expirationDate;
        }

        # Get pwdMaxAge
        $pwdMaxAge = $config["password_max_age"];

        # Compute expiration date
        if ($pwdMaxAge) {
            $changedDate = \Ltb\Date::ldapDate2phpDate($pwdChangedTime);
            $expirationDate = date_add( $changedDate, new DateInterval('PT'.$pwdMaxAge.'S'));
        }

        return $expirationDate;
    }

    public function modifyPassword($ldap, $dn, $password, $forceReset) : bool {

        $changes = array('userPassword' => $password);

        if ($forceReset) {
            $changes['pwdReset'] = 'TRUE';
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
        $search = \Ltb\PhpLDAP::ldap_read($ldap, $dn, "(objectClass=*)", array('pwdreset'));
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return false;
        } else {
            $entry = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search);
        }

        $pwdreset = $entry[0]['pwdreset'][0] ?? null;
        if( isset($pwdreset) and $pwdreset === "TRUE" ) {
            return true;
        } else {
            return false;
        }
    }

    public function enableAccount($ldap, $dn) : bool {

        $attrsToDelete = array( 'pwdAccountDisabled' => array() );

        $update = \Ltb\PhpLDAP::ldap_mod_replace($ldap, $dn, $attrsToDelete);
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ($errno) {
            error_log("LDAP - Enabling account error $errno  (".\Ltb\PhpLDAP::ldap_error($ldap).")");
            return false;
        } else {
            return true;
        }
    }

    public function disableAccount($ldap, $dn) : bool {

        # Date of disabling
        $currentDate = gmdate("YmdHis")."Z";

        $attrs = array( 'pwdAccountDisabled' => array($currentDate) );

        $update = \Ltb\PhpLDAP::ldap_mod_replace($ldap, $dn, $attrs);
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ($errno) {
            error_log("LDAP - Disabling account error $errno  (".\Ltb\PhpLDAP::ldap_error($ldap).")");
            return false;
        } else {
            return true;
        }
    }

    public function isAccountEnabled($ldap, $dn) : bool {

        # Get entry
        $search = \Ltb\PhpLDAP::ldap_read($ldap, $dn, "(objectClass=*)", array('pwdAccountDisabled'));
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".\Ltb\PhpLDAP::ldap_error($ldap).")");
            return false;
        } else {
            $entry = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search);
        }

        if (empty($entry[0]['pwdaccountdisabled'][0])) {
            return true;
        } else {
            return false;
        }

    }

    public function getLdapDate($date) : string {
        return \Ltb\Date::string2ldapDate( $date->format('d/m/Y') );
    }

    public function getPwdPolicyConfiguration($ldap, $entry_dn, $default_ppolicy_dn) : Array {

        $ppolicyConfig = array();

        # Check pwdPolicySubEntry
        $search_user = \Ltb\PhpLDAP::ldap_read($ldap, $entry_dn, "(objectClass=*)", array('pwdpolicysubentry'));
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return $ppolicyConfig;
        } else {
            $user_entry = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search_user);
        }

        $ppolicy_dn = $user_entry[0]['pwdpolicysubentry'] ? $user_entry[0]['pwdpolicysubentry'][0] : $default_ppolicy_dn;

        # Get values from ppolicy
        $search = \Ltb\PhpLDAP::ldap_read($ldap, $ppolicy_dn, "(objectClass=pwdPolicy)", array('pwdLockoutDuration', 'pwdMaxAge', 'pwdLockout'));
        $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

        if ( $errno ) {
            error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
            return $ppolicyConfig;
        } else {
            $entry = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search);
        }

        $ppolicyConfig["dn"] = $entry[0]["dn"];
        $ppolicyConfig["lockout_duration"] = $entry[0]["pwdlockoutduration"][0] ?? 0;
        $ppolicyConfig["password_max_age"] = $entry[0]["pwdmaxage"][0] ?? 0;
        $pwdlockout = $entry[0]['pwdlockout'][0] ?? false;
        $ppolicyConfig["lockout_enabled"] = strtolower($pwdlockout) == "true" ? true : false;

        return $ppolicyConfig;
    }

    public function getDnAttribute() : string {
        return "entryDn";
    }
}
