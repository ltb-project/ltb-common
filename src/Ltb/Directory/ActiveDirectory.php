<?php

namespace Ltb\Directory;
use \DateTime;
use \DateInterval;

class ActiveDirectory implements \Ltb\Directory
{

    private $operationalAttributes = array(
                                           'lockouttime',
                                           'useraccountcontrol',
                                           'pwdlastset',
                                           'accountExpires'
                                          );

    public function getOperationalAttributes() : array {
        return $this->operationalAttributes;
    }

    public function isLocked($entry, $pwdPolicyConfiguration) : bool {

        # Get lockoutTime
        $lockoutTime = $entry['lockouttime'][0] ?? 0;

        # Get unlock date
        $unlockDate = $this->getUnlockDate($entry, $pwdPolicyConfiguration);

        if ($lockoutTime > 0 and !$unlockDate) {
            return true;
        }

        if ($unlockDate and time() <= $unlockDate->getTimestamp()) {
            return true;
        }

        return false;
    }

    public function getLockDate($entry, $pwdPolicyConfiguration) : ?DateTime {

        $lockDate = NULL;

        # Get lockoutTime
        $lockoutTime = $entry['lockouttime'][0] ?? 0;

        if ( !$lockoutTime or $lockoutTime === 0) {
            return $lockDate;
        }

        $lockDate = \Ltb\Date::adDate2phpDate($lockoutTime);
        return $lockDate;
    }

    public function getUnlockDate($entry, $pwdPolicyConfiguration) : ?DateTime {

        $unlockDate = NULL;

        # Get lock date
        $lockDate = $this->getLockDate($entry, $pwdPolicyConfiguration);

        if ( !$lockDate ) {
            return $unlockDate;
        }

        # Get lockout duration
        $lockoutDuration = $pwdPolicyConfiguration["lockout_duration"];

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

    public function isPasswordExpired($entry, $pwdPolicyConfiguration) : bool {

        # Get pwdLastSet
        $pwdLastSet = $entry['pwdlastset'][0] ?? null;

        if (!$pwdLastSet) {
            return false;
        }

        # Get password expiration date
        $expirationDate = $this->getPasswordExpirationDate($entry, $pwdPolicyConfiguration);

        if (!$expirationDate) {
            return false;
        }

        if ($expirationDate and time() >= $expirationDate->getTimestamp()) {
            return true;
        }

        return false;
    }

    public function getPasswordExpirationDate($entry, $pwdPolicyConfiguration) : ?DateTime {

        $expirationDate = NULL;

        # Get pwdLastSet
        $pwdLastSet = $entry['pwdlastset'][0] ?? null;

        if ( !$pwdLastSet or $pwdLastSet === 0) {
            return $expirationDate;
        }

        # Get pwdMaxAge
        $pwdMaxAge = $pwdPolicyConfiguration["password_max_age"];

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
        if ( isset($pwdlastset) and intval($pwdlastset) === 0) {
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

    public function isAccountEnabled($entry) : bool {

        if ($entry['useraccountcontrol'] and ( $entry['useraccountcontrol'][0] & 2)) {
            return false;
        } else {
            return true;
        }
    }

    public function getLdapDate($date) : string {
        return \Ltb\Date::timestamp2adDate( $date->getTimestamp() );
    }

    public function getPhpDate($date) : ?DateTime {
        return \Ltb\Date::adDate2phpDate( $date );
    }

    # Function that parses all entries and returns ppolicies and user's ppolicies
    public function getPwdPolicies($ldap, $entries, $default_ppolicy_dn) : array {

        $passwordPolicies = array(); # list of unique password policies
        $userPolicies = array();     # associative array: user => associated ppolicy

        # Get default password policy from LDAP
        $defaultPasswordPolicy = $this->getPwdPolicyConfiguration($ldap, null, $default_ppolicy_dn);
        # Add the password policy to the list of unique ppolicies
        array_push($passwordPolicies, $defaultPasswordPolicy);

        # parse entries
        foreach($entries as $entry_key => $entry)
        {
            $userPolicies[$entry['dn']] = &$passwordPolicies[0];
        }
        # return the list of unique password policies + the mapping user => password policy
        return array( $passwordPolicies, $userPolicies);
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

    public function isAccountValid($entry, $pwdPolicyConfiguration) : bool {

        $time = time();
        $startdate = $this->getStartDate($entry, $pwdPolicyConfiguration);
        $enddate = $this->getEndDate($entry, $pwdPolicyConfiguration);

        if ( isset($startdate) ) {
            if ( $time <= $startdate->getTimestamp() ) {
                return false;
            }
        }

        if ( isset($enddate) ) {
            if ( $time >= $enddate->getTimestamp() ) {
                return false;
            }
        }

        return true;
    }

    public function getStartDate($entry, $pwdPolicyConfiguration) : ?DateTime {

        // No start date in AD
        return null;
    }

    public function getEndDate($entry, $pwdPolicyConfiguration) : ?DateTime {

        if (!isset($entry['accountexpires']) or ($entry['accountexpires'][0] == 0) or ($entry['accountexpires'][0] == 9223372036854775807)) {
            return null;
        }

        $enddate = \Ltb\Date::adDate2phpDate($entry['accountexpires'][0]);
        return $enddate ? $enddate : null;
    }

    public function computePassword($ldapInstance, $dn, $password, $hash, $hash_options, $use_exop_passwd) : string {

        $password = \Ltb\Password::make_ad_password($password);

        return $password;
    }

    public function changePasswordData($ldapInstance, $dn, $userdata, $password, $oldpassword, $who_change_password, $use_exop_passwd, $use_ppolicy_control, $custom_pwd_field_mode, $custom_pwd_attribute, $ad_options) : array {

        list($error_code, $error_msg, $ppolicy_error_code) = array(null, null, null);

        $userdata = \Ltb\Password::set_ad_data($userdata, $ad_options, $password);

        # Special case: AD mode with password changed as user
        if ( $ad_mode and $who_change_password === "user" ) {
            list($error_code, $error_msg) = $ldapInstance->change_ad_password_as_user($dn, $oldpassword, $password);
        } elseif ($use_exop_passwd) {
            list($error_code, $error_msg, $ppolicy_error_code) = $ldapInstance->change_password_with_exop($dn, $oldpassword, $password, $use_ppolicy_control);
            if( $error_code == 0 )
            {
                list($error_code, $error_msg) = $ldapInstance->modify_attributes($dn, $userdata);
            }
        } else {
            # Else just replace with new password
            if ( $use_ppolicy_control ) {
                list($error_code, $error_msg, $ppolicy_error_code) = $ldapInstance->modify_attributes_using_ppolicy($dn, $userdata);
            } else {
                list($error_code, $error_msg) = $ldapInstance->modify_attributes($dn, $userdata);
            }
        }

        return array( $error_code, $error_msg, $ppolicy_error_code );
    }

}
