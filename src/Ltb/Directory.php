<?php

namespace Ltb;
use \DateTime;

interface Directory
{
    /*
     * Is account locked?
     */
    public function isLocked($ldap, $dn, $config) : bool;

    /*
     * Date when account has been locked
     */
    public function getLockDate($ldap, $dn) : ?DateTime;

    /*
     * Date when account will be automatically unlocked
     */
    public function getUnlockDate($ldap, $dn, $config) : ?DateTime;

    /*
     * Lock account
     */
    public function lockAccount($ldap, $dn) : bool;

    /*
     * Unlock account
     */
    public function unlockAccount($ldap, $dn) : bool;

    /*
     * Is password expired?
     */
    public function isPasswordExpired($ldap, $dn, $config) : bool;

    /*
     * Date when password will be expired
     */
    public function getPasswordExpirationDate($ldap, $dn, $config) : ?DateTime;

    /*
     * Modify the password
     */
    public function modifyPassword($ldap, $dn, $password, $forceReset) : bool;

    /*
     * Should user reset password at next connection?
     */
    public function resetAtNextConnection($ldap, $dn) : bool;

    /*
     * Enable account
     */
    public function enableAccount($ldap, $dn) : bool;

    /*
     * Disable account
     */
    public function disableAccount($ldap, $dn) : bool;

    /*
     * Is account enabled?
     */
    public function isAccountEnabled($ldap, $dn) : bool;

    /*
     * Get LDAP date from PHP date
     */
    public function getLdapDate($date) : string;

    /*
     * Get password policy configuration
     */
    public function getPwdPolicyConfiguration($ldap, $entry_dn, $default_ppolicy_dn) : Array;
}
