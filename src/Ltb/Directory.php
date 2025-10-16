<?php

namespace Ltb;
use \DateTime;

interface Directory
{

    /*
     * Get specific operational attributes
     */
    public function getOperationalAttributes() : array;

    /*
     * Is account locked?
     */
    public function isLocked($entry, $pwdPolicyConfiguration) : bool;

    /*
     * Date when account has been locked
     */
    public function getLockDate($entry, $pwdPolicyConfiguration) : ?DateTime;

    /*
     * Date when account will be automatically unlocked
     */
    public function getUnlockDate($entry, $pwdPolicyConfiguration) : ?DateTime;

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
    public function isPasswordExpired($entry, $pwdPolicyConfiguration) : bool;

    /*
     * Date when password will be expired
     */
    public function getPasswordExpirationDate($entry, $pwdPolicyConfiguration) : ?DateTime;

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
    public function isAccountEnabled($entry) : bool;

    /*
     * Get LDAP date from PHP date
     */
    public function getLdapDate($date) : string;

    /*
     * Get PHP date from LDAP date
     */
    public function getPhpDate($date) : ?DateTime;

    /*
     * Parses all entries and returns an array of all password policies
     */
    public function getPwdPolicies($ldap, $entries, $default_ppolicy_dn) : array;

    /*
     * Get password policy configuration
     */
    public function getPwdPolicyConfiguration($ldap, $entry_dn, $default_ppolicy_dn) : Array;

    /*
     * Return special attribute name containing entry DN
     */
    public function getDnAttribute() : string;

    /*
     * Is account valid? Relies on start and end validity dates
     */
    public function isAccountValid($entry, $pwdPolicyConfiguration) : bool;

    /*
     * Get validity start date
     */
    public function getStartDate($entry, $pwdPolicyConfiguration) : ?DateTime;

    /*
     * Get validity end date
     */
    public function getEndDate($entry, $pwdPolicyConfiguration) : ?DateTime;
}
