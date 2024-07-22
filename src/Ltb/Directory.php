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
     * Date when account will be automatically unlocked
     */
    public function getUnlockDate($ldap, $dn, $config) : ?DateTime;

    /*
     * Lock duration (in seconds)
     */
    public function getLockoutDuration($ldap, $dn, $config) : ?int;

    /*
     * Can account be locked?
     */
    public function canLockAccount($ldap, $dn, $config) : bool;
}
