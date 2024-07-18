<?php

namespace Ltb\Directory;

class OpenLDAP implements \Ltb\Directory
{
    public function isLocked($entry, $ppolicy) {

        $ppolicy_entry = $policy;
        $isLocked = false;

        $pwdLockout = strtolower($ppolicy_entry[0]['pwdlockout'][0]) == "true" ? true : false;
        $pwdLockoutDuration = $ppolicy_entry[0]['pwdlockoutduration'][0];
        $pwdAccountLockedTime = $entry[0]['pwdaccountlockedtime'][0];

        if ( $pwdAccountLockedTime === "000001010000Z" ) {
            $isLocked = true;
        } else if (isset($pwdAccountLockedTime)) {
            if (isset($pwdLockoutDuration) and ($pwdLockoutDuration > 0)) {
                // $lockDate = ldapDate2phpDate($pwdAccountLockedTime);
                $lockdate = time() // TODO add Date functions in LTB-LDAP
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
