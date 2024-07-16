<?php

namespace Ltb\Directory;

class ActiveDirectory implements Directory
{
    public function isLocked($entry, $ppolicy) {

        $isLocked = false;

        $userAccountControl = $entry[0]['useraccountcontrol'][0];

        if ($userAccountControl & 2) { $isLocked = true; }

        return $isLocked;
    }
}
