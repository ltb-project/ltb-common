<?php

namespace Ltb;

interface Directory
{
    public function isLocked($entry, $ppolicy);
}
