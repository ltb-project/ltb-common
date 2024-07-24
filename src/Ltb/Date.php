<?php namespace Ltb;
use \DateTime;
use \DateTimeZone;

/**
 * Date functions
 */
final class Date {

    static function ldapDate2phpDate($string) {
        //  This code is part of FusionDirectory (http://www.fusiondirectory.org/)
        //  Copyright (C) 2016  FusionDirectory

        // century = 2(%x30-39) ; "00" to "99"
        // year    = 2(%x30-39) ; "00" to "99"
        $year = '(?P<year>\d{4})';
        // month   =   ( %x30 %x31-39 ) ; "01" (January) to "09"
        //           / ( %x31 %x30-32 ) ; "10" to "12"
        $month = '(?P<month>0[1-9]|1[0-2])';
        // day     =   ( %x30 %x31-39 )    ; "01" to "09"
        //           / ( %x31-32 %x30-39 ) ; "10" to "29"
        //           / ( %x33 %x30-31 )    ; "30" to "31"
        $day = '(?P<day>0[1-9]|[0-2]\d|3[01])';
        // hour    = ( %x30-31 %x30-39 ) / ( %x32 %x30-33 ) ; "00" to "23"
        $hour = '(?P<hour>[0-1]\d|2[0-3])';
        // minute  = %x30-35 %x30-39                        ; "00" to "59"
        $minute = '(?P<minute>[0-5]\d)';
        // second      = ( %x30-35 %x30-39 ) ; "00" to "59"
        // leap-second = ( %x36 %x30 )       ; "60"
        $second = '(?P<second>[0-5]\d|60)';
        // fraction        = ( DOT / COMMA ) 1*(%x30-39)
        $fraction = '([.,](?P<fraction>\d+))';
        // g-time-zone     = %x5A  ; "Z"
        //                   / g-differential
        // g-differential  = ( MINUS / PLUS ) hour [ minute ]
        $timezone = '(?P<timezone>Z|[-+]([0-1]\d|2[0-3])([0-5]\d)?)';

        // GeneralizedTime = century year month day hour
        //                      [ minute [ second / leap-second ] ]
        //                      [ fraction ]
        //                      g-time-zone
        $pattern = '/^'.
            "$year$month$day$hour".
            "($minute$second?)?".
            "$fraction?".
            $timezone.
            '$/';

        if (preg_match($pattern, $string, $m)) {
            if (empty($m['minute'])) {
                $m['minute'] = '00';
            }
            if (empty($m['second'])) {
                $m['second'] = '00';
            }
            if (empty($m['fraction'])) {
                $m['fraction'] = '0';
            }
            $date = new DateTime($m['year'].'-'.$m['month'].'-'.$m['day'].'T'.$m['hour'].':'.$m['minute'].':'.$m['second'].'.'.$m['fraction'].$m['timezone']);
            $date->setTimezone(new DateTimeZone('UTC'));
            return $date;
        } else {
            return false;
        }
    }

    static function string2ldapDate($string) {
        $values = explode("/",$string);
        $day = $values[0];
        $month = $values[1];
        $year = $values[2];

        $ldapdate = $year.$month.$day."000000Z";

        return $ldapdate;
    }

    static function adDate2phpDate($string) {
        $winSecs = (int)($string / 10000000); // divide by 10 000 000 to get seconds
        $unixTimestamp = ($winSecs - 11644473600); // 1.1.1600 -> 1.1.1970 difference in seconds
        $date = new DateTime();
        $date->setTimestamp($unixTimestamp);
        return $date;
    }

    static function timestamp2adDate($string) {
        $adDate = ((int)$string + 11644473600) * 10000000;
        return $adDate;
    }

}