<?php namespace Ltb;


class Ldap {

    // php ldap instance
    public $ldap                 = null;

    // ldap connection parameters
    public $ldap_url             = null;
    public $ldap_starttls        = null;
    public $ldap_binddn          = null;
    public $ldap_bindpw          = null;
    public $ldap_network_timeout = null;
    public $ldap_user_base       = null;
    public $ldap_size_limit      = null;
    public $ldap_krb5ccname      = null;

    public function __construct(
                          $ldap_url,
                          $ldap_starttls,
                          $ldap_binddn,
                          $ldap_bindpw,
                          $ldap_network_timeout,
                          $ldap_user_base,
                          $ldap_size_limit,
                          $ldap_krb5ccname
                      )
    {
        $this->ldap_url             = $ldap_url;
        $this->ldap_starttls        = $ldap_starttls;
        $this->ldap_binddn          = $ldap_binddn;
        $this->ldap_bindpw          = $ldap_bindpw;
        $this->ldap_network_timeout = $ldap_network_timeout;
        $this->ldap_user_base       = $ldap_user_base;
        $this->ldap_size_limit      = $ldap_size_limit;
        $this->ldap_krb5ccname      = $ldap_krb5ccname;
        
    }

    function connect() {

        # Connect to LDAP
        $ldap = \Ltb\PhpLDAP::ldap_connect($this->ldap_url);
        \Ltb\PhpLDAP::ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
        \Ltb\PhpLDAP::ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);
        if ( isset($this->ldap_network_timeout) ) {
            \Ltb\PhpLDAP::ldap_set_option($ldap, LDAP_OPT_NETWORK_TIMEOUT, $this->ldap_network_timeout);
        }

        if ( $this->ldap_starttls && !\Ltb\PhpLDAP::ldap_start_tls($ldap) ) {
            error_log("LDAP - Unable to use StartTLS");
            return array(false, "ldaperror");
        }

        # Bind
        if ( isset($this->ldap_binddn) && isset($this->ldap_bindpw) ) {
            $bind = \Ltb\PhpLDAP::ldap_bind($ldap, $this->ldap_binddn, $this->ldap_bindpw);
        } elseif ( isset($this->ldap_krb5ccname) ) {
            putenv("KRB5CCNAME=".$ldap_krb5ccname);
            $bind = \Ltb\PhpLDAP::ldap_sasl_bind($ldap, NULL, NULL, 'GSSAPI') or error_log('LDAP - GSSAPI Bind failed');
        } else {
            $bind = \Ltb\PhpLDAP::ldap_bind($ldap);
        }

        if ( !$bind ) {
            $errno = \Ltb\PhpLDAP::ldap_errno($ldap);
            if ( $errno ) {
                error_log("LDAP - Bind error $errno  (".\Ltb\PhpLDAP::ldap_error($ldap).")");
            } else {
                error_log("LDAP - Bind error");
            }
            return array(false, "ldaperror");
        }

        $this->ldap = $ldap;
        return array($ldap, false);
    }

    function search($ldap_filter,$attributes, $attributes_map, $search_result_title, $search_result_sortby, $search_result_items)
    {

        $result = "";
        $nb_entries = 0;
        $entries = array();
        $size_limit_reached = false;

        # Connect to LDAP
        $ldap_connection = $this->connect();

        $ldap = $ldap_connection[0];
        $result = $ldap_connection[1];

        if ($ldap) {

            foreach( $search_result_items as $item ) {
                $attributes[] = $attributes_map[$item]['attribute'];
            }
            $attributes[] = $attributes_map[$search_result_title]['attribute'];
            $attributes[] = $attributes_map[$search_result_sortby]['attribute'];

            # Search for users
            $search = \Ltb\PhpLDAP::ldap_search($ldap, $this->ldap_user_base, $ldap_filter, $attributes, 0, $this->ldap_size_limit);

            $errno = \Ltb\PhpLDAP::ldap_errno($ldap);

            if ( $errno == 4) {
                $size_limit_reached = true;
            }
            if ( $errno != 0 and $errno !=4 ) {
                $result = "ldaperror";
                error_log("LDAP - Search error $errno  (".\Ltb\PhpLDAP::ldap_error($ldap).")");
            } else {

                # Get search results
                $nb_entries = \Ltb\PhpLDAP::ldap_count_entries($ldap, $search);

                if ($nb_entries === 0) {
                    $result = "noentriesfound";
                } else {
                    $entries = \Ltb\PhpLDAP::ldap_get_entries($ldap, $search);

                    # Sort entries
                    if (isset($search_result_sortby)) {
                        $sortby = $attributes_map[$search_result_sortby]['attribute'];
                        $this->ldapSort($entries, $sortby);
                    }

                    unset($entries["count"]);
                }
            }
        }

        return [$ldap,$result,$nb_entries,$entries,$size_limit_reached];

    }

    function get_list($ldap_base, $ldap_filter, $key, $value) {

        $return = array();

        if ($this->ldap != null) {

            # Search entry
            $search = \Ltb\PhpLDAP::ldap_search($this->ldap, $ldap_base, $ldap_filter, array($key, $value) );

            $errno = \Ltb\PhpLDAP::ldap_errno($this->ldap);

            if ( $errno ) {
                error_log("LDAP - Search error $errno  (".\Ltb\PhpLDAP::ldap_error($this->ldap).")");
            } else {
                $entries = \Ltb\PhpLDAP::ldap_get_entries($this->ldap, $search);
                for ($i=0; $i<$entries["count"]; $i++) {
                    if(isset($entries[$i][$key][0])) {
                        $return[$entries[$i][$key][0]] = isset($entries[$i][$value][0]) ? $entries[$i][$value][0] : $entries[$i][$key][0];
                    }
                }
            }
        }

        return $return;
    }

    # if key is not found in attributes, order of entries is preserved
    function ldapSort(array &$entries, $key)
    {
        # 'count' is an additionnal attribute of ldap entries that will be preserved
        # remove it since lost by usort ( changed to integer index )
        $count=$entries['count'];
        unset($entries['count']);

        $sort_key=$key;

        usort($entries,
              fn($a, $b) =>
              ( is_array($a) and is_array($b) ) ?
                ( array_key_exists($sort_key,$a) ?
                    ( array_key_exists($sort_key,$b) ? $a[$sort_key][0] <=> $b[$sort_key][0] : 1 )
                  : ( array_key_exists($sort_key,$b) ? -1 : 0 ))
              : 0
        );


        # preserve count since sorting should not change number of elements.
        $entries['count']=$count;

        return true;

    }

    # ldap_search + ldap_sort combined done at server side if possible
    # if not supported fallback on client sorting.
    function sorted_search($ldap_base, $ldap_filter, $attributes, $sortby, $ldap_size_limit) {

        if($this->ldap == null)
            return array(null, null, null);

        if (isset($sortby) and $sortby)
        {
            $check_attribute='supportedControl';
            $check = \Ltb\PhpLDAP::ldap_read($this->ldap, '', '(objectClass=*)', [$check_attribute]);
            $entries = \Ltb\PhpLDAP::ldap_get_entries($this->ldap, $check);
            if (in_array(LDAP_CONTROL_SORTREQUEST, $entries[0]['supportedcontrol'],true)) {
                # server side sort
                $controls=[['oid' => LDAP_CONTROL_SORTREQUEST, 'value' => [['attr'=>$sortby]]]];
                # if $sortby is not in $attributes ? what to do ?
                $ldap_result = \Ltb\PhpLDAP::ldap_search($this->ldap, $ldap_base, $ldap_filter, $attributes, 0, $ldap_size_limit, -1, LDAP_DEREF_NEVER, $controls );
                $errno = \Ltb\PhpLDAP::ldap_errno($this->ldap);
                if ( $errno === 0 )
                {
                    $entries=\Ltb\PhpLDAP::ldap_get_entries($this->ldap, $ldap_result);
                }
            }
        }

        if (!isset($errno))
        {
            $ldap_result = \Ltb\PhpLDAP::ldap_search($this->ldap, $ldap_base, $ldap_filter, $attributes, 0, $ldap_size_limit);
            $errno = \Ltb\PhpLDAP::ldap_errno($this->ldap);
            if ( $errno === 0 )
            {
                $entries=\Ltb\PhpLDAP::ldap_get_entries($this->ldap, $ldap_result);
                $this->ldapSort($entries,$sortby);
            }
            else {
                var_dump($errno);
            }
        }

        return array($ldap_result,$errno,$entries);
    }

    /**
     * Gets the value of the password attribute
     * @param string $dn the dn of the user
     * @param string $pwdattribute the Attribute that contains the password
     * @return string|false the first value of the password taken from ldap_get_values
     */
    function get_password_value($dn, $pwdattribute): string|false {
        $search_userpassword = \Ltb\PhpLDAP::ldap_read($this->ldap, $dn, "(objectClass=*)", array($pwdattribute));
        if ($search_userpassword) {
            $password_values = \Ltb\PhpLDAP::ldap_get_values($this->ldap, \Ltb\PhpLDAP::ldap_first_entry($this->ldap, $search_userpassword), $pwdattribute);
            if(isset($password_values[0]))
            {
                return $password_values[0];
            }
        }
        return false;
    }

    /**
     * Changes the password of a user while binded as the user in an Active Directory
     * @param string $dn the dn of the user
     * @param string $oldpassword the old password
     * @param string $password the new password
     * @return array [$error_code, $error_msg]
     */
    function change_ad_password_as_user($dn, $oldpassword, $password): array {
        # The AD password change procedure is modifying the attribute unicodePwd by
        # first deleting unicodePwd with the old password and them adding it with the
        # the new password
        $oldpassword_hashed = \Ltb\Password::make_ad_password($oldpassword);

        $modifications = array(
            array(
                "attrib" => "unicodePwd",
                "modtype" => LDAP_MODIFY_BATCH_REMOVE,
                "values" => array($oldpassword_hashed),
            ),
            array(
                "attrib" => "unicodePwd",
                "modtype" => LDAP_MODIFY_BATCH_ADD,
                "values" => array($password),
            )
        );

        \Ltb\PhpLDAP::ldap_modify_batch($this->ldap, $dn, $modifications);
        $error_code = \Ltb\PhpLDAP::ldap_errno($this->ldap);
        $error_msg = \Ltb\PhpLDAP::ldap_error($this->ldap);
        return array($error_code, $error_msg);
    }

    protected function get_ppolicy_error_code($ctrls) {
        if (isset($ctrls[LDAP_CONTROL_PASSWORDPOLICYRESPONSE])) {
            $value = $ctrls[LDAP_CONTROL_PASSWORDPOLICYRESPONSE]['value'];
            if (isset($value['error'])) {
                $ppolicy_error_code = $value['error'];
                error_log("LDAP - Ppolicy error code: $ppolicy_error_code");
                return $ppolicy_error_code;
            }
        }
        return false;
    }

    /**
     * Changes the Password using extended password modification
     * @param string $dn the dn of the user
     * @param string $oldpassword the old password
     * @param string $password the new password
     * @param array $userdata
     * @param bool $use_ppolicy_control
     * @return array 0: error_code, 1: error_msg, 2: ppolicy_error_code
     */
    function change_password_with_exop($dn, $oldpassword, $password, $use_ppolicy_control): array {
        $ppolicy_error_code = false;
        $exop_passwd = FALSE;
        if ( $use_ppolicy_control ) {
            $ctrls = array();
            $exop_passwd = \Ltb\PhpLDAP::ldap_exop_passwd($this->ldap, $dn, $oldpassword, $password, $ctrls);
            $error_code = \Ltb\PhpLDAP::ldap_errno($this->ldap);
            $error_msg = \Ltb\PhpLDAP::ldap_error($this->ldap);
            if (!$exop_passwd) {
                $ppolicy_error_code = self::get_ppolicy_error_code($ctrls);
            }
        } else {
            $exop_passwd = \Ltb\PhpLDAP::ldap_exop_passwd($this->ldap, $dn, $oldpassword, $password);
            $error_code = \Ltb\PhpLDAP::ldap_errno($this->ldap);
            $error_msg = \Ltb\PhpLDAP::ldap_error($this->ldap);
        }
        return array($error_code, $error_msg, $ppolicy_error_code);
    }

    /**
     * Changes attributes (and possibly password) using Password Policy Control
     * @param string $dn the dn of the user
     * @param array $userdata the array, containing the modifications
     * @return array 0: error_code, 1: error_msg, 2: ppolicy_error_code
     */
    function modify_attributes_using_ppolicy($dn, $userdata): array {
        $error_code = "";
        $error_msg = "";
        $matcheddn = null;
        $referrals = array();
        $ctrls = array();
        $ppolicy_error_code = false;
        $ppolicy_replace = \Ltb\PhpLDAP::ldap_mod_replace_ext($this->ldap, $dn, $userdata, [['oid' => LDAP_CONTROL_PASSWORDPOLICYREQUEST]]);
        if (\Ltb\PhpLDAP::ldap_parse_result($this->ldap, $ppolicy_replace, $error_code, $matcheddn, $error_msg, $referrals, $ctrls)) {
            $ppolicy_error_code = self::get_ppolicy_error_code($ctrls);
        }
        return array($error_code, $error_msg, $ppolicy_error_code);
    }

    /**
     * Changes attributes (and password)
     * @param string $dn the dn of the user
     * @param array $userdata the array, containing the new (hashed) password
     * @return array 0: error_code, 1: error_msg
     */
    function modify_attributes($dn, $userdata): array {
        \Ltb\PhpLDAP::ldap_mod_replace($this->ldap, $dn, $userdata);
        $error_code = \Ltb\PhpLDAP::ldap_errno($this->ldap);
        $error_msg = \Ltb\PhpLDAP::ldap_error($this->ldap);
        return array($error_code, $error_msg);
    }

    const PPOLICY_ERROR_CODE_TO_RESULT_MAPPER = [
            0 => "passwordExpired",
            1 => "accountLocked",
            2 => "changeAfterReset",
            3 => "passwordModNotAllowed",
            4 => "mustSupplyOldPassword",
            5 => "badquality",
            6 => "tooshort",
            7 => "tooyoung",
            8 => "inhistory"
        ];

}
?>
