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
    public $ldap_page_size       = 0;

    public function __construct(
                          $ldap_url,
                          $ldap_starttls,
                          $ldap_binddn,
                          $ldap_bindpw,
                          $ldap_network_timeout,
                          $ldap_user_base,
                          $ldap_size_limit,
                          $ldap_krb5ccname,
                          $ldap_page_size = 0
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
        $this->ldap_page_size       = $ldap_page_size;

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
        if ( !empty($this->ldap_binddn) ) {
            $bind = \Ltb\PhpLDAP::ldap_bind($ldap, $this->ldap_binddn, $this->ldap_bindpw);
        } elseif ( isset($this->ldap_krb5ccname) ) {
            putenv("KRB5CCNAME=".$this->ldap_krb5ccname);
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

    # Function that call ldap_search, ldap_read, or ldap_list
    # depending on the given scope
    # Expected arguments: scope + same list as ldap_search without ldap connection
    # - string $scope
    # - array|string $base,
    # - array|string $filter,
    # - array $attributes = [],
    # - int $attributes_only = 0,
    # - int $sizelimit = -1,
    # - int $timelimit = -1,
    # - int $deref = LDAP_DEREF_NEVER,
    # - ?array $controls = null
    function search_with_scope(string $scope = "sub", ...$searchargs)
    {
        switch($scope)
        {
            case "sub":
                return \Ltb\PhpLDAP::ldap_search($this->ldap, ...$searchargs);
            case "one":
                return \Ltb\PhpLDAP::ldap_list($this->ldap, ...$searchargs);
            case "base":
                return \Ltb\PhpLDAP::ldap_read($this->ldap, ...$searchargs);
            default:
                error_log("search_with_scope: invalid scope $scope");
                return false;
        }
    }

    function search($ldap_filter,$attributes, $attributes_map, $search_result_title, $search_result_sortby, $search_result_items, $search_scope = "sub")
    {

        $result = "";
        $nb_entries = 0;
        $entries = array();
        $size_limit_reached = false;

        # Connect to LDAP
        $ldap_connection = $this->connect();
        $result = $ldap_connection[1];

        if ($this->ldap) {

            # Order of the attributes array:
            # [ $search_result_items[], title, sortby, $attributes[] ]
            array_unshift($attributes, $attributes_map[$search_result_sortby]['attribute']);
            array_unshift($attributes, $attributes_map[$search_result_title]['attribute']);
            foreach( array_reverse($search_result_items) as $item ) {
                array_unshift($attributes, $attributes_map[$item]['attribute']);
            }

           $cookie = "";
           do {
               $controls = [];
               if($this->ldap_page_size != 0)
               {
                   $controls = [[
                                  'oid' => LDAP_CONTROL_PAGEDRESULTS,
                                  'value' => [
                                               'size' => $this->ldap_page_size,
                                               'cookie' => $cookie]
                               ]];
               }

               # Search for users
               $search = $this->search_with_scope($search_scope,
                                                  $this->ldap_user_base,
                                                  $ldap_filter,
                                                  $attributes,
                                                  0,
                                                  $this->ldap_size_limit,
                                                  -1,
                                                  LDAP_DEREF_NEVER,
                                                  $controls );

               if($search == false)
               {
                   # Error during search: compute the error code and stop the process
                   $errno = \Ltb\PhpLDAP::ldap_errno($this->ldap);
                   break;
               }

               $errno = null;
               $matcheddn = null;
               $errmsg = null;
               $referrals = null;
               \Ltb\PhpLDAP::ldap_parse_result($this->ldap, $search, $errno, $matcheddn, $errmsg, $referrals, $controls);

               if($errno != 0 and $errno !=4)
               {
                   # if any error occurs, stop the search loop and treat error
                   break;
               }

               $nb_entries += \Ltb\PhpLDAP::ldap_count_entries($this->ldap, $search);
               $entries = array_merge($entries, \Ltb\PhpLDAP::ldap_get_entries($this->ldap, $search));
               $entries["count"] = $nb_entries;

               if (isset($controls[LDAP_CONTROL_PAGEDRESULTS]['value']['cookie'])) {
                   $cookie = $controls[LDAP_CONTROL_PAGEDRESULTS]['value']['cookie'];
               } else {
                   $cookie = "";
               }

           } while (!empty($cookie) && $this->ldap_page_size != 0);

            if ( $errno == 4) {
                $size_limit_reached = true;
                error_log("LDAP - Search reached size limit, only $nb_entries returned");
            }
            if ( $errno != 0 and $errno !=4 ) {
                $result = "ldaperror";
                error_log("LDAP - Search error $errno  (".\Ltb\PhpLDAP::ldap_error($this->ldap).")");
            } else {

                if ($nb_entries === 0) {
                    $result = "noentriesfound";
                } else {

                    # Sort entries
                    if (isset($search_result_sortby)) {
                        $sortby = $attributes_map[$search_result_sortby]['attribute'];
                        $this->ldapSort($entries, $sortby);
                    }

                    unset($entries["count"]);
                }
            }
        }

        return [$this->ldap,$result,$nb_entries,$entries,$size_limit_reached];

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
        $count = isset($entries['count']) ? $entries['count'] : null;
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
        if( $count ) {
            $entries['count']=$count;
        }

        return true;

    }


    function compare_text($value1, $value2)
    {
        return $value1 <=> $value2;
    }

    function compare_bytes($value1, $value2)
    {
        if( is_numeric($value1) && is_numeric($value2) )
        {
            return ($value1 - $value2);
        }
        else
        {
            return 1;
        }
    }

    function compareValue($value1, $value2, $type)
    {
        # Check if comparison method exists
        if(method_exists($this, 'compare_'.$type)){
            # Run appropriate comparison method
            return $this->{'compare_'.$type}($value1, $value2);
        }
        else
        {
            # By default, use a simple text comparison method
            return $this->compare_text($value1, $value2);
        }
    }


    function compareEntries($sort_key, $direction, $type)
    {
        return function ($a, $b) use ($sort_key, $direction, $type) {

            $res = null;

            if( is_array($a) and is_array($b) )
            {
                if( array_key_exists($sort_key,$a) )
                {
                    if( array_key_exists($sort_key,$b) )
                    {
                        # Ascending order "asc" by default (from lesser to greater values)
                        $res = $this->compareValue($a[$sort_key][0], $b[$sort_key][0], $type);
                    }
                    else
                    {
                        $res = 1;
                    }
                }
                else
                {
                    if( array_key_exists($sort_key,$b) )
                    {
                        $res = -1;
                    }
                    else
                    {
                        $res = 0;
                    }
                }
            }
            else
            {
                $res = 0;
            }

            # invert result if this is descending order (from greater to lesser values)
            if( $direction == "desc" )
            {
                $res = $res * -1;
            }
            return $res;
        };
    }

    # sorting function with direction (ascending / descending)
    function sortEntries(array &$entries, $key, $direction, $type)
    {
        # 'count' is an additionnal attribute of ldap entries that will be preserved
        # remove it since lost by usort ( changed to integer index )
        $count = isset($entries['count']) ? $entries['count'] : null;
        unset($entries['count']);

        usort($entries, $this->compareEntries($key, $direction, $type));


        # preserve count since sorting should not change number of elements.
        if( $count ) {
            $entries['count']=$count;
        }

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
     * Gets the value of the LDAP attribute
     * @param string $dn the dn of the user
     * @param string $attribute the LDAP attribute
     * @return array|false the array containing attribute values
     */
    function get_attribute_values($dn, $attribute) {
        $search = \Ltb\PhpLDAP::ldap_read($this->ldap, $dn, "(objectClass=*)", array($attribute));
        if ($search) {
            return \Ltb\PhpLDAP::ldap_get_values($this->ldap, \Ltb\PhpLDAP::ldap_first_entry($this->ldap, $search), $attribute);
        }
        return false;
    }

    /*
    * Gets the value of the password attribute
    * @param string $dn the dn of the user
    * @param string $pwdattribute the Attribute that contains the password
    * @return array|false the array containing attribute values
    */
    function get_password_value($dn, $pwdattribute) {
        $password_values = $this->get_attribute_values($dn, $pwdattribute);
        if(isset($password_values[0])) {
            return $password_values[0];
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

    /**
     * get the first value of the first attribute in the first entry found
     * @param string $ldap_base: the base search
     * @param string $ldap_scope: the scope for the search
     * @param string $ldap_filter: the filter for searching the entry
     * @param string $attribute: a list of attributes, separated by ","
     * @return string: the first value of the first attribute found in the first entry
     */
    function get_first_value($ldap_base, $ldap_scope, $ldap_filter, $attribute): string {

        $value = "";

        if ($this->ldap) {

            # Search entry
            $search = $this->search_with_scope($ldap_scope, $ldap_base, $ldap_filter, explode(",", $attribute));

            $errno = \Ltb\PhpLDAP::ldap_errno($this->ldap);

            if ( $errno ) {
                error_log("LDAP - Search error $errno  (".\Ltb\PhpLDAP::ldap_error($this->ldap).")");
            } else {
                $entry = \Ltb\PhpLDAP::ldap_get_entries($this->ldap, $search);

                # Loop over attribute
                foreach ( explode(",", $attribute) as $ldap_attribute ) {
                    if ( isset ($entry[0][$ldap_attribute]) ) {
                         $value = $entry[0][$ldap_attribute][0];
                         break;
                    }
                }
            }
        }

        return $value;

    }

    /**
     * test if a DN matches filter, base and scope
     * @param string $dn: entry DN
     * @param string $dnAttribute: attribute name containing the DN
     * @param string $filter
     * @param string $base
     * @param string $scope
     * @return bool: true if DN matches filter, base and scope
     */
    public function matchDn($dn, $dnAttribute, $filter, $base, $scope): bool {

        # Build filter
        $dn_escape = ldap_escape($dn, "", LDAP_ESCAPE_FILTER);
        $search_filter = '(&' . $filter . '(' . $dnAttribute . '=' . $dn_escape .'))';

        # Search with scope
        $search = $this->search_with_scope($scope, $base, $search_filter, ['1.1']);

        $count = \Ltb\PhpLDAP::ldap_count_entries($this->ldap, $search);

        if ( $count == 1) { return true; }
        return false;
    }

    /**
     * sort values of each attributes of an entry
     * @param array $entry: LDAP entry
     * @param array $attributes_map: confguration map
     * @return array: entry sorted
     */
    public function sortEntry($entry, $attributes_map): array {

        foreach ($entry as $attr => $values) {
            if ( is_array($values) && $values['count'] > 1 ) {

                # Find key in attributes_map
                $attributes_map_filter = array_filter($attributes_map, function($v) use(&$attr) {
                    return $v['attribute'] == "$attr";
                });
                if( count($attributes_map_filter) < 1 )
                {
                    $k = "";
                    error_log("WARN: no key found for attribute $attr in \$attributes_map");
                }
                elseif( count($attributes_map_filter) > 1 )
                {
                    $k = array_key_first($attributes_map_filter);
                    error_log("WARN: multiple keys found for attribute $attr in \$attributes_map, using first one: $k");
                }
                else
                {
                    $k = array_key_first($attributes_map_filter);
                }

                if(isset($attributes_map[$k]['sort']))
                {
                    if($attributes_map[$k]['sort'] == "descending" )
                    {
                        # descending sort
                        arsort($values);
                    }
                    else
                    {
                        # ascending sort
                        asort($values);
                    }
                }
                else
                {
                    # if 'sort' param unset: default to ascending sort
                    asort($values);
                }
            }
            if ( isset($values['count']) ) {
                unset($values['count']);
            }
            $entry[$attr] = $values;

        }
        return $entry;
    }
}
?>
