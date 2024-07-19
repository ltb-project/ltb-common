# LDAP Tool Box PHP framework

[![Latest Stable Version](http://poser.pugx.org/ltb-project/ltb-common/v)](https://packagist.org/packages/ltb-project/ltb-common)
[![Latest Unstable Version](http://poser.pugx.org/ltb-project/ltb-common/v/unstable)](https://packagist.org/packages/ltb-project/ltb-common)
[![Total Downloads](http://poser.pugx.org/ltb-project/ltb-common/downloads)](https://packagist.org/packages/ltb-project/ltb-common)
[![CI Status](https://github.com/ltb-project/ltb-common/actions/workflows/unittests.yml/badge.svg)](https://github.com/ltb-project/ltb-common/actions/workflows/unittests.yml)
[![Composer Status](https://github.com/ltb-project/ltb-common/actions/workflows/php.yml/badge.svg)](https://github.com/ltb-project/ltb-common/actions/workflows/php.yml)

## Presentation

This is a PHP library to share code between LTB applications like [Self Service Password](https://github.com/ltb-project/self-service-password), [White Pages](https://github.com/ltb-project/white-pages), [Service Desk](https://github.com/ltb-project/service-desk), ...

## Installation

Add the dependency in your [composer](https://getcomposer.org/) configuration:

```json
{
    "require": {
        "ltb-project/ltb-common": "v0.2"
    }
}
```

Then update dependencies:
```
composer update
```

Use autoloading in your code to load composer dependencies:
```php
require __DIR__ . 'vendor/autoload.php';
```

## Usage

### LDAP connection

```php
$ldap_url = "ldap://ldap.example.com";
$ldap_starttls = false;
$ldap_binddn = "cn=admin,dc=example,dc=com";
$ldap_bindpw = "secret";
$ldap_network_timeout = 3;
$ldap_user_base = "ou=people,dc=example,dc=com";
$ldap_size_limit = 1000;                         
$ldap_krb5ccname = null;

$ldapInstance = new \Ltb\Ldap(                       
        $this->ldap_url,        
        $this->ldap_starttls,   
        $this->ldap_binddn, 
        $this->ldap_bindpw,
        $this->ldap_network_timeout,
        $this->ldap_user_base,
        $this->ldap_size_limit,
        $this->ldap_krb5ccname
);

$ldap_connection = $ldapInstance->connect();

$ldap = $ldap_connection[0];
$result = $ldap_connection[1];

if (!$result) {
    error_log("Unable to connect to $ldap_url");
    exit 1;
}
```

## Tests


### Unit tests

Get composer dependencies:

```
composer update
```

Run the tests:

```
vendor/bin/phpunit tests/Ltb
```

If you want coverage analysis, make sure to install `xdebug` PHP extension, and run:

```
XDEBUG_MODE=coverage vendor/bin/phpunit --coverage-text --configuration phpunit.xml
```


### Integration tests

Make sure you have docker or podman installed

Get composer dependencies:

```
composer update
```

Run the tests (requires an internet connection for donwloading the openldap docker image):

```
./runIntegrationTests.sh
```

If you already have an openldap server, you can also adapt the tests in tests/ directory, and run them with:

```
vendor/bin/phpunit tests/IntegrationTests
```


