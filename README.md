# ltb-project/ldap

php composer common library for ltb projects usage of ldap
This project is maintained by ltb-project team.

This covers the 3 following projects

* <https://github.com/ltb-project/white-pages>
* <https://github.com/ltb-project/service-desk>
* <https://github.com/ltb-project/self-service-password>

Starting point : identifying code to factorize for all this project and maintain a coherent unified naming convention.

projet start from white-page see https://github.com/ltb-project/white-pages/issues/119

Usage of this framework in projects will be done in a **ltb-ldap** branch until it becomes default.


## composer library

See https://getcomposer.org/

https://getcomposer.org/doc/02-libraries.md cover how to make library installable through Composer.

This package is published on https://packagist.org/packages/ltb-project/ldap

## ltb projects coverage


|||version|commentaire|bug tracking|
|self-service-password|<https://github.com/ltb-project/self-service-password>|wip|||
|service-desk|<https://github.com/ltb-project/service-desk>|wip|||
|white-pages|<https://github.com/ltb-project/white-pages>|wip||https://github.com/ltb-project/white-pages/issues/119|

# Notes

This project provides ldap_sort support that is now removed from php.

replace :

```
ldap_sort($link, $result, $sortfilter)
```

by

```
Ldap::ldapSort($result, $sortfilter)
```

remark : $link is unused so not provided as parameter.
