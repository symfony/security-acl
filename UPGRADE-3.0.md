Security Component - ACL (Access Control List)
==============================================

Security provides an infrastructure for sophisticated authorization systems,
which makes it possible to easily separate the actual authorization logic from
so called user providers that hold the users credentials. It is inspired by
the Java Spring framework.

Resources
---------

Documentation:

https://symfony.com/doc/3.0/book/security.html

Tests
-----

You can run the unit tests with the following command:

    $ cd path/to/Symfony/Component/Security/Acl/
    $ composer.phar install --dev
    $ phpunit
