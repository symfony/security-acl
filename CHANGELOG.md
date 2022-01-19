CHANGELOG
=========

3.2.0
-----

 * Change minimum PHP version to 7.2.5
 * Add PSR-6 support for ACL caching
 * Add support for `doctrine/cache` v2
 * Drop support for Symfony 3
 * Deprecate not implementing `__serialize()` and `__unserialize()` methods in
   `AclInterface` and `EntryInterface` implementations. The methods will be
   added to the interfaces in 4.0.
