UPGRADE FROM 2.x to 3.0
=======================

### Entry, FieldEntry and EntryInterface

 * The `acl` constructor argument and related getter getAcl() has been removed due to problems with release memory (https://github.com/symfony/symfony/issues/2376).
   Classes that before work with Entry objects and call Entry::getAcl now must:
        a) expect instance of AclEntryInterface and call AclEntry::getAcl and AclEntry::getEntry.
        or b) additionally to EntryInterface $entry argument require AclInterface $acl argument

### MutableAclProvider
 * propertyChanged method now expect as $sender argument instance of MutableAclInterface or AclEntryInterface (was MutableAclInterface or EntryInterface)