# FreeIPA LDAP users and groups for 3rd party clients

This guide explains FreeIPA's LDAP DIT (directory information tree) for
users and user groups, and how 3rd party clients can use LDAP to fetch
user and group information.

- Author: Christian Heimes <cheimes@redhat.com>
- Created: 2023-08-16

## Conventions

* IPA domain: `ipa.example`
* IPA Base DN (`$SUFFIX`): `dc=ipa,dc=example`
* IPA Kerberos realm: `IPA.EXAMPLE`
* 389-DS / dirsrv instance name: `IPA-EXAMPLE`

The `basedn` is derived from the domain name and the 389-DS instance name
is derived from the Kerberos realm. The information can be read from IPA's
configuration file or retrieved with the `ipa` command line tool:

```shell
$ cat /etc/ipa/default.conf 
[global]
...
basedn = dc=ipa,dc=example
realm = IPA.EXAMPLE
domain = ipa.example
...
```

```shell
$ kinit yourusername
$ ipa env | grep -E '(basedn|domain|realm):'
  basedn: dc=ipa,dc=example
  domain: ipa.example
  realm: IPA.EXAMPLE
```

## Alternatives to LDAP clients

TODO

* sssd-ifp (info pipe) D-Bus bindings
* [mod_lookup_identity](https://www.adelton.com/apache/mod_lookup_identity/) for Apache HTTPd
* PAM service
* [mod_intercept_form_submit](https://www.adelton.com/apache/mod_intercept_form_submit/)
  and [mod_authnz_pam](https://www.adelton.com/apache/mod_authnz_pam/) for Apache HTTPd
* OIDC / SCIM with ipa-tuura and KeyCloak


## Authentication

TODO

* service account
* system account `cn=sysaccounts,cn=etc,$SUFFIX`
* password, Kerberos/GSSAPI


## Users

FreeIPA has several types of user accounts. *Staged users* and *Deleted users*
are part of FreeIPA's provisioning system. Staged and deleted accounts are
hidden from normal operations and cannot log in.

* base DN: `cn=users,cn=accounts,$SUFFIX`
* user filter: `(&(objectClass=posixAccount)(!(nsAccountLock=TRUE)))`
* user search filter: `(&(objectClass=posixAccount)(!(nsAccountLock=TRUE))(uid=%s))`
* user dn example: `uid=myuser,cn=users,cn=accounts,$SUFFIX`
* object classes:
  - `posixAccount` (primary)
  - `inetOrgPerson` (optional)
  - `inetUser`
  - `ipaObject`
  - `organizationalPerson` (optional)
  - `person`
  - ...
* attributes:
    * user login: `uid` (**RDN attribute**)
    * UUID: `ipaUniqueId`
    * full name: `cn`
    * display name: `displayName` (optional, usually the same as `cn`)
    * first name: `givenName` (optional)
    * last name: `sn`
    * email addresses: `mail` (optional, multi-valued)
    * account lock status: `nsAccountLock` (user is active if the attribute is missing or `FALSE`)

Please note that applications should not use the `uidNumber` and `gidNumber`
attributes of a group entry. The values only reflect the defaults. ID views
can override the values for a given host or host group.


## User groups

FreeIPA has multiple types of groups: *user groups*, *host groups*, and NIS
*net groups*. As the name suggests, users can be members of user groups.
Further more, there are four types of user groups: *non-POSIX user groups*,
*POSIX user groups*, *External user groups*, and *private user groups*.
Private user groups (PUG) behave differently than other user groups and are
managed internally.

* base DN: `cn=groups,cn=accounts,$SUFFIX`
* generic group filter: `(objectClass=ipaUserGroup)`
* group search filter: `(&(objectClass=ipaUserGroup)(cn=%s))`
* group dn example: `cn=mygroup,cn=groups,cn=accounts,$SUFFIX`
* object classes: (not PUG)
  - `ipaUserGroup` (primary)
  - `groupOfNames`
  - `ipaObject`
  - `nestedGroup`
* attributes:
    * group name: `cn` (**RDN attribute**)
    * description: `description` (optional)
    * UUID: `ipaUniqueId`

Additionally user groups may have an `ipaNTGroupsAttr` object class and an
`ipaNTSecurityIdentifier` attribute.

### non-POSIX user groups

Non-POSIX user groups are only visible to clients that use LDAP or IPA API.
They are cheaper than POSIX groups and should be preferred, unless group
information and membership must be visible to the OS, too.

### POSIX user groups

* additional object class: `posixGroup`

POSIX user groups are visible in the OS, e.g. with `getent group mygroupname`
or group members from `id username`. They have the additional object class
`posixGroup`, which provides the `gidNumber` attribute (POSIX gid).

Please note that applications should not use the `gidNumber` of a group entry.
The value only reflects the default `gid` number. ID views can override the
group name and gid for a given host or host group.

### External user groups

* additional object class: `ipaExternalGroup`

An external user group is a non-POSIX user group that contains externally
managed user accounts, e.g. from Active Directory.

### Private user groups

* object classes:
  - `ipaObject`
  - `mepManagedEntry`
  - `posixGroup`

Typically ever user account has a private user group (PUG) with the same name
as the user. PUGs are managed internally. 3rd party applications should not
use PUGs.


## Group member / memberOf in FreeIPA

There are two common standards to store group membership information in LDAP.
Typically LDAP schemas either use
[RFC2307](https://datatracker.ietf.org/doc/html/rfc2307) or *RFC2307bis*.
The blog [LDAP Schemas: RFC2307 vs RFC2307bis](https://unofficialaciguide.com/2019/07/31/ldap-schemas-for-aci-administrators-rfc2307-vs-rfc2307bis/)
explains the differences. FreeIPA uses *RFC2307bis* with member/memberOf attributes
for group membership.

In RFC2307, group entries have multi-valued `memberUID` attribute, that
identifies the user names (RDN attribute) of the members. User objects
don't contain any information about group membership. Nested groups
are not possible.

With RFC2307bis, group entries have a multi-valued `member` attribute,
that contains the distinguised name (DN) of users and other members.
User entries have a multi-valued `memberOf` attribute with the DN
of the groups, that the user is a member of. This makes it possible
to retrive group membership from the user object. Further more,
groups also can have a `memberOf` relation, which enables nested groups.

FreeIPA makes heavy use of nested membership for other features, e.g.
for role-based access control and host-based access control. A user group
can be member of a RBAC role, which grants members of the user group
privileges, and eventually permissions to create/read/update/delete
data in LDAP.

### How to parse FreeIPA's memberOf information

RFC2307bis makes it possible to retrieve a user's group membership
information from `memberOf` together with user information in a single
query. RFC2307 with `memberUID` requires a second search with a slightly
more expensive matching search.

Application have to parse the attribute values of `memberOf` to extract
group names. The following example user is member of two groups, has an
HBAC rule, a SUDO rule, and an RBAC role assigned. The privileges and
permissions are inherited from the RBAC role.

```shell
$ ldapsearch -LLL -Y GSSAPI \
    -b cn=users,cn=accounts,dc=ipa,dc=example \
    '(&(objectClass=posixAccount)(!(nsAccountLock=TRUE))(uid=myuser))' \
    uid ch mail memberOf ipaUniqueId
dn: uid=myuser,cn=users,cn=accounts,dc=ipa,dc=example
uid: myuser
mail: myuser@ipa.example
memberOf: cn=ipausers,cn=groups,cn=accounts,dc=ipa,dc=example
memberOf: cn=mygroup,cn=groups,cn=accounts,dc=ipa,dc=example
memberOf: cn=helpdesk,cn=roles,cn=accounts,dc=ipa,dc=example
memberOf: cn=Modify Users and Reset passwords,cn=privileges,cn=pbac,dc=ipa,dc=example
memberOf: cn=System: Change User password,cn=permissions,cn=pbac,dc=ipa,dc=example
memberOf: cn=System: Manage User Certificates,cn=permissions,cn=pbac,dc=ipa,dc=example
memberOf: cn=System: Manage User Principals,cn=permissions,cn=pbac,dc=ipa,dc=example
memberOf: cn=System: Modify Users,cn=permissions,cn=pbac,dc=ipa,dc=example
memberOf: cn=Modify Group membership,cn=privileges,cn=pbac,dc=ipa,dc=example
memberOf: cn=System: Modify External Group Membership,cn=permissions,cn=pbac,dc=ipa,dc=example
memberOf: cn=System: Modify Group Membership,cn=permissions,cn=pbac,dc=ipa,dc=example
memberOf: ipaUniqueID=20b35fce-29fd-11ee-b4fa-fa163e9ccace,cn=hbac,dc=ipa,dc=example
memberOf: ipaUniqueID=224b709c-29fd-11ee-a74a-fa163e9ccace,cn=sudorules,cn=sudo,dc=ipa,dc=example
ipaUniqueId: d7ff86cc-29fc-11ee-b4fa-fa163e9ccace
```

1) Filter out and ignore all DNs that do not end with the group base dn
   `cn=groups,cn=accounts,$SUFFIX`.
2) Extract the value of the leftmost RDN with attribute name `cn`.


### 389-DS implementation details

389-DS LDAP server implements the member / memberOf feature with the help
of two plugins.

The `cn=MemberOf Plugin,cn=plugins,cn=config` creates and updates the
reverse mapping attribute `memberOf` everytime a `member` attribute is
modified. In FreeIPA the plugin also monitors the attributes `ipaOwner`,
`memberHost`, and `memberUser`

A `ldapmodify` with the LDIF:

```
dn: cn=mygroup,cn=groups,cn=accounts,dc=ipa,dc=example
changetype: modify
add: member
member: uid=myuser,cn=users,cn=accounts,dc=ipa,dc=example
```

updates the user entry with

```
dn: uid=myuser,cn=users,cn=accounts,dc=ipa,dc=example
memberOf: cn=mygroup,cn=groups,cn=accounts,dc=ipa,dc=example
```

The `MemberOf Plugin` only works in one direction. An update of
`memberOf` does **NOT** update the reverse entry!

The second plugin `cn=referential integrity postoperation,cn=plugins,cn=config`
ensures that the `member` attribute does not contain any dangling members.
It updates members on rename (`MODRDN`) or removes members on delete.


## Unique identifier (ipaUniqueId, entryUUID)

Some 3rd party application require a unique identifier that does not chance
when a user or group is renamed. IPA's users, user groups, and most other
entries in IPA have the `ipaObject` object class. The object class provides
the attribute `ipaUniqueId`, which is a UUIDv4 (random UUID).

Some application want the [RFC 4530](https://www.rfc-editor.org/rfc/rfc4530)
`entryUUID` operational attribute instead. 389-DS supports entryUUID
since version 1.4.3 or newer. The version is available in Fedora 32+,
CentOS 8 Stream, CentOS 9 stream, RHEL 8.5+, and RHEL 9.0+. EntryUUID is not
available in CentOS 7 and RHEL 7.9.

In case an IPA domain was created with an older version of 389-DS, it is
necessary to enable the entryUUID plugin on each server and run a fixup task
to create missing entryUUID attributes.

On all IPA servers, check the status of the entryuuid plugin:

```shell
$ dsconf IPA-EXAMPLE plugin entryuuid status
```

If the plugin is disabled, enable it with:

```shell
$ dsconf IPA-EXAMPLE plugin entryuuid enable
```

Once the plugin is enabled on all IPA servers, run a fixup task to create
missing `entryUUID` attributes. The task may take a while to complete.

```shell
$ dsconf IPA-EXAMPLE plugin entryuuid fixup dc=ipa,dc=example
```

**NOTE**
The entryUUID attribute is a so called *operational attribute*. That means the
attribute is created and maintained by the LDAP server. Operational attributes
don't need an object class. They are not returned by a wildcard `'*'` query,
because `*` only matches user attributes. Operational attributes must be fetched
either explicitly by name (e.g. `* entryUUID`) or with the `+` wildcard
(e.g. `* +`).


## Security considerations

LDAP filters and queries are vulnerable to SQL inject-like attacks. Any value
from an untrusted source must be escaped properly.
[RFC 4515](https://www.rfc-editor.org/rfc/rfc451) defines quoting rules for LDAP
filters.

* `NUL` byte '`\x00`' -> '`\00`'
* open parenthesis (LPAREN) '`(`' -> '`\28`'
* closing parenthesis (RPAREN) '`)`' -> '`\29`'
* asterisk '`*`' -> '`\2a`'
* backslash '`\`' -> '`\5c`'


## Terminology

TODO

- DIT: directory information tree, the tree-like hierarchy of an LDAP
  directory, see [DIT and the LDAP Root DSE](https://ldap.com/dit-and-the-ldap-root-dse/)
- DN: distinguised name
- RDN: relative distinguised name
