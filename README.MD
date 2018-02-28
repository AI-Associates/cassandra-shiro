# Cassandra Shiro authenticator

Cassandra IAuthenticator implementation using Apache Shiro.

## Setup

Build JAR file with `mvn clean verify`.

Copy `target/cassandra-shiro-1.0-SNAPSHOT-jar-with-dependencies.jar` to c* `lib/`. 
This contains the authenticator with required dependencies.

Run Cassandra with password authentication set in `cassandra.yaml`.
 
Log in with default admin credentials and add a role with name equal to 
one of the usernames available via configured Shiro realm (such as LDAP,
 INI, etc.) 

```
$ bin/cqlsh -u cassandra -p cassandra

Connected to Test Cluster at 127.0.0.1:9042.
[cqlsh 5.0.1 | Cassandra 3.11.1 | CQL spec 3.4.4 | Native protocol v4]
Use HELP for help.
cassandra@cqlsh> create role cass_admin with SUPERUSER = true AND LOGIN = true and PASSWORD = 'password';
cassandra@cqlsh> ^D


```

Kill Cassandra server.

Change yaml config to use Shiro plain authenticator:

```yaml
authenticator: associates.ai.cassandra.auth.ShiroPlainAuthenticator
```

Also, make sure that you're not using AllowAllAuthorizer. Set the authorizer property as follows:

```yaml
authorizer: CassandraAuthorizer
```

Copy `shiro.ini.example` as `shiro.ini` to Cassandra `conf/` directory 
(or anywhere else on the classpath). 
Customize with specific realm configuration.

Restart cassandra.

Test by connecting to the cluster with `cqlsh`:

```
$ bin/cqlsh -u cass_admin -p pass

Connected to Test Cluster at 127.0.0.1:9042.
[cqlsh 5.0.1 | Cassandra 3.11.1 | CQL spec 3.4.4 | Native protocol v4]
Use HELP for help.
cass_admin@cqlsh> list roles;

 role       | super | login | options
------------+-------+-------+---------
 cass_admin |  True |  True |        {}
  cassandra |  True |  True |        {}

(2 rows)
cass_admin@cqlsh> ^D
```

## LDAP Search realm

LDAP Search realm `associates.ai.cassandra.auth.realm.SearchLdapRealm` allows you to search for given username using supplied 
pattern in directory. See `shiro.ini.example` for example config.

### Multiple realms in same ini file

Shiro supports multiple realms in one config. Check out [Shiro docs on Realms](﻿https://shiro.apache.org/realm.html#explicit-assignment)
for more info. See [shiro.ini.multi-realm-example](shiro.ini.multi-realm-example) for
a simple example using both stock `DefaultLdapRealm` and `SearchLdapRealm` to perform authentication.
 

## Running with example OpenLDAP server

For testing in development you can use the supplied `docker/docker-compose.yml`
file which will start an OpenLDAP server compatible with the example config.
Start container with `docker-compose up -d` and follow setup instructions above.
   
Connect to LDAP server (e.g. with [Apache Directory Studio](﻿http://directory.apache.org/studio/)) 
or browse `docker/bootstrap/example.ldif` LDIF file for available usernames.
  
Before changing Cassandra authenticator implementation you can execute `roles.cql` 
file to configure the available roles (instead of creating them manually).  