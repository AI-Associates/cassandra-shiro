-- apply this file to cassandra DB to login with credentials from bootstrap LDIF file
-- warning: do this before switching authenticator implementation!
CREATE ROLE IF NOT EXISTS cass_admin WITH superuser = TRUE AND login = TRUE ;
CREATE ROLE IF NOT EXISTS extern1 WITH superuser = FALSE AND login = TRUE ;
CREATE ROLE IF NOT EXISTS other_user WITH superuser = FALSE AND login = TRUE ;

