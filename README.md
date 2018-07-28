Installation
------------

This function assumes pgcrypto to be installed in a schema called `pgcrypto`.
If you don't have installed pgcrypto you can do so by running the following
command:

```
CREATE EXTENSION pgcrypto WITH SCHEMA pgcrypto;
```

If you have installed pgcrypto in another schema, adjust the script accordingly.

To install the PBKDF2 functions, run the following:

```
psql your_database < pbkdf2.pgsql
```

Documentation
-------------

`bytea pbkdf2.pbkdf2_hmac(password bytea, salt bytea, iterations integer, hash_name text, dklen integer DEFAULT NULL)`
implements the PBKDF2 with HMAC.

`text pbkdf2.hash(password text, salt bytea DEFAULT NULL, hash_name text DEFAULT 'sha256', iterations integer DEFAULT 150000, salt_length integer DEFAULT 18, dklen integer DEFAULT NULL)`
generates a combined hash in the form of `<algorithm>$<iterations>$<salt>$<hash>`.
If no salt is provided, a random salt will be generated consisting of a hex
string with `<salt_length>` characters.

`boolean pbkdf2.verify(password text, combined text)` verifies a password against a
combined hash as generated by `pbkdf2.hash`.

Examples
--------

```
database=# SELECT pbkdf2.hash('password');
                                         hash
--------------------------------------------------------------------------------------
 pbkdf2_sha256$150000$b0558c36c3dd6c840f$Mp1bj0sZaiv7OqGggaFhNFdjUKCc5S0lRZjaokwaWNg=
(1 row)
```

```
database=# SELECT pbkdf2.hash('password', 'salt');
                                  hash
------------------------------------------------------------------------
 pbkdf2_sha256$150000$salt$lcRD0EorXiBKLn89W9T5qAZ4Hg8dxn2CNfq6+bvgtMk=
(1 row)
```

```
database=# UPDATE auth_user SET password = pbkdf2.hash('password') WHERE username = 'user';
UPDATE 1
```

```
database=# SELECT pbkdf2.verify('password', password) FROM auth_user WHERE username = 'user';
 verify 
--------
 t
(1 row)
```