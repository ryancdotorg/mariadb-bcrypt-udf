This is a set [user-defined functions](https://mariadb.com/kb/en/mariadb/user-defined-functions/) for [MariaDB](https://mariadb.com/).


It should work with MySQL with trivial modifications (change the include directory in the Makefile), but I have not tested this.

I'm using Openwall's [bcrypt implementation](http://www.openwall.com/crypt/), and some of the interfacing code was cribbed from
[Ricardo Garcia's](https://github.com/rg3) [bcrypt wrapper library](https://github.com/rg3/bcrypt).

Two functions are defined:

BCRYPT\_HASH(password, work\_factor)
------------------------------------
Returns a bcrypt `$2b$` hash for the provided password with a random salt and
the given work factor. If `work\_factor` is NULL, a sensible default
(currently 12) will be used. The `work\_factor` is clamped to be between 4 and
16 inclusive - if you want to allow smaller or larger work factors, change
`WORKFACTOR\_MIN` and/or `WORKFACTOR\_MAX` in `bcrypt.c`. Returns NULL on error.

Note that passwords containing null bytes are not supported and will cause an
error.

BCRYPT\_CHECK(password, hash)
-----------------------------
Returns 1 if the supplied password matches the hash, 0 if not. Returns NULL on
error.

Note that passwords containing null bytes are not supported and will cause an
error.

Installing
-----------
Only tested on Debian Jessie with MariaDB 10.0. Please do not file issues about
this not compiling on other platforms without including a patch.

    sudo apt-get install libmariadb-client-lgpl-dev build-essential
    make clean all
    sudo cp bcrypt.so /usr/lib/mysql/plugin/
    mysql -e "drop function if exists bcrypt_hash;  create function bcrypt_hash  returns string  soname 'bcrypt.so';"
    mysql -e "drop function if exists bcrypt_check; create function bcrypt_check returns integer soname 'bcrypt.so';"

WARNING
=======
Since bcrypt deliberately uses a lot of CPU time, these functions could be used
to DoS your database server. Use with caution. The work factor supplied by the
hash is *NOT* currently limited and may take *minutes* to run with large values.
