# proftpd-mysql-password
Support for MySQL PASSWORD() in Proftpd's SQLAuthTypes

With recent versions of MySQL, the hashing algorithm used by the PASSWORD() function has changed, breaking Proftpds Backend SQLAuthType. (Details: http://www.proftpd.org/docs/howto/SQL.html)

This is a quick workaround. After patching Proftpd, you can `MysqlPassword` in `SQLAuthTypes` (even if you are using a non-MySQL `SQLBackend`!)

No MySQL libraries are needed. Porftpd must be compiled with OpenSSL support enabled.
