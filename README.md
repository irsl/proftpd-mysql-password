# proftpd-mysql-password
Support for MySQL PASSWORD() in ProFTPd's SQLAuthTypes

With recent versions of MySQL, the hashing algorithm used by the PASSWORD() function has changed, breaking Proftpds Backend SQLAuthType. (Details: http://www.proftpd.org/docs/howto/SQL.html @ Question "I've upgraded to MySQL 5.7, and now I am unable to login using my MySQL users.")

This is a quick workaround, providing the original SHA-1^2 algorithm natively. After patching Proftpd, you can use `MysqlPassword` in `SQLAuthTypes` (even if you are using a non-MySQL `SQLBackend`!)

No MySQL libraries are needed. ProFTPd must be compiled with OpenSSL support enabled.
