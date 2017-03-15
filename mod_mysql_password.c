/*
 * ProFTPD: mod_mysql_passorwd -- A simple helper module to provide
 * the same old MySQL Password authenentication as SQLAuthTypes
 */

#include "conf.h"
#include "privs.h"
#include "mod_sql.h"

#define MOD_MYSQL_PASSWORD_VERSION "1.0"


#if defined(HAVE_OPENSSL) || defined(PR_USE_OPENSSL)
# include <openssl/evp.h>
#endif


#if defined(HAVE_OPENSSL) || defined(PR_USE_OPENSSL)

static modret_t *sql_auth_mysql_password(cmd_rec *cmd, const char *plaintext,
    const char *ciphertext) {

  /* The ciphertext argument is a combined digest name and hashed value, of
   * the form "{digest}hash".
   */

  EVP_MD_CTX *md_ctx;
  const EVP_MD *md;

  unsigned char buf[EVP_MAX_MD_SIZE*2+1], mdval_tmp[EVP_MAX_MD_SIZE], mdval_final[EVP_MAX_MD_SIZE];
  unsigned int mdlen;

  char *hashvalue;   /* ptr to hashed value we're comparing to */
  int i;

  if (ciphertext[0] != '*') {
    sql_log(DEBUG_WARN, "%s", "syntax error in password hash");
    return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
  }

  hashvalue = (char*)ciphertext + 1;

  OpenSSL_add_all_digests();

  md = EVP_get_digestbyname("sha1");
  if (md == NULL) {
    sql_log(DEBUG_WARN, "sha1 digest is not supported");
    return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
  }

  md_ctx = EVP_MD_CTX_create();
  EVP_DigestInit(md_ctx, md);
  EVP_DigestUpdate(md_ctx, plaintext, strlen(plaintext));
  EVP_DigestFinal(md_ctx, mdval_tmp, &mdlen);
  EVP_MD_CTX_destroy(md_ctx);

  md_ctx = EVP_MD_CTX_create();
  EVP_DigestInit(md_ctx, md);
  EVP_DigestUpdate(md_ctx, mdval_tmp, mdlen);
  EVP_DigestFinal(md_ctx, mdval_final, &mdlen);
  EVP_MD_CTX_destroy(md_ctx);

  memset(buf, '\0', sizeof(buf));

  for(i = 0; i < mdlen; i++)
    sprintf((char*)buf + (i * 2), "%02X", mdval_final[i]);

  if (strcmp((char *) buf, hashvalue) == 0) {
    return PR_HANDLED(cmd);
  }

  return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
}
#else

#error OpenSSL support is mandatory

#endif


#if defined(PR_SHARED_MODULE)
static void sql_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_mysql_password.c", (const char *) event_data) == 0) {
    (void) sql_unregister_authtype("MysqlPassword");
  }
}
#endif

static int mysql_password_init(void) {
#if defined(PR_SHARED_MODULE)
  pr_event_register(&sql_module, "core.module-unload", sql_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */

  (void) sql_register_authtype("MysqlPassword", sql_auth_mysql_password);

  return 0;
}



module mysql_password_module = {

  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "mysql_password",

  /* Module configuration directive table */
  NULL,

  /* Module command handler table */
  NULL,

  /* Module auth handler table */
  NULL,

  /* Module initialization */
  mysql_password_init,

  /* Session initialization */
  NULL,

  /* Module version */
  MOD_MYSQL_PASSWORD_VERSION
};

