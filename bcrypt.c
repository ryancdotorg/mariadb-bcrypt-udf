/* bcrypt user-defined functions for MariaDB
 *
 * Written in 2016 by Ryan Castellucci
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along
 * with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>. */

#include <my_global.h>
#include <my_sys.h>
#include <m_string.h>
#include <mysql.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "crypt_blowfish/ow-crypt.h"

#define BCRYPT_HASHSIZE	(64)
#define RANDBYTES (16)

#define PASS_MAXLEN (128)

#define WORKFACTOR_MIN (4)
#define WORKFACTOR_MAX (16)
#define WORKFACTOR_DEFAULT (12)

/* Parts of this code copied or adapted from https://github.com/rg3/bcrypt
 * which was written by Ricardo Garcia <r@rg3.name> and released CC0. */

static int try_close(int fd) {
  int ret;
  for (;;) {
    errno = 0;
    ret = close(fd);
    if (ret == -1 && errno == EINTR)
      continue;
    break;
  }
  return ret;
}

static int try_read(int fd, char *out, size_t count) {
  size_t total;
  ssize_t partial;

  total = 0;
  while (total < count)
  {
    for (;;) {
      errno = 0;
      partial = read(fd, out + total, count - total);
      if (partial == -1 && errno == EINTR)
        continue;
      break;
    }

    if (partial < 1)
      return -1;

    total += partial;
  }

  return 0;
}

/*
 * This is a best effort implementation. Nothing prevents a compiler from
 * optimizing this function and making it vulnerable to timing attacks, but
 * this method is commonly used in crypto libraries like NaCl.
 *
 * Return value is zero if both strings are equal and nonzero otherwise.
*/
static int timing_safe_strcmp(const char *str1, const char *str2)
{
  const unsigned char *u1;
  const unsigned char *u2;
  int ret;
  int i;

  int len1 = strlen(str1);
  int len2 = strlen(str2);

  /* In our context both strings should always have the same length
   * because they will be hashed passwords. */
  if (len1 != len2)
    return 1;

  /* Force unsigned for bitwise operations. */
  u1 = (const unsigned char *)str1;
  u2 = (const unsigned char *)str2;

  ret = 0;
  for (i = 0; i < len1; ++i)
    ret |= (u1[i] ^ u2[i]);

  return ret;
}

/* copy mysql string to c string, adding null terminator, and returning error
 * if the mysql string contains any null bytes */
int my_str_to_c_str(char *dst, size_t dst_sz, char *src, size_t src_sz) {
  size_t i;

  if ((src_sz + 1) > dst_sz || dst == NULL || src == NULL) {
    return -1;
  }

  for (i = 0; i < src_sz; ++i) {
    if (src[i] == 0) { return -1; }
    dst[i] = src[i];
  }

  dst[i] = 0; 

  return 0;
}

my_bool bcrypt_hash_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (args->arg_count != 2) {
    strcpy(message,"BCRYPT_HASH() requires a string and an integer parameter");
    return 1;
  }
  args->arg_type[0]=STRING_RESULT;
  args->arg_type[1]=INT_RESULT;
  initid->max_length=(BCRYPT_HASHSIZE);
  initid->maybe_null=1;
  initid->const_item=0;
  return 0;
}

char *bcrypt_hash(UDF_INIT *initid, UDF_ARGS *args, char *res, unsigned long *len, char *is_null, char *err) {
  int ret, fd;

  char *aux;
  char randb[RANDBYTES];

  char pass[PASS_MAXLEN+1];
  char salt[BCRYPT_HASHSIZE];

  long long workfactor;

  /* password */
  if (!args->args[0]) {
    *is_null = 1;
    return 0;
  } else {
    if ((ret = my_str_to_c_str(pass, sizeof(pass), args->args[0], args->lengths[0])) != 0) {
      *is_null = 1;
      return 0;
    }
  }

  /* work factor */
  if (args->args[1]) {
    workfactor = *(long long*) args->args[1];
  } else {
    workfactor = WORKFACTOR_DEFAULT;
  }
  
  if (workfactor < WORKFACTOR_MIN) {
    workfactor = WORKFACTOR_MIN;
  } else if (workfactor > WORKFACTOR_MAX) {
    workfactor = WORKFACTOR_MAX;
  }

  /* start salt generation */
  if ((fd = open("/dev/urandom", O_RDONLY)) < 0) {
    *is_null = 1;
    return 0;
  }

  if (try_read(fd, randb, RANDBYTES) != 0) {
    try_close(fd);
    *is_null = 1;
    return 0;
  }

  if (try_close(fd) != 0) {
    *is_null = 1;
    return 0;
  }

  if ((aux = crypt_gensalt_rn("$2b$", workfactor, randb, RANDBYTES, salt, BCRYPT_HASHSIZE)) == NULL) {
    *is_null = 1;
    return 0;    
  }
  /* end salt generation */

  /* compute password hash */
  if ((aux = crypt_rn(pass, salt, res, BCRYPT_HASHSIZE)) == NULL) {
    *is_null = 1;
    return 0;
  }

  *len = strlen(res);
  return res;
}

my_bool bcrypt_check_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (args->arg_count != 2) {
    strcpy(message,"BCRYPT_CHECK() requires two string parameters");
    return 1;
  }
  args->arg_type[0]=STRING_RESULT;
  args->arg_type[1]=STRING_RESULT;
  initid->max_length=(BCRYPT_HASHSIZE);
  initid->maybe_null=1;
  initid->const_item=0;
  return 0;
}

long long bcrypt_check(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *err) {
  int ret;

  char *aux;
  char chk_hash[BCRYPT_HASHSIZE];

  char pass[PASS_MAXLEN+1];
  char hash[BCRYPT_HASHSIZE];

  /* password */
  if (!args->args[0]) {
    *is_null = 1;
    return 0;
  } else {
    if ((ret = my_str_to_c_str(pass, sizeof(pass), args->args[0], args->lengths[0])) != 0) {
      *is_null = 1;
      return 0;
    }
  }

  /* hash */
  if (!args->args[1]) {
    *is_null = 1;
    return 0;
  } else {
    if ((ret = my_str_to_c_str(hash, sizeof(hash), args->args[1], args->lengths[1])) != 0) {
      *is_null = 1;
      return 0;
    }
  }
  

  /* compute password hash */
  if ((aux = crypt_rn(pass, hash, chk_hash, BCRYPT_HASHSIZE)) == NULL) {
    *is_null = 1;
    return 0;
  }

  ret = timing_safe_strcmp(hash, chk_hash);

  if (ret == 0) {
    return 1;
  } else if (ret > 0) {
    return 0;
  } else {
    *is_null = 1;
    return 0;
  }
}
