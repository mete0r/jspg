/* OpenPGP encryption using RSA/AES
 * Copyright 2005-2006 Herbert Hanewinkel, www.haneWIN.de
 * version 2.0, check www.haneWIN.de for the latest version

 * This software is provided as-is, without express or implied warranty.  
 * Permission to use, copy, modify, distribute or sell this software, with or
 * without fee, for any purpose and by any individual or organization, is hereby
 * granted, provided that the above copyright notice and this paragraph appear 
 * in all copies. Distribution as a part of an application or binary must
 * include the above copyright notice in the documentation and/or other
 * materials provided with the application or distribution.
 */

/* We need an unpredictable session key of 128 bits ( = 2^128 possible keys).
 * If we generate the session key with a PRNG from a small seed we get only
 * a small number of session keys, e.g. 4 bytes seed => 2^32 keys, a brute
 * force attack could try all 2^32 session keys. 
 * (see RFC 1750 - Randomness Recommendations for Security.)
 *
 * Sources for randomness in Javascript are limited.
 * We have load, exec time, seed from random(), mouse movement events
 * and the timing from key press events.
 * But even here we have restrictions.
 * - A mailer will add a timestamp to the encrypted message, therefore
 *   only the msecs from the clock can be seen as unpredictable.
 * - Because the Windows timer is still based on the old DOS timer,
 *   the msecs jump under Windows in 18.2 msecs steps.
 * - Only a few bits from mouse mouvement event coordinates are unpredictable,
 *   if the same buttons are clicked on the screen.
 */

function SimpleRNG(entropy) {

  function randomString(len, nozero) {
    var r = '';
    var t = entropy.timeByte(); // exec time

    while (len > 0) {
      t ^= entropy.getByte();
      if(t==0 && nozero) {
        continue;
      }
      --len;
      r += String.fromCharCode(t);
    }
    return r;
  }

  this.random = function(len) {
    return randomString(len, false);
  };

  this.random_nonzero = function(len) {
    return randomString(len, true);
  };
}
