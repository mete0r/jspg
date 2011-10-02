OpenPGP.AES = {
  Cipher: function(key) {
    var kex = new keyExpansion(key);
    return {
      blocksize: 16,
      encrypt_block: function(block) {
        return AESencrypt(block, kex);
      },
    };
  },
};
