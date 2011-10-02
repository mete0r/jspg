OpenPGP.BigInt = {
  create: function (bits, octets) {
    var bn=1;
    var r=[0], rn=0;
    var bit_in_octet=256;
    var octet;
    var octet_pos = octets.length;

    for(var n=0; n<bits; n++) {
      bit_in_octet <<= 1;
      if(bit_in_octet > 255) {
          bit_in_octet=1;
          octet = octets.charCodeAt(--octet_pos);
      }
      if(bn > bm) {
          bn=1;
          r[++rn]=0;
      }
      if(octet & bit_in_octet) {
          r[rn]|=bn;
      }
      bn<<=1;
    }
    r.n_bits = bits;
    r.n_octets = octets.length;
    return r;
  },
  encode: b2mpi,
  mul: bmul,
  mod: bmod,
  modexp: bmodexp,
  n_octets: function(bigint) {
    return bigint.n_octets;
  },
};
