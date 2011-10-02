/*
 * JsPG: a javascript OpenPGP implementation
 *
 * Copyright 2011 mete0r
 *
 * Copyright 2005 Herbert Hanewinkel, www.haneWIN.de
 * version 1.1, check www.haneWIN.de for the latest version

 * This software is provided as-is, without express or implied warranty.  
 * Permission to use, copy, modify, distribute or sell this software, with or
 * without fee, for any purpose and by any individual or organization, is hereby
 * granted, provided that the above copyright notice and this paragraph appear 
 * in all copies. Distribution as a part of an application or binary must
 * include the above copyright notice in the documentation and/or other materials
 * provided with the application or distribution.
 */

OpenPGP = {
  version: '0.0',

  TAG_PUBLIC_KEY_ENCRYPTED_SESSION_KEY: 1,
  TAG_SIGNATURE: 2,
  TAG_PUBLIC_KEY: 6,
  TAG_SYMMETRICALLY_ENCRYPTED_DATA: 9,
  TAG_LITERAL_DATA: 11,
  TAG_USER_ID: 13,
  TAG_PUBLIC_SUBKEY: 14,

  ALGO_PK_RSA: 1,
  ALGO_PK_RSA_ENCRYPT: 2, // deprecated
  ALGO_PK_RSA_SIGN: 3, // deprecated
  ALGO_PK_ELGAMAL: 16,
  ALGO_PK_DSA: 17,

  ALGO_SYMM_PLAIN_TEXT: 0,
  ALGO_SYMM_IDEA: 1,
  ALGO_SYMM_TRIPLE_DES: 2,
  ALGO_SYMM_CAST5: 3,
  ALGO_SYMM_BLOWFISH: 4,
  ALGO_SYMM_AES128: 7,
  ALGO_SYMM_AES192: 8,
  ALGO_SYMM_AES256: 9,
  ALGO_SYMM_TWOFISH: 10,
};

OpenPGP.dataio = {
  dumps_int8: function(n) {
    return String.fromCharCode(n & 0xff);
  },
  dumps_int16be: function (n) {
    return OpenPGP.dataio.dumps_int8(n >> 8) + OpenPGP.dataio.dumps_int8(n);
  },
  dumps_int24be: function(n) {
    return OpenPGP.dataio.dumps_int8(n >> 16) + OpenPGP.dataio.dumps_int16be(n);
  },
  dumps_int32be: function (n) {
    return OpenPGP.dataio.dumps_int16be(n >> 16) + OpenPGP.dataio.dumps_int16be(n);
  },
};

OpenPGP.Hex = function() {
  this.encode = function (s) {
    var result = '';
    for(var i=0; i<s.length; i++)
    {
      c = s.charCodeAt(i);
      result += ((c<16) ? "0" : "") + c.toString(16);
    }
    return result;
  }
  this.decode = function (hex) {
    var r='';
    if (hex.length%2) hex+='0';

    for(var i = 0; i<hex.length; i += 2) {
      r += OpenPGP.dataio.dumps_int8(parseInt(hex.slice(i, i+2), 16));
    }
    return r;
  };
};

OpenPGP.hex = new OpenPGP.Hex();

OpenPGP.crc24 = function (data) {
  var crc = 0xb704ce;

  for(var n=0; n<data.length;n++) {
    crc ^= (data.charCodeAt(n)&255)<<16;
    for(i=0;i<8;i++) {
      crc <<= 1;
      if(crc & 0x1000000) crc^=0x1864cfb;
    }
  }
  return OpenPGP.dataio.dumps_int24be(crc);
};

OpenPGP.Radix64 = function() {
  var base64s = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  this.decode = function (t) {
    var c, n;
    var r='', s=0, a=0;
    var tl=t.length;

    for(n=0; n<tl; n++) {
      c = base64s.indexOf(t.charAt(n));
      if (c >= 0) {
        if(s) r+=OpenPGP.dataio.dumps_int8(a | (c>>(6-s))&255);
        s=(s+2)&7;
        a=(c<<s)&255;
      }
    }
    return r;
  };
  this.encode = function (t) {
   var a, c, n;
   var r='', l=0, s=0;
   var tl=t.length;

   for(n=0; n<tl; n++)
   {
    c=t.charCodeAt(n);
    if(s == 0)
    {
     r+=base64s.charAt((c>>2)&63);
     a=(c&3)<<4;
    }
    else if(s==1)
    {
     r+=base64s.charAt((a|(c>>4)&15));
     a=(c&15)<<2;
    }
    else if(s==2)
    {
     r+=base64s.charAt(a|((c>>6)&3));
     l+=1;
     if((l%60)==0) r+="\n";
     r+=base64s.charAt(c&63);
    }
    l+=1;
    if((l%60)==0) r+="\n";

    s+=1;
    if(s==3) s=0;  
   }
   if(s>0)
   {
    r+=base64s.charAt(a);
    l+=1;
    if((l%60)==0) r+="\n";
    r+='=';
    l+=1;
   }
   if(s==1)
   {
    if((l%60)==0) r+="\n";
    r+='=';
   }

   return r;
  };
};

OpenPGP.radix64 = new OpenPGP.Radix64();

OpenPGP.Stream = function (s) {
  this.s = s;
  this.i = 0;
  this.read_int8 = function() {
    return this.s.charCodeAt(this.i++);
  };
  this.read_int16be = function() {
    return (s.charCodeAt(this.i++)<<8) + s.charCodeAt(this.i++);
  }
  this.read_int32be = function() {
    return (s.charCodeAt(this.i++)<<24) + (s.charCodeAt(this.i++)<<16) + (s.charCodeAt(this.i++)<<8) + s.charCodeAt(this.i++)
  }
  this.read = function(len) {
    var data = s.substr(this.i, len);
    this.i += data.length;
    return data;
  }
  this.read_bits = function(bits) {
    var bytes = Math.floor((bits + 7)/8);
    return this.read(bytes);
  }
  this.read_mpi = function() {
    var bits = this.read_int16be();
    var data = this.read_bits(bits);
    return OpenPGP.BigInt.create(bits, data);
  }
  return this;
}

OpenPGP.RNG = {
  random: function(n_octets) {
    throw 'OpenPGP.RNG.random() is not implemented';
  },
};

OpenPGP.SHA1 = {
  sha1: function(s) {
    throw 'OpenPGP.SHA1.sha1() is not implemented';
  },
};

OpenPGP.AES = {
  Cipher: function(key) {
    throw 'OpenPGP.AES.Cipher() is not implemented';
    var cipher = {
      blocksize: 16,
      encrypt_block: function(block) {
        throw 'OpenPGP.AES.Cipher.encrypt_block() is not implemented';
      },
    };
    return cipher;
  },
};

OpenPGP.BigInt = {
  create: function() {
    throw 'OpenPGP.BigInt.create() is not implemented';
  },
  encode: function() {
    throw 'OpenPGP.BigInt.encode() is not implemented';
  },
  mul: function() {
    throw 'OpenPGP.BigInt.mul() is not implemented';
  },
  mod: function() {
    throw 'OpenPGP.BigInt.mod() is not implemented';
  },
  modexp: function() {
    throw 'OpenPGP.BigInt.modexp() is not implemented';
  },
  n_octets: function(bigint) {
    throw 'OpenPGP.BigInt.n_octets() is not implemented';
  },
};

OpenPGP.PublicKeyAlgorithm = {};

OpenPGP.PublicKeyAlgorithm.id_map = {};
OpenPGP.PublicKeyAlgorithm.from_id = function(algo_id) {
  var algo = OpenPGP.PublicKeyAlgorithm.id_map[algo_id];
  if ( ! algo) {
    throw 'unsupported public key algorithm id '+algo_id;
  }
  return algo;
};

OpenPGP.PublicKeyAlgorithm.id_map[OpenPGP.ALGO_PK_RSA] =
OpenPGP.PublicKeyAlgorithm.id_map[OpenPGP.ALGO_PK_RSA_ENCRYPT] =
OpenPGP.PublicKeyAlgorithm.id_map[OpenPGP.ALGO_PK_RSA_SIGN] =
OpenPGP.PublicKeyAlgorithm.RSA = {
  name: 'RSA',
  read_fields_from_pubkey_packet: function(stream) {
    var fields = {};
    fields.modulus = fields.n = stream.read_mpi();
    fields.exponent = fields.e = stream.read_mpi();
    fields.key_modulus = fields.modulus;
    return fields;
  },
  encrypt: function(fields, m) {
    var mod = fields.modulus;
    var exp = fields.exponent;
    return OpenPGP.BigInt.encode(OpenPGP.BigInt.modexp(m, exp, mod));
  },
};

OpenPGP.PublicKeyAlgorithm.id_map[OpenPGP.ALGO_PK_ELGAMAL] =
OpenPGP.PublicKeyAlgorithm.Elgamal = {
  name: 'Elgamal',
  read_fields_from_pubkey_packet: function(stream) {
    var fields = {};
    fields.prime = fields.p = stream.read_mpi();
    fields.group_generator = fields.g = stream.read_mpi();
    fields.public_key_value = fields.y = stream.read_mpi();
    fields.key_modulus = fields.prime;
    return fields;
  },
  encrypt: function(fields, m) {
    var p = fields.prime;
    //var el = [3,5,9,17,513,2049,4097,8193];
    var exp = [9]; //el[randomByte()&7];

    var grp = fields.group_generator;
    var y   = fields.public_key_value;
    var c1 = OpenPGP.BigInt.modexp(grp, exp, p);
    var c2 = OpenPGP.BigInt.mod(OpenPGP.BigInt.mul(m, OpenPGP.BigInt.modexp(y, exp, p)), p);

     return OpenPGP.BigInt.encode(c1)+OpenPGP.BigInt.encode(c2);
  },
};

OpenPGP.PublicKeyAlgorithm.id_map[OpenPGP.ALGO_PK_DSA] =
OpenPGP.PublicKeyAlgorithm.DSA = {
  name: 'DSA',
  read_fields_from_pubkey_packet: function(stream) {
    var fields = {};
    fields.prime = fields.p = stream.read_mpi();
    fields.group_order = fields.q = stream.read_mpi();
    fields.group_generator = fields.g = stream.read_mpi();
    fields.public_key_value = fields.y = stream.read_mpi();
    fields.key_modulus = fields.prime;
    return fields;
  },
  encrypt: function(fields, m) {
    throw 'DSA not supported';
  },
};

OpenPGP.Packet = {};

OpenPGP.Packet.tag_map = {};

OpenPGP.Packet.from_tag = function(tag) {
  var packet = OpenPGP.Packet.tag_map[tag];
  if ( ! packet) {
    throw 'unsupported packet tag '+tag;
  }
  return packet;
};

OpenPGP.Packet.load_header = function(stream) {
  var tag = stream.read_int8();

  if ((tag & 128) == 0) {
    return null;
  }

  var packet = {};

  packet.new_format = tag & 64;

  if (packet.new_format) {
    packet.tag = tag & 63;

    packet.bodyLen = 0;
    packet.partial = true;
  } else {
    packet.tag = (tag >> 2) & 15;
    length_type = tag & 3;

    switch (length_type) {
      case 0:
        packet.bodyLen = stream.read_int8();
        break;
      case 1:
        packet.bodyLen = stream.read_int16be();
        break;
      case 2:
        packet.bodyLen = stream.read_int32be();
        break;
      case 3:
        packet.bodyLen = undefined; // indeterminate length
        break;
    }
  }

  return packet;
};

OpenPGP.Packet.load_new_length_header = function(packet, stream) {
  var octet = stream.read_int8();

  if (octet <= 191) {
    packet.partial = false;
    return octet;
  } else if (octet <= 223) {
    packet.partial = false;
    return ((octet - 192) << 8) + (stream.read_int8()) + 192;
  } else if (octet == 255) {
    packet.partial = false;
    return stream.read_int32be();
  } else if (224 <= octet && octet < 255) {
    packet.partial = true;
    return 1 << (octet & 0x1f);
  } else {
    throw 'can\'t parse packet';
  }
};

OpenPGP.Packet.load_body = function (packet, stream) {
  var body_octets = stream.read(packet.bodyLen);
  while (packet.partial) {
    var partialBodyLen = OpenPGP.Packet.load_new_length_header(packet, stream);
    body_octets += stream.read(partialBodyLen);
    packet.bodyLen += partialBodyLen;
  }
  return body_octets;
};

OpenPGP.Packet.load = function (stream) {
  var packet = OpenPGP.Packet.load_header(stream);
  if (packet == null) {
    return null;
  }
  var body_octets = OpenPGP.Packet.load_body(packet, stream);
  var body_type = OpenPGP.Packet.from_tag(packet.tag);
  body_type.parse_body(packet, body_octets);
  return packet;
}

OpenPGP.Packet.read_packets = function (stream) {
  var packets = [];
  while (true) {
    var packet = OpenPGP.Packet.load(stream);
    if (packet != null) {
      packets.push(packet);
    } else {
      return packets;
    }
  }
};

OpenPGP.Packet.dumps_header = function(tag, len) {
  var tag_octet = 0x80 | (tag << 2);
  if (len <= 0xff) {
    // length-type: one-octet
    return OpenPGP.dataio.dumps_int8(tag_octet | 0x0) + OpenPGP.dataio.dumps_int8(len);
  } else if (len <= 0xffff) {
    // length-type: two-octet
    return OpenPGP.dataio.dumps_int8(tag_octet | 0x1) + OpenPGP.dataio.dumps_int16be(len);
  } else if (len <= 0xffffffff) {
    // length-type: four-octet
    return OpenPGP.dataio.dumps_int8(tag_octet | 0x2) + OpenPGP.dataio.dumps_int32be(len);
  } else {
    // length-type: indeterminate
    return OpenPGP.dataio.dumps_int8(tag_octet | 0x3);
  }
};

OpenPGP.Packet.dumps = function(tag, payload) {
  var len = payload.length;
  return OpenPGP.Packet.dumps_header(tag, len) + payload;
};

OpenPGP.Packet.tag_map[OpenPGP.TAG_PUBLIC_KEY] =
OpenPGP.Packet.tag_map[OpenPGP.TAG_PUBLIC_SUBKEY] =
OpenPGP.PublicKeyPacket = {};

OpenPGP.PublicKeyPacket.parse_body = function (packet, octets) {
  var stream = new OpenPGP.Stream(octets);

  var vers = packet.vers = stream.read_int8();
  var time = packet.timestamp = stream.read_int32be();

  if (vers==2 || vers==3) {
    var valid = stream.read_int16be();
  }

  var algo_id = packet.algorithm_id = stream.read_int8();
  var algo = packet.algorithm = OpenPGP.PublicKeyAlgorithm.from_id(algo_id);

  // Algorithm-Specific Fields
  packet.algo_fields = algo.read_fields_from_pubkey_packet(stream);

  // Fingerprint and Key ID
  if (vers==4) {
    // the RFC specifies this as 0x99, followed by two-octet packet length,
    // followed by entire packet starting with the version field.
    // the Key ID and fingerprint of a subkey are calculated in the
    // same way as for a primary key, including the 0x99 as the first octet
    // (even though this is not a valid packet ID for a public subkey).
    var pkt = OpenPGP.Packet.dumps(OpenPGP.TAG_PUBLIC_KEY, octets);
    var fp = OpenPGP.SHA1.sha1(pkt);
    packet.fp=OpenPGP.hex.encode(fp);
    packet.keyid=OpenPGP.hex.encode(fp.substr(fp.length-8,8));
  } else if (vers==3) {
    // The fingerprint of a V3 key is formed by hashing the body (but not
    // the two-octet length) of the MPIs that form the key material (public
    // modulus n, followed by exponent e) with MD5. Note that both V3 keys
    // and MD5 are deprecated.
    packet.fp = '';
    packet.keyid = OpenPGP.hex.encode(packet.modulus.substr(packet.modulus.length-8, 8));
  } else {
    packet.fp = '';
    packet.keyid = '';
  }
  return packet;
};

OpenPGP.Packet.tag_map[OpenPGP.TAG_USER_ID] =
OpenPGP.UserIDPacket = {};

OpenPGP.UserIDPacket.parse_body = function (packet, octets) {
  packet.userid = octets;
  return packet;
}

OpenPGP.Packet.tag_map[OpenPGP.TAG_SIGNATURE] =
OpenPGP.SignaturePacket = {};

OpenPGP.SignaturePacket.parse_body = function (packet, octets) {
  // TODO
  return packet;
}

// OpenPGP Literal Data Packet (Tag 11)
OpenPGP.Packet.tag_map[OpenPGP.TAG_LITERAL_DATA] =
OpenPGP.LiteralData = {};

OpenPGP.LiteralData.dumps = function (text) {
  if(text.indexOf('\r\n') == -1) {
    text = text.replace(/\n/g,'\r\n');
  }
  payload = ''
    +'t'
    +OpenPGP.dataio.dumps_int8(4)
    +'file\0\0\0\0'
    +text;
  return OpenPGP.Packet.dumps(OpenPGP.TAG_LITERAL_DATA, payload);
};

// OpenPGP Symmetrically Encrypted Data Packet (Tag 9)
OpenPGP.Packet.tag_map[OpenPGP.TAG_SYMMETRICALLY_ENCRYPTED_DATA] =
OpenPGP.SymmetricallyEncryptedData = {};

OpenPGP.SymmetricallyEncryptedData.dumps = function(cipher, packet_data) {
  var enc = OpenPGP.CFB(cipher, packet_data);
  return OpenPGP.Packet.dumps(OpenPGP.TAG_SYMMETRICALLY_ENCRYPTED_DATA, enc);
};

// OpenPGP Public Key Encryted Session Key packet (Tag 1)
OpenPGP.Packet.tag_map[OpenPGP.TAG_PUBLIC_KEY_ENCRYPTED_SESSION_KEY] =
OpenPGP.PublicKeyEncryptedSessionKey = {};

OpenPGP.PublicKeyEncryptedSessionKey.dumps = function (pubkey, symm_algo_id, sessionkey) {
  var keyid = OpenPGP.hex.decode(pubkey.keyid);

  var k = OpenPGP.BigInt.n_octets(pubkey.algo_fields.key_modulus);
  var m = OpenPGP.PublicKeyEncryptedSessionKey.create_m(k, symm_algo_id, sessionkey);
  var encrypted = pubkey.algorithm.encrypt(pubkey.algo_fields, m);
  var payload = OpenPGP.dataio.dumps_int8(3)+keyid+OpenPGP.dataio.dumps_int8(pubkey.algorithm_id)+encrypted;
  return OpenPGP.Packet.dumps(OpenPGP.TAG_PUBLIC_KEY_ENCRYPTED_SESSION_KEY, payload);
};

OpenPGP.PublicKeyEncryptedSessionKey.create_m = function (k, symm_algo_id, sessionkey) {
  /*
  The value "m" in the above formulas is derived from the session key
  as follows.  First, the session key is prefixed with a one-octet
  algorithm identifier that specifies the symmetric encryption
  algorithm used to encrypt the following Symmetrically Encrypted Data
  Packet.  Then a two-octet checksum is appended, which is equal to the
  sum of the preceding session key octets, not including the algorithm
  identifier, modulo 65536.  This value is then encoded as described in
  PKCS#1 block encoding EME-PKCS1-v1_5 in Section 7.2.1 of [RFC3447] to
  form the "m" value used in the formulas above.  See Section 13.1 of
  this document for notes on OpenPGP's use of PKCS#1.
  */

  var checksum = 0;
  for(var i = 0; i < sessionkey.length; i++) {
    checksum += sessionkey.charCodeAt(i);
  }
  checksum &= 0xffff;

  var M = OpenPGP.dataio.dumps_int8(symm_algo_id)
        + sessionkey
        + OpenPGP.dataio.dumps_int16be(checksum);
  var m_data = OpenPGP.EME_PKCS1_v1_5_encode(k, M);
  var m_bits = m_data.length * 8;
  return OpenPGP.BigInt.create(m_bits, m_data);
};

OpenPGP.EME_PKCS1_v1_5_encode = function (k, M) {
  function random_nonzero(len) {
    var octets = '';
    while (octets.length < len) {
        var data = OpenPGP.RNG.random(len - octets.length);
        for (var i=0;i<data.length;++i) {
            var c = data[i];
            if (c == '\0') {
                continue;
            }
            octets += c;
        }
    }
    return octets;
  }
  var mLen = M.length;
  var PS = random_nonzero(k - mLen - 3);   // add random padding (non-zero)
  return '\0' + OpenPGP.dataio.dumps_int8(2) + PS + '\0' + M;
}

OpenPGP.PublicKeyMessage = {};
OpenPGP.PublicKeyMessage.unarmor = function (text) {
  var i= text.indexOf('-----BEGIN PGP PUBLIC KEY BLOCK-----');

  if(i == -1) {
    throw ('No PGP Public Key Block');
  }
 
  var a=text.indexOf('\n\n',i);
  if(a>0) a += 2;
  else
  {
    a = text.indexOf('\n\r\n', i);
    if(a>0) a += 3;
  }

  var e=text.indexOf('\n=',i); 
  if(a>0 && e>0) {
    return OpenPGP.radix64.decode(text.slice(a,e));
  } else {
    throw('Invalid PGP Public Key Block');
  }
}

OpenPGP.PublicKeyMessage.load_octetstream = function(stream) {
  var pubkey = {};
  var packets = OpenPGP.Packet.read_packets(stream);

  var primarykey;
  var subkeys = [];
  var fp;
  var keyid;
  var userid;

  for (var i in packets) {
    var packet = packets[i];
    switch (packet.tag) {
    case OpenPGP.TAG_PUBLIC_KEY:
      primarykey = packet;
      break;
    case OpenPGP.TAG_PUBLIC_SUBKEY:
      subkeys.push(packet);
      break;
    case OpenPGP.TAG_USER_ID:
      userid = packet;
      break;
    };
  }

  if (primarykey == null && subkeys.length == 0) {
    throw "No public key packet found."; 
  }

  pubkey.packets = packets;
  pubkey.primarykey = primarykey;
  pubkey.subkeys = subkeys;
  pubkey.userid = userid.userid;

  pubkey.vers = primarykey.vers;
  pubkey.fp = primarykey.fp;
  pubkey.keyid = primarykey.keyid.substr(primarykey.keyid.length - 8, 8);
  pubkey.algorithm_id = subkeys[0].algorithm_id;
  pubkey.algorithm = subkeys[0].algorithm;
  return pubkey;
};

OpenPGP.PublicKeyMessage.load_octets = function (octets) {
  var stream = new OpenPGP.Stream(octets);
  return OpenPGP.PublicKeyMessage.load_octetstream(stream);
};

OpenPGP.PublicKeyMessage.load_armored = function(armored) {
  var bin = OpenPGP.PublicKeyMessage.unarmor(armored);
  return OpenPGP.PublicKeyMessage.load_octets(bin);
};

OpenPGP.CFB = function (cipher, text) {
  var blocksize = cipher.blocksize;         // bytes per data block
  var i, n;
  var len = text.length;
  var iblock = new Array(blocksize)
  var rblock = OpenPGP.RNG.random(blocksize);
  var ct = new Array(blocksize+2);

  var ciphertext = '';

  // append zero padding
  if (len%blocksize) {
    for (i=(len%blocksize); i<blocksize; i++) { 
      text+='\0';
    }
  }

  // set up initialisation vector and random byte vector
  for(i=0; i<blocksize; i++) {
    iblock[i] = 0;
  }

  iblock = cipher.encrypt_block(iblock);
  for(i=0; i<blocksize; i++) {
    ct[i] = (iblock[i] ^= rblock[i]);
  }

  iblock = cipher.encrypt_block(iblock);
  // append check octets
  ct[blocksize]   = (iblock[0] ^ rblock[blocksize-2]);
  ct[blocksize+1] = (iblock[1] ^ rblock[blocksize-1]);

  for(i = 0; i < blocksize+2; i++) {
    ciphertext += OpenPGP.dataio.dumps_int8(ct[i]);
  }

  // resync
  iblock = ct.slice(2, blocksize+2);

  for(n = 0; n < text.length; n+=blocksize) {
    iblock = cipher.encrypt_block(iblock);
    for(i = 0; i < blocksize; i++) {
      iblock[i] ^= text.charCodeAt(n+i);
      ciphertext += OpenPGP.dataio.dumps_int8(iblock[i]);
    }
  }
  return ciphertext.substr(0,len+blocksize+2);
};

OpenPGP.SymmetricAlgorithm = {};

OpenPGP.SymmetricAlgorithm.id_map = {};

OpenPGP.SymmetricAlgorithm.from_id = function(algo_id) {
  return OpenPGP.SymmetricAlgorithm.id_map[algo_id];
  throw 'unsupported symmetric algorithm id '+algo_id;
};

OpenPGP.SymmetricAlgorithm.AES = function(algo_id, bits) {
  var algo = {};
  algo.id = algo_id;
  algo.key_bits = bits;
  algo.key_size = bits / 8;
  algo.cipher = function(key) {
    return OpenPGP.AES.Cipher(key);
  }
  return algo;
};

OpenPGP.SymmetricAlgorithm.id_map[OpenPGP.ALGO_SYMM_AES128] =
OpenPGP.SymmetricAlgorithm.AES128 =
OpenPGP.SymmetricAlgorithm.AES(OpenPGP.ALGO_SYMM_AES128, 128);

OpenPGP.SymmetricAlgorithm.id_map[OpenPGP.ALGO_SYMM_AES192] =
OpenPGP.SymmetricAlgorithm.AES192 =
OpenPGP.SymmetricAlgorithm.AES(OpenPGP.ALGO_SYMM_AES192, 192);

OpenPGP.SymmetricAlgorithm.id_map[OpenPGP.ALGO_SYMM_AES256] =
OpenPGP.SymmetricAlgorithm.AES256 =
OpenPGP.SymmetricAlgorithm.AES(OpenPGP.ALGO_SYMM_AES256, 256);

OpenPGP.Message = {};
OpenPGP.Message.armor = function(message) {
  var armored = '';
  armored += '-----BEGIN PGP MESSAGE-----\n';
  armored += 'Version: JsPG v'+OpenPGP.version+'\n';
  armored += '\n';
  armored += OpenPGP.radix64.encode(message)+'\n';
  armored += '='+OpenPGP.radix64.encode(OpenPGP.crc24(message))+'\n';
  armored += '-----END PGP MESSAGE-----\n';
  return armored;
};

OpenPGP.encrypt = function (pubkey, symm_algo_id, plaintext) {
  var symm_algo_id = OpenPGP.ALGO_SYMM_AES256;
  var symm_algo = OpenPGP.SymmetricAlgorithm.from_id(symm_algo_id);

  var ld = OpenPGP.LiteralData.dumps(plaintext);

  var sesskey = OpenPGP.RNG.random(symm_algo.key_size);
  var cipher = symm_algo.cipher(sesskey);
  var sed = OpenPGP.SymmetricallyEncryptedData.dumps(cipher, ld);

  var sesskey_enckey = pubkey.subkeys[0];
  var pkesk = OpenPGP.PublicKeyEncryptedSessionKey.dumps(sesskey_enckey, symm_algo_id, sesskey);

  var message = pkesk + sed;
  return OpenPGP.Message.armor(message);
};
