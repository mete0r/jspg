OpenPGPTest = TestCase('OpenPGPTest');

OpenPGPTest.prototype.setUp = function() {
    entropy.startCollect();
}

OpenPGPTest.prototype.tearDown = function() {
    entropy.endCollect();
}

OpenPGPTest.prototype.testCreateNoKeyBlock = function() {
    try {
	var key = OpenPGP.PublicKeyMessage.unarmor('');
    } catch (e) {
	assertEquals('No PGP Public Key Block', e);
    }
};

OpenPGPTest.prototype.testInvalidKeyBlock = function() {
    var s = '';
    s += '-----BEGIN PGP PUBLIC KEY BLOCK-----\n';
    s += 'Version: GnuPG v1.4.10 (GNU/Linux)\n';
    try {
	var key = OpenPGP.PublicKeyMessage.unarmor(s);
    } catch (e) {
	assertEquals('Invalid PGP Public Key Block', e);
    }

    s += '\n';
    try {
	var key = OpenPGP.PublicKeyMessage.unarmor(s);
    } catch (e) {
	assertEquals('Invalid PGP Public Key Block', e);
    }

    s += 'mQENBE4oQRYBCADYRKL410PAm+nIF8qA7FpfgmGpj7aXbOjJyzPom4k5kxqsEkZ4\n';
    s += 'k3IR3iznewPSGRv3832luRzwmUUkJjk71hRVbwtXSDlns4i8nTHfNxQPwiZXgmN+\n';
    try {
	var key = OpenPGP.PublicKeyMessage.unarmor(s);
    } catch (e) {
	assertEquals('Invalid PGP Public Key Block', e);
    }
};

OpenPGPTest.prototype.testStream = function() {
    var stream;

    stream = new OpenPGP.Stream('ABCDE');
    assertEquals('AB', stream.read(2));
    assertEquals('CDE', stream.read(undefined));

    stream = new OpenPGP.Stream('ABCDE');
    assertEquals('AB', stream.read(2));
    assertEquals('CDE', stream.read());

    stream = new OpenPGP.Stream('ABCDE');
    assertEquals('AB', stream.read(2));
    assertEquals('CDE', stream.read(100));

    stream = new OpenPGP.Stream('ABCDE');
    assertEquals(65, stream.read_int8());
    assertEquals(0x42434445, stream.read_int32be());
};

OpenPGPTest.prototype.test_load_new_length_header = function() {
    load_new_length_header = OpenPGP.Packet.load_new_length_header;
    var octets = '\x64';
    var stream = new OpenPGP.Stream(octets);
    var packet = {partial:0};

    assertEquals(100, load_new_length_header(packet, stream));
    assertFalse(packet.partial);

    stream = new OpenPGP.Stream('\xC5\xFB');
    assertEquals(1723, load_new_length_header(packet, stream));
    assertFalse(packet.partial);

    stream = new OpenPGP.Stream('\xFF\x00\x01\x86\xA0');
    assertEquals(100000, load_new_length_header(packet, stream));
    assertFalse(packet.partial);

    stream = new OpenPGP.Stream('\xEF\xE1\xE0\xF0\xC5\xDD');
    assertEquals(32768, load_new_length_header(packet, stream));
    assertTrue(packet.partial);
    assertEquals(2, load_new_length_header(packet, stream));
    assertTrue(packet.partial);
    assertEquals(1, load_new_length_header(packet, stream));
    assertTrue(packet.partial);
    assertEquals(65536, load_new_length_header(packet, stream));
    assertTrue(packet.partial);
    assertEquals(1693, load_new_length_header(packet, stream));
    assertFalse(packet.partial);
};

OpenPGPTest.prototype.test_dumps_header = function() {
    var dumps_header = OpenPGP.Packet.dumps_header;
    assertEquals('\x84\x00', dumps_header(1, 0));
    assertEquals('\xA4\x00', dumps_header(9, 0));
    assertEquals('\xAC\x00', dumps_header(11, 0));
};

OpenPGPTest.prototype.testPackets = function() {
    var s = '';
    s += '-----BEGIN PGP PUBLIC KEY BLOCK-----\n';
    s += 'Version: GnuPG v1.4.10 (GNU/Linux)\n';
    s += '\n';
    s += 'mQENBE4oQRYBCADYRKL410PAm+nIF8qA7FpfgmGpj7aXbOjJyzPom4k5kxqsEkZ4\n';
    s += 'k3IR3iznewPSGRv3832luRzwmUUkJjk71hRVbwtXSDlns4i8nTHfNxQPwiZXgmN+\n';
    s += 'OJhaDy3jmZlCh6HaJrCI3tA+x3jFLhmWMZFivEfbOUCVBh5DNy29zVe6eXJm/SeM\n';
    s += 'pvYL7+6bDnClDGQJk3kqUwKVkH+hV1ujZrZH0IQDIdrKeKl4TRHq60+xnPKhjUI9\n';
    s += 'XmtYPIszCeEX0m5XcPS/SpW5/OFK6leNzvZDjl954LzZEvmPWUOBdg23wLW/aoCz\n';
    s += 'U6sMDFs8/5L/67lhMm9AJvthpe5h/A70tuJbABEBAAG0BnNhbXBsZYkBOAQTAQIA\n';
    s += 'IgUCTihBFgIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQV1hKDS5GO7AB\n';
    s += 'nAgApw5LlCnv8Yt7vfXGOE8Qr15O76UXE3U1wZcoaWbPwTCZXh8XrPrWN2fmVM2U\n';
    s += 'yCGW1Ucg28gpBKkCPWmdsvYv7FSmxvespwVtMVFIIyW8x8AOJQLl8zPh8lRlHuWG\n';
    s += 'aIyAZLCRvTBRZ0pBpCWbi+GEfmaFRi9PzOv3rk2z+HXmIxeB9f7UiWdpMzStLix4\n';
    s += 'bTNmJV2p9IYk1J6wVwEk/s4FKZTqAIv1ZP9+Ydj5YpKpShNfvO5/RdzkOe8BH1n9\n';
    s += 'y58WPtvIUfWwCU0N+oAHxWNXAIUaANe5Kh3jb5OfrPHWprIgMKgXvlj4tqUVajY7\n';
    s += 'aeor8yvhipqJExTK1H/+mJ73xLkBDQROKEEWAQgAl6ibsuUAyxckPkFdeHFF3CRa\n';
    s += 'lxBVkEHBJE0hfqVY8dI+wnvmiToHpRfrxttdBRiKtR2+i01neYur7VgYtyukn06m\n';
    s += 'qJ2URQOtPXAjAr9jhubtbVl/pzg4Rq9LP++Ttl/giPuNcyXX/qACejPVbHaz4Ck/\n';
    s += 'r8pU2Gg1jRB8fvqd29yTzxaxjaN2/PtXLvL+Y0YYciH6NChZWXTqa6NVDZpIXvHZ\n';
    s += 'q0PwT97Zc9DjXF830ZBvgrbLQTcuyBtdvro9ltdfkMF58Lz6Q+SpxmhdNX5u0ONF\n';
    s += 'my3jNrpdv6+MWdarjyW23S3i0ACFsmysIvg7grMU1RnYNBxIRUrrqm+DuwLZnwAR\n';
    s += 'AQABiQEfBBgBAgAJBQJOKEEWAhsMAAoJEFdYSg0uRjuwpYYH/iN1ipqsTEVxoPtz\n';
    s += 'RI+fac5MBUS+PqCXG/vUfWO0mpgkTQ0jYbGDqVPXb0xA/BjX+kub3sPora6QCiD3\n';
    s += 'elc/xMHEiOB5ZzreeD/6iiWVF895yklzwZVNnJkXnGuFrf9+eqdsxXukvXSSyTIW\n';
    s += '6TosBOCWTTKEhcQLk4/gi5mGmAsaPq650+nma3MM3MDIzFuMA+JqcoQq+37GM/6y\n';
    s += '7qXsFW8757VAMeYmTYSewJCSMgBaEujN73diV9HOcoRmfdCqSw8JjpKi+fyiQDf/\n';
    s += 'qFMg61E1jLzME/1+KXnt/tTgKJWpOCgC3hb9CouCY/AE0r8Ydb26o9y4M7/5kFxp\n';
    s += 'ZO1NaRw=\n';
    s += '=bM+q\n';
    s += '-----END PGP PUBLIC KEY BLOCK-----\n';

    var keyblock = OpenPGP.PublicKeyMessage.unarmor(s);
    var stream = new OpenPGP.Stream(keyblock);
    var packets = OpenPGP.Packet.read_packets(stream);
    assertEquals(5, packets.length);

    assertEquals(OpenPGP.TAG_PUBLIC_KEY, packets[0].tag);
    var pubkey_packet = packets[0];
    assertEquals(4, pubkey_packet.vers);
    assertEquals(OpenPGP.ALGO_PK_RSA, pubkey_packet.algorithm_id);
    assertEquals(OpenPGP.PublicKeyAlgorithm.RSA, pubkey_packet.algorithm);
    assertEquals(2048, pubkey_packet.algo_fields.n.n_bits);
    assertEquals(17, pubkey_packet.algo_fields.e.n_bits);
    assertEquals('57584a0d2e463bb0', pubkey_packet.keyid);
    assertEquals('310fef5ba967d55308fe5b2557584a0d2e463bb0', pubkey_packet.fp);

    assertEquals(OpenPGP.TAG_USER_ID, packets[1].tag);
    var userid_packet = packets[1];
    assertEquals('sample', userid_packet.userid);

    assertEquals(OpenPGP.TAG_SIGNATURE, packets[2].tag);

    assertEquals(OpenPGP.TAG_PUBLIC_SUBKEY, packets[3].tag);
    var pubsubkey_packet = packets[3];
    assertEquals(4, pubsubkey_packet.vers);
    assertEquals(OpenPGP.ALGO_PK_RSA, pubsubkey_packet.algorithm_id);
    assertEquals(OpenPGP.PublicKeyAlgorithm.RSA, pubsubkey_packet.algorithm);
    assertEquals(2048, pubsubkey_packet.algo_fields.modulus.n_bits);
    var modulus_data = OpenPGP.hex.decode('97a89bb2e500cb17243e415d787145dc245a9710559041c1244d217ea558f1d23ec27be6893a07a517ebc6db5d05188ab51dbe8b4d67798babed5818b72ba49f4ea6a89d944503ad3d702302bf6386e6ed6d597fa7383846af4b3fef93b65fe088fb8d7325d7fea0027a33d56c76b3e0293fafca54d868358d107c7efa9ddbdc93cf16b18da376fcfb572ef2fe6346187221fa3428595974ea6ba3550d9a485ef1d9ab43f04fded973d0e35c5f37d1906f82b6cb41372ec81b5dbeba3d96d75f90c179f0bcfa43e4a9c6685d357e6ed0e3459b2de336ba5dbfaf8c59d6ab8f25b6dd2de2d00085b26cac22f83b82b314d519d8341c48454aebaa6f83bb02d99f');
    //assertEquals(modulus_data, pubsubkey_packet.algo_fields.modulus.data);
    assertEquals(17, pubsubkey_packet.algo_fields.e.n_bits);
    assertEquals([0x010001], pubsubkey_packet.algo_fields.exponent);
    assertEquals('7bda65fbae604328', pubsubkey_packet.keyid);
    assertEquals('e7032e4ff19efcb0bd60d18b7bda65fbae604328', pubsubkey_packet.fp);

    assertEquals(OpenPGP.TAG_SIGNATURE, packets[4].tag);

    assertEquals([0x010001], OpenPGP.BigInt.create(17, OpenPGP.hex.decode('010001')));
    assertEquals([0x8123456, 0xF], OpenPGP.BigInt.create(32, OpenPGP.hex.decode('F8123456')));
}

OpenPGPTest.prototype.testPublicKey = function() {
    var s = '';
    s += '-----BEGIN PGP PUBLIC KEY BLOCK-----\n';
    s += 'Version: GnuPG v1.4.10 (GNU/Linux)\n';
    s += '\n';
    s += 'mQENBE4oQRYBCADYRKL410PAm+nIF8qA7FpfgmGpj7aXbOjJyzPom4k5kxqsEkZ4\n';
    s += 'k3IR3iznewPSGRv3832luRzwmUUkJjk71hRVbwtXSDlns4i8nTHfNxQPwiZXgmN+\n';
    s += 'OJhaDy3jmZlCh6HaJrCI3tA+x3jFLhmWMZFivEfbOUCVBh5DNy29zVe6eXJm/SeM\n';
    s += 'pvYL7+6bDnClDGQJk3kqUwKVkH+hV1ujZrZH0IQDIdrKeKl4TRHq60+xnPKhjUI9\n';
    s += 'XmtYPIszCeEX0m5XcPS/SpW5/OFK6leNzvZDjl954LzZEvmPWUOBdg23wLW/aoCz\n';
    s += 'U6sMDFs8/5L/67lhMm9AJvthpe5h/A70tuJbABEBAAG0BnNhbXBsZYkBOAQTAQIA\n';
    s += 'IgUCTihBFgIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQV1hKDS5GO7AB\n';
    s += 'nAgApw5LlCnv8Yt7vfXGOE8Qr15O76UXE3U1wZcoaWbPwTCZXh8XrPrWN2fmVM2U\n';
    s += 'yCGW1Ucg28gpBKkCPWmdsvYv7FSmxvespwVtMVFIIyW8x8AOJQLl8zPh8lRlHuWG\n';
    s += 'aIyAZLCRvTBRZ0pBpCWbi+GEfmaFRi9PzOv3rk2z+HXmIxeB9f7UiWdpMzStLix4\n';
    s += 'bTNmJV2p9IYk1J6wVwEk/s4FKZTqAIv1ZP9+Ydj5YpKpShNfvO5/RdzkOe8BH1n9\n';
    s += 'y58WPtvIUfWwCU0N+oAHxWNXAIUaANe5Kh3jb5OfrPHWprIgMKgXvlj4tqUVajY7\n';
    s += 'aeor8yvhipqJExTK1H/+mJ73xLkBDQROKEEWAQgAl6ibsuUAyxckPkFdeHFF3CRa\n';
    s += 'lxBVkEHBJE0hfqVY8dI+wnvmiToHpRfrxttdBRiKtR2+i01neYur7VgYtyukn06m\n';
    s += 'qJ2URQOtPXAjAr9jhubtbVl/pzg4Rq9LP++Ttl/giPuNcyXX/qACejPVbHaz4Ck/\n';
    s += 'r8pU2Gg1jRB8fvqd29yTzxaxjaN2/PtXLvL+Y0YYciH6NChZWXTqa6NVDZpIXvHZ\n';
    s += 'q0PwT97Zc9DjXF830ZBvgrbLQTcuyBtdvro9ltdfkMF58Lz6Q+SpxmhdNX5u0ONF\n';
    s += 'my3jNrpdv6+MWdarjyW23S3i0ACFsmysIvg7grMU1RnYNBxIRUrrqm+DuwLZnwAR\n';
    s += 'AQABiQEfBBgBAgAJBQJOKEEWAhsMAAoJEFdYSg0uRjuwpYYH/iN1ipqsTEVxoPtz\n';
    s += 'RI+fac5MBUS+PqCXG/vUfWO0mpgkTQ0jYbGDqVPXb0xA/BjX+kub3sPora6QCiD3\n';
    s += 'elc/xMHEiOB5ZzreeD/6iiWVF895yklzwZVNnJkXnGuFrf9+eqdsxXukvXSSyTIW\n';
    s += '6TosBOCWTTKEhcQLk4/gi5mGmAsaPq650+nma3MM3MDIzFuMA+JqcoQq+37GM/6y\n';
    s += '7qXsFW8757VAMeYmTYSewJCSMgBaEujN73diV9HOcoRmfdCqSw8JjpKi+fyiQDf/\n';
    s += 'qFMg61E1jLzME/1+KXnt/tTgKJWpOCgC3hb9CouCY/AE0r8Ydb26o9y4M7/5kFxp\n';
    s += 'ZO1NaRw=\n';
    s += '=bM+q\n';
    s += '-----END PGP PUBLIC KEY BLOCK-----\n';

    var key = OpenPGP.PublicKeyMessage.load_armored(s);
    assertEquals(OpenPGP.ALGO_PK_RSA, key.algorithm_id);
    assertEquals(4, key.vers);
    assertEquals('sample', key.userid);
    assertEquals('2e463bb0', key.keyid);
    assertEquals('310fef5ba967d55308fe5b2557584a0d2e463bb0', key.fp);
}

OpenPGPTest.prototype.testSymmAlgorithmAES = function() {
    var algo_id = OpenPGP.ALGO_SYMM_AES256;
    var algo = OpenPGP.SymmetricAlgorithm.AES256;
    assertEquals(algo_id, algo.id);
    assertEquals(256, algo.key_bits);
    assertEquals(32, algo.key_size);

    assertEquals('function', typeof(algo.cipher));
};

OpenPGPTest.prototype.testEncrypt = function() {
    var s = '';
    s += '-----BEGIN PGP PUBLIC KEY BLOCK-----\n';
    s += 'Version: GnuPG v1.4.10 (GNU/Linux)\n';
    s += '\n';
    s += 'mQENBE4oQRYBCADYRKL410PAm+nIF8qA7FpfgmGpj7aXbOjJyzPom4k5kxqsEkZ4\n';
    s += 'k3IR3iznewPSGRv3832luRzwmUUkJjk71hRVbwtXSDlns4i8nTHfNxQPwiZXgmN+\n';
    s += 'OJhaDy3jmZlCh6HaJrCI3tA+x3jFLhmWMZFivEfbOUCVBh5DNy29zVe6eXJm/SeM\n';
    s += 'pvYL7+6bDnClDGQJk3kqUwKVkH+hV1ujZrZH0IQDIdrKeKl4TRHq60+xnPKhjUI9\n';
    s += 'XmtYPIszCeEX0m5XcPS/SpW5/OFK6leNzvZDjl954LzZEvmPWUOBdg23wLW/aoCz\n';
    s += 'U6sMDFs8/5L/67lhMm9AJvthpe5h/A70tuJbABEBAAG0BnNhbXBsZYkBOAQTAQIA\n';
    s += 'IgUCTihBFgIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQV1hKDS5GO7AB\n';
    s += 'nAgApw5LlCnv8Yt7vfXGOE8Qr15O76UXE3U1wZcoaWbPwTCZXh8XrPrWN2fmVM2U\n';
    s += 'yCGW1Ucg28gpBKkCPWmdsvYv7FSmxvespwVtMVFIIyW8x8AOJQLl8zPh8lRlHuWG\n';
    s += 'aIyAZLCRvTBRZ0pBpCWbi+GEfmaFRi9PzOv3rk2z+HXmIxeB9f7UiWdpMzStLix4\n';
    s += 'bTNmJV2p9IYk1J6wVwEk/s4FKZTqAIv1ZP9+Ydj5YpKpShNfvO5/RdzkOe8BH1n9\n';
    s += 'y58WPtvIUfWwCU0N+oAHxWNXAIUaANe5Kh3jb5OfrPHWprIgMKgXvlj4tqUVajY7\n';
    s += 'aeor8yvhipqJExTK1H/+mJ73xLkBDQROKEEWAQgAl6ibsuUAyxckPkFdeHFF3CRa\n';
    s += 'lxBVkEHBJE0hfqVY8dI+wnvmiToHpRfrxttdBRiKtR2+i01neYur7VgYtyukn06m\n';
    s += 'qJ2URQOtPXAjAr9jhubtbVl/pzg4Rq9LP++Ttl/giPuNcyXX/qACejPVbHaz4Ck/\n';
    s += 'r8pU2Gg1jRB8fvqd29yTzxaxjaN2/PtXLvL+Y0YYciH6NChZWXTqa6NVDZpIXvHZ\n';
    s += 'q0PwT97Zc9DjXF830ZBvgrbLQTcuyBtdvro9ltdfkMF58Lz6Q+SpxmhdNX5u0ONF\n';
    s += 'my3jNrpdv6+MWdarjyW23S3i0ACFsmysIvg7grMU1RnYNBxIRUrrqm+DuwLZnwAR\n';
    s += 'AQABiQEfBBgBAgAJBQJOKEEWAhsMAAoJEFdYSg0uRjuwpYYH/iN1ipqsTEVxoPtz\n';
    s += 'RI+fac5MBUS+PqCXG/vUfWO0mpgkTQ0jYbGDqVPXb0xA/BjX+kub3sPora6QCiD3\n';
    s += 'elc/xMHEiOB5ZzreeD/6iiWVF895yklzwZVNnJkXnGuFrf9+eqdsxXukvXSSyTIW\n';
    s += '6TosBOCWTTKEhcQLk4/gi5mGmAsaPq650+nma3MM3MDIzFuMA+JqcoQq+37GM/6y\n';
    s += '7qXsFW8757VAMeYmTYSewJCSMgBaEujN73diV9HOcoRmfdCqSw8JjpKi+fyiQDf/\n';
    s += 'qFMg61E1jLzME/1+KXnt/tTgKJWpOCgC3hb9CouCY/AE0r8Ydb26o9y4M7/5kFxp\n';
    s += 'ZO1NaRw=\n';
    s += '=bM+q\n';
    s += '-----END PGP PUBLIC KEY BLOCK-----\n';

    var key = OpenPGP.PublicKeyMessage.load_armored(s);
    assertEquals(OpenPGP.ALGO_PK_RSA, key.algorithm_id);
    assertEquals(4, key.vers);
    assertEquals('sample', key.userid);
    assertEquals('2e463bb0', key.keyid);
    assertEquals('310fef5ba967d55308fe5b2557584a0d2e463bb0', key.fp);

    var plaintext = '';
    plaintext += ' * This software is provided as-is, without express or implied warranty. \n'
    plaintext += ' * Permission to use, copy, modify, distribute or sell this software, with or\n'
    plaintext += ' * without fee, for any purpose and by any individual or organization, is hereby\n'
    plaintext += ' * granted, provided that the above copyright notice and this paragraph appear\n'
    plaintext += ' * in all copies. Distribution as a part of an application or binary must\n'
    plaintext += ' * include the above copyright notice in the documentation and/or other\n'
    plaintext += ' * materials provided with the application or distribution.\n'

    var encrypted = OpenPGP.encrypt(key, OpenPGP.ALGO_SYMM_AES256, plaintext);
    jstestdriver.console.log('\n'+encrypted);
}
