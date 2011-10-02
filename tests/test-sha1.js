Sha1Test = TestCase('Sha1Test');

Sha1Test.prototype.testSha1 = function() {
    assertEquals("a9993e364706816aba3e25717850c26c9cd0d89d", hex_sha1('abc'));
};
