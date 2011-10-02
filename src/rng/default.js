var entropy = new Entropy();
OpenPGP.RNG = new SimpleRNG(entropy);
