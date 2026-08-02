import Zen from '@akaoio/zen';
async function run() {
  const SEA = Zen.SEA;
  console.log("SEA:", !!SEA);
  const pair = await SEA.pair();
  console.log("Pair:", Object.keys(pair));
  const enc = await SEA.encrypt(pair, "mypassword");
  console.log("Encrypted:", typeof enc);
  const dec = await SEA.decrypt(enc, "mypassword");
  console.log("Decrypted:", dec.pub === pair.pub);
}
run().catch(console.error);
