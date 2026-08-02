declare module "zen/src/sign.js" {
  interface SignKeyPair {
    priv: string;
    curve?: string;
  }
  function sign(data: string, pair: SignKeyPair): Promise<string>;
  export default sign;
}

declare module "zen/src/verify.js" {
  interface VerifyKeyPair {
    pub: string;
    curve?: string;
  }
  function verify(data: string, pair: VerifyKeyPair | string): Promise<string>;
  export default verify;
}

declare module "zen/src/pair.js" {
  interface ZenKeyPair {
    pub: string;
    priv: string;
    epub: string;
    epriv: string;
  }
  function pair(): Promise<ZenKeyPair>;
  export default pair;
}
