import CertTree "mo:ic-certification/CertTree";
import CanisterSigs "mo:ic-certification/CanisterSigs";
import CertifiedData "mo:base/CertifiedData";
import SHA256 "mo:sha2/Sha256";
import Hash "mo:base/Hash";
import Iter "mo:base/Iter";
import Time "mo:base/Time";
import Option "mo:base/Option";
import Debug "mo:base/Debug";
import HTTP "Http";
import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Nat8 "mo:base/Nat8";
import Array "mo:base/Array";

module {

  public type CertifiedHttpMemory = CertTree.Store;

  public func init() : CertifiedHttpMemory {
    CertTree.newStore();
  };

  public class CertifiedHttp<K>(
    cert_store: CertifiedHttpMemory,
    keyToBlob : K -> Blob,
  ) {

    let ct = CertTree.Ops(cert_store);
    let csm = CanisterSigs.Manager(ct, null);

    public func putHash(key : K, value : Blob) : () {
      ct.put(["http_assets", keyToBlob(key)], value);
      ct.setCertifiedData();
    };

    public func put(key : K, value : Blob) : () {
      // insert into CertTree
      ct.put(["http_assets", keyToBlob(key)], SHA256.fromBlob(#sha256, value));
      ct.setCertifiedData();
    };
    public func delete(key : K) : () {
      // remove from CertTree
      ct.delete(["http_assets", keyToBlob(key)]);
      ct.setCertifiedData();
    };

    /* Expiry Logic */
    public func pruneAll() : () {
      csm.pruneAll();
    };

    /* Certification Logic */
    private func base64(b : Blob) : Text {
      let base64_chars : [Text] = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "+", "/"];
      let bytes = Blob.toArray(b);
      let pad_len = if (bytes.size() % 3 == 0) { 0 } else {
        3 - bytes.size() % 3 : Nat;
      };
      let buf = Buffer.fromArray<Nat8>(bytes);
      for (_ in Iter.range(0, pad_len -1)) { buf.add(0) };
      let padded_bytes = Buffer.toArray(buf);
      var out = "";
      for (j in Iter.range(1, padded_bytes.size() / 3)) {
        let i = j - 1 : Nat; // annoying inclusive upper bound in Iter.range
        let b1 = padded_bytes[3 * i];
        let b2 = padded_bytes[3 * i +1];
        let b3 = padded_bytes[3 * i +2];
        let c1 = (b1 >> 2) & 63;
        let c2 = (b1 << 4 | b2 >> 4) & 63;
        let c3 = (b2 << 2 | b3 >> 6) & 63;
        let c4 = (b3) & 63;
        out #= base64_chars[Nat8.toNat(c1)] # base64_chars[Nat8.toNat(c2)] # (if (3 * i +1 >= bytes.size()) { "=" } else { base64_chars[Nat8.toNat(c3)] }) # (if (3 * i +2 >= bytes.size()) { "=" } else { base64_chars[Nat8.toNat(c4)] });
      };
      return out;
    };

    public func certificationHeader(url : K) : HTTP.HeaderField {
      let witness = ct.reveal(["http_assets", keyToBlob(url)]);
      let encoded = ct.encodeWitness(witness);
      let cert = switch (CertifiedData.getCertificate()) {
        case (?c) c;
        case null {
          // unfortunately, we cannot do
          //   throw Error.reject("getCertificate failed. Call this as a query call!")
          // here, because this function isn’t async, but we can’t make it async
          // because it is called from a query (and it would do the wrong thing) :-(
          //
          // So just return erronous data instead
          "getCertificate failed. Call this as a query call!" : Blob;
        };
      };
      return (
        "ic-certificate",
        "certificate=:" # base64(cert) # ":, " # "tree=:" # base64(encoded) # ":",
      );
    };

  };


};
