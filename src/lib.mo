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
import BTree "mo:stableheapbtreemap/BTree";
import Text "mo:base/Text";
import Timer "mo:base/Timer";

module {

  public type CertifiedHttpMemory = CertTree.Store;

  public func init() : CertifiedHttpMemory {
    CertTree.newStore();
  };

  type ChunkedCallback = {
    max_chunks: Nat;
    done: ([Blob]) -> ();
    var last_chunk: Nat;
    chunks: [var ?Blob];
    sha: SHA256.Digest;
    timerId : Timer.TimerId;
  };

  public class CertifiedHttp(
    cert_store: CertifiedHttpMemory,
  ) {

    let ct = CertTree.Ops(cert_store);
    let csm = CanisterSigs.Manager(ct, null);

    let chunked = BTree.init<Text, ChunkedCallback>(?8);

    public func chunkedSend(key:Text, chunk_id: Nat, content: Blob) : () {
      switch(BTree.get(chunked, Text.compare, key)) {
        case (?st) {
          st.last_chunk := chunk_id;
          st.chunks[chunk_id] := ?content;
          st.sha.writeBlob(content);

          if (st.last_chunk + 1 != chunk_id) {
            Debug.trap("chunkedSend: Uploading non sequentail chunks not supported");
            chunkedClear(key);
            return ();
          };

          if (chunk_id + 1 == st.max_chunks) {
            let hash = st.sha.sum();
            putHash(key, hash);

            chunkedClear(key);

            let fchunks = Array.tabulate<Blob>(st.max_chunks, func(i) : Blob {
                let ?b = st.chunks[i] else Debug.trap("chunkedSend: missing chunk");
                b;
            });

            st.done(fchunks);
          };
        };
        case (null) {
          Debug.trap("chunkedSend without chunkedStart");
        }
      };
    };

    public func chunkedStart(key:Text, chunks: Nat, content:Blob, done: ([Blob]) -> () ) : () {
      if (chunks == 1) {
        done([content]);
        return;
      };

      chunkedClear(key);

      let st:ChunkedCallback = {
        max_chunks = chunks;
        chunks = Array.init<?Blob>(chunks, null);
        done;
        var last_chunk = 0;
        sha = SHA256.Digest(#sha256);
        timerId = Timer.setTimer(#seconds(chunks * 3), func() : async () { // timeouts after 3 x chunks seconds
          chunkedClear(key);
        });
      };

      ignore BTree.insert(chunked, Text.compare, key, st);
    };

    private func chunkedClear(key:Text) : () {
      switch(BTree.get(chunked, Text.compare, key)) {
        case (?st) {
          Timer.cancelTimer(st.timerId);
          ignore BTree.delete(chunked, Text.compare, key);
        };
        case (null) ();
      };
    };

    public func putHash(key : Text, value : Blob) : () {
      ct.put(["http_assets", Text.encodeUtf8(key)], value);
      ct.setCertifiedData();
    };

    public func put(key : Text, value : Blob) : () {
      // insert into CertTree
      ct.put(["http_assets", Text.encodeUtf8(key)], SHA256.fromBlob(#sha256, value));
      ct.setCertifiedData();
    };
    public func delete(key : Text) : () {
      // remove from CertTree
      ct.delete(["http_assets", Text.encodeUtf8(key)]);
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

    public func certificationHeader(url : Text) : HTTP.HeaderField {
      let witness = ct.reveal(["http_assets", Text.encodeUtf8(url)]);
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
