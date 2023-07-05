import FHM "mo:StableHashMap/FunctionalStableHashMap";
import SHA256 "mo:motoko-sha/SHA256";
import CertTree "mo:ic-certification/CertTree";
import CanisterSigs "mo:ic-certification/CanisterSigs";
import CertifiedData "mo:base/CertifiedData";
import HTTP "./Http";
import Iter "mo:base/Iter";
import Blob "mo:base/Blob";
import Option "mo:base/Option";
import Time "mo:base/Time";
import Text "mo:base/Text";
import Debug "mo:base/Debug";
import Prelude "mo:base/Prelude";
import Principal "mo:base/Principal";
import Buffer "mo:base/Buffer";
import Nat8 "mo:base/Nat8";
import CertifiedHttp "lib";
import Int "mo:base/Int";
import HashMap "mo:StableHashMap/ClassStableHashMap";

actor Self {
  type HttpRequest = HTTP.HttpRequest;
  type HttpResponse = HTTP.HttpResponse;

  var files = HashMap.StableHashMap<Text, Blob>(0, Text.equal, Text.hash); // You can make this stable too using FuncStableHashMap

  stable var cert_store = CertifiedHttp.init();

  var cert = CertifiedHttp.CertifiedHttp<Text>(
      cert_store,
      Text.encodeUtf8,
  );

  public shared func upload(key:Text, val:Blob) {
      files.put(key, val);
      cert.put(key, val);
  };

  public shared func delete(key:Text) {
      files.delete(key);
      cert.delete(key);
  };

  public query func http_request(req : HttpRequest) : async HttpResponse {
    let ?body = files.get(req.url) else return e404;

    {
      status_code : Nat16 = 200;
      headers = [("content-type", "text/html"), cert.certificationHeader(req.url)];
      body = body;
      streaming_strategy = null;
      upgrade = null;
    };

  };

  let e404:HttpResponse = {
          status_code = 404;
          headers = [];
          body = "Error 404":Blob;
          streaming_strategy = null;
          upgrade = ?false;
        };

};
