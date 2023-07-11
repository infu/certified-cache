
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

actor Self {
  type HttpRequest = HTTP.HttpRequest;
  type HttpResponse = HTTP.HttpResponse;


  stable var cert_store = CertifiedHttp.init();

  var cert = CertifiedHttp.CertifiedHttp(
      cert_store
  );

  public shared func upload(key:Text, val:Blob) {
      cert.put(key, val);
  };

  public shared func delete(key:Text) {
      cert.delete(key);
  };


};
