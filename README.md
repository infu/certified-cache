# Certified HTTP

Designed to answer HTTP cert calls

Started from certified-cache fork.

Similar to how certified-cache works, but it's stable and doesn't store the files, only their certificates.

You handle file storage yourself.

```mo

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

```

It also uses https://mops.one/sha2 which allows it to certify larger files without running out of instructions
