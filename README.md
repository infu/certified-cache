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

Advanced - hashing chunks when you receive them

```mo
          switch(cmd) {
                case(#store({key; val})) {
                    assert(val.chunks > 0);

                    if (val.chunks == 1) {

                        // Insert the file in your store (Use your own store)
                        assets.db.insert({
                            id= key;
                            chunks= val.chunks;
                            content= [val.content];
                            content_encoding= val.content_encoding;
                            content_type = val.content_type;
                        });
                        cert.put(key, val.content);
                        return ();
                    };
                    // Allows uploads of large certified files.
                    cert.chunkedStart(key, val.chunks, func(content: [Blob]) {
                        // when done

                        // Insert the file in your store (Use your own store)
                        assets.db.insert({
                            id= key;
                            chunks= val.chunks;
                            content= content;
                            content_encoding= val.content_encoding;
                            content_type = val.content_type;
                        });
                    });

                };

                 case(#store_chunk(x)) {
                    cert.chunkedSend(x.key, x.chunk_id, x.content);
                };
          }
```
