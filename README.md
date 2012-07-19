# mod_shorturl #

mod_shorturl is mongoDB base shorturl module for Apache HTTPD Server.

## Dependencies ##

* [mongoDB driver](http://dl.mongodb.org/dl/cxx-driver)

## Build ##

    % ./autogen.sh (or autoreconf -i)
    % ./configure [OPTION]
    % make
    % make install

### Build Options ###

mongoDB path.

* --with-mongo=PATH  [default=/usr/include]
* --with-mongo-lib=PATH  [default=no]

apache path.

* --with-apxs=PATH  [default=yes]
* --with-apr=PATH  [default=yes]

## Configration ##

httpd.conf:

    LoadModule shorturl_module modules/mod_shorturl.so
    <IfModule shorturl_module>
        MongoHost    localhost
        MongoPort    27017
        MongoTimeout 5
        MongoHost         localhost:27017
        # MongoHost         localhost:27017,localhost:27018,localhost:27019
        # MongoReplicaSet   test
        MongoDb             test
        MongoCollection     test
        # MongoAuthDb       admin
        # MongoAuthUser     user
        # MongoAuthPassword pass
    </IfModule>
    <Location /shorturl>
        SetHandler shorturl
    </Location>

## Setting ##

mongoDB:

    test> db.insert( { _id:"localhost/github", url:"http://github.com" } )
