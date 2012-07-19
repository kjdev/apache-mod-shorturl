
ACLOCAL_AMFLAGS = -I m4

moddir = @APACHE_MODULEDIR@
mod_LTLIBRARIES = mod_shorturl.la

mod_shorturl_la_SOURCES = mod_shorturl.cpp
mod_shorturl_la_CFLAGS = @APACHE_CFLAGS@ @APACHE_INCLUDES@ @MONGO_INCLUDES@
mod_shorturl_la_CPPFLAGS = @APACHE_CPPFLAGS@ @APACHE_INCLUDES@ @MONGO_INCLUDES@
mod_shorturl_la_LDFLAGS = -avoid-version -module @APACHE_LDFLAGS@ @MONGO_LDFLAGS@
mod_shorturl_la_LIBS = @APACHE_LIBS@ @MONGO_LIBS@
