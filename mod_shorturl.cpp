/*
**  mod_shorturl.cpp -- Apache shorturl module
**
**  Then activate it in Apache's httpd.conf file:
**
**    # httpd.conf
**    LoadModule shorturl_module modules/mod_shorturl.so
**    <IfModule shorturl_module>
**      MongoHost         localhost:27017
**      # MongoHost         localhost:27017,localhost:27018,localhost:27019
**      # MongoReplicaSet   test
**      MongoDb             test
**      MongoCollection     test
**      # MongoAuthDb       admin
**      # MongoAuthUser     user
**      # MongoAuthPassword pass
**      # MongoTimeout      5
**    </IfModule>
**    <Location /shorturl>
**      SetHandler shorturl
**    </Location>
*/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

/* mongo */
#include "mongo/client/dbclient.h"

/* httpd */
#ifdef __cplusplus
extern "C" {
#endif
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_log.h"
#include "util_script.h"
#include "ap_config.h"
#include "apr_strings.h"
#ifdef __cplusplus
}
#endif

/* log */
#ifdef AP_SHORTURL_DEBUG_LOG_LEVEL
#define SHORTURL_DEBUG_LOG_LEVEL AP_SHORTURL_DEBUG_LOG_LEVEL
#else
#define SHORTURL_DEBUG_LOG_LEVEL APLOG_DEBUG
#endif

#define _RERR(r, format, args...)                                       \
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0,                            \
                  r, "[SHORTURL] %s(%d): "format, __FILE__, __LINE__, ##args)
#define _SERR(s, format, args...)                                       \
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0,                             \
                 s, "[SHORTURL] %s(%d): "format, __FILE__, __LINE__, ##args)
#define _PERR(p, format, args...)                                       \
    ap_log_perror(APLOG_MARK, APLOG_CRIT, 0,                            \
                  p, "[SHORTURL] %s(%d): "format, __FILE__, __LINE__, ##args)

#define _RDEBUG(r, format, args...)                                     \
    ap_log_rerror(APLOG_MARK, SHORTURL_DEBUG_LOG_LEVEL, 0,              \
                  r, "[SHORTURL_DEBUG] %s(%d): "format,                 \
                  __FILE__, __LINE__, ##args)
#define _SDEBUG(s, format, args...)                                     \
    ap_log_error(APLOG_MARK, SHORTURL_DEBUG_LOG_LEVEL, 0,               \
                 s, "[SHORTURL_DEBUG] %s(%d): "format,                  \
                 __FILE__, __LINE__, ##args)
#define _PDEBUG(p, format, args...)                                     \
    ap_log_perror(APLOG_MARK, SHORTURL_DEBUG_LOG_LEVEL, 0,              \
                  p, "[SHORTURL_DEBUG] %s(%d): "format,                 \
                  __FILE__, __LINE__, ##args)

/* default parameter */
#define MONGO_DEFAULT_HOST    "localhost"
#define MONGO_DEFAULT_TIMEOUT 0
#define MONGO_CONFIG_UNSET    -1

/* mongo server config */
typedef struct {
    apr_pool_t *pool;
    char *host;
    int timeout;
    char *replset;
    char *db;
    char *collection;
    char *auth_db;
    char *auth_user;
    char *auth_password;
    mongo::DBClientConnection *cli;
} shorturl_server_config_t;

/* Functions */
static const char*
mongo_set_host(cmd_parms *parms, void *conf, char *arg);
static const char*
mongo_set_timeout(cmd_parms *parms, void *conf, char *arg);
static const char*
mongo_set_replset(cmd_parms *parms, void *conf, char *arg);
static const char*
mongo_set_db(cmd_parms *parms, void *conf, char *arg);
static const char*
mongo_set_collection(cmd_parms *parms, void *conf, char *arg);
static const char*
mongo_set_auth_db(cmd_parms *parms, void *conf, char *arg);
static const char*
mongo_set_auth_user(cmd_parms *parms, void *conf, char *arg);
static const char*
mongo_set_auth_password(cmd_parms *parms, void *conf, char *arg);

static void*
shorturl_create_server_config(apr_pool_t *p, server_rec *s);
static void*
shorturl_merge_server_config(apr_pool_t *p,
                             void *base_server,void *override_server);
/*
static int
shorturl_post_config(apr_pool_t *p, apr_pool_t *plog,
                     apr_pool_t *ptemp, server_rec *s);
*/
static void shorturl_child_init(apr_pool_t *p, server_rec *s);
static int shorturl_handler(request_rec* r);

/* Commands */
static const command_rec shorturl_cmds[] =
{
    AP_INIT_TAKE1(
        "MongoHost",
        (const char*(*)())(mongo_set_host), NULL, RSRC_CONF,
        "mongoDB host."),
    AP_INIT_TAKE1(
        "MongoTimeout",
        (const char*(*)())(mongo_set_timeout), NULL, RSRC_CONF,
        "mongoDB read/write timeout (not connection)."),
    AP_INIT_TAKE1(
        "MongoReplicaSet",
        (const char*(*)())(mongo_set_replset), NULL, RSRC_CONF,
        "mongoDB replicaset."),
    AP_INIT_TAKE1(
        "MongoDb",
        (const char*(*)())(mongo_set_db), NULL, RSRC_CONF,
        "mongoDB connection database."),
    AP_INIT_TAKE1(
        "MongoCollection",
        (const char*(*)())(mongo_set_collection), NULL, RSRC_CONF,
        "mongoDB connection collection."),
    AP_INIT_TAKE1(
        "MongoAuthDb",
        (const char*(*)())(mongo_set_auth_db), NULL, RSRC_CONF,
        "mongoDB authenticate database."),
    AP_INIT_TAKE1(
        "MongoAuthUser",
        (const char*(*)())(mongo_set_auth_user), NULL, RSRC_CONF,
        "mongoDB authenticate user."),
    AP_INIT_TAKE1(
        "MongoAuthPassword",
        (const char*(*)())(mongo_set_auth_password), NULL, RSRC_CONF,
        "mongoDB authenticate password."),
    { NULL, NULL, NULL, 0, TAKE1, NULL }
};

/* Hooks */
static void
shorturl_register_hooks(apr_pool_t *p)
{
    /* ap_hook_post_config(shorturl_post_config, NULL, NULL, APR_HOOK_MIDDLE); */
    ap_hook_child_init(shorturl_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(shorturl_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Module */
#ifdef __cplusplus
extern "C" {
#endif
module AP_MODULE_DECLARE_DATA shorturl_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                          /* create per-dir    config structures */
    NULL,                          /* merge  per-dir    config structures */
    shorturl_create_server_config, /* create per-server config structures */
    shorturl_merge_server_config,  /* merge  per-server config structures */
    shorturl_cmds,                 /* table of config file commands       */
    shorturl_register_hooks        /* register hooks                      */
};
#ifdef __cplusplus
}
#endif


/* cleanup */
static apr_status_t mongo_cleanup(void *parms)
{
    shorturl_server_config_t *config = (shorturl_server_config_t *)parms;

    if (!config) {
        return APR_SUCCESS;
    }

    /* mongo cleanup */
    if (config->cli) {
        delete config->cli;
        config->cli = NULL;
        _PDEBUG(NULL, "Cleanup: mongo database: %s(%d)",
                config->host, config->timeout);
    }

    if (config->pool) {
        apr_pool_clear(config->pool);
        config->pool = NULL;
    }

    return APR_SUCCESS;
}

/* config settings */
static const char*
mongo_set_host(cmd_parms *parms, void *conf, char *arg)
{
    shorturl_server_config_t *config;

    if (strlen(arg) == 0) {
        return "MongoHost argument must be a string representing a host.";
    }

    config = (shorturl_server_config_t *)
        ap_get_module_config(parms->server->module_config, &shorturl_module);
    config->host = apr_pstrdup(parms->pool, arg);

    return NULL;
}

static const char*
mongo_set_timeout(cmd_parms *parms, void *conf, char *arg)
{
    shorturl_server_config_t *config;
    int timeout;

    if (sscanf(arg, "%d", &timeout) != 1 || timeout < 0) {
        return "MongoTimeout must be an integer representing the timeout number";
    }

    config =(shorturl_server_config_t *)
        ap_get_module_config(parms->server->module_config, &shorturl_module);
    config->timeout = timeout;

    return NULL;
}

static const char*
mongo_set_replset(cmd_parms *parms, void *conf, char *arg)
{
    shorturl_server_config_t *config;

    if (strlen(arg) == 0) {
        return
            "MongoReplicaSet argument "
            "must be a string representing a replset.";
    }

    config = (shorturl_server_config_t *)
        ap_get_module_config(parms->server->module_config, &shorturl_module);
    config->replset = apr_pstrdup(parms->pool, arg);

    return NULL;
}

static const char*
mongo_set_db(cmd_parms *parms, void *conf, char *arg)
{
    shorturl_server_config_t *config;

    if (strlen(arg) == 0) {
        return "MongoDb argument must be a string representing a database name.";
    }

    config = (shorturl_server_config_t *)
        ap_get_module_config(parms->server->module_config, &shorturl_module);
    config->db = apr_pstrdup(parms->pool, arg);

    return NULL;
}

static const char*
mongo_set_collection(cmd_parms *parms, void *conf, char *arg)
{
    shorturl_server_config_t *config;

    if (strlen(arg) == 0) {
        return
            "MongoCollection argument "
            "must be a string representing a collection name.";
    }

    config = (shorturl_server_config_t *)
        ap_get_module_config(parms->server->module_config, &shorturl_module);
    config->collection = apr_pstrdup(parms->pool, arg);

    return NULL;
}

static const char*
mongo_set_auth_db(cmd_parms *parms, void *conf, char *arg)
{
    shorturl_server_config_t *config;

    if (strlen(arg) == 0) {
        return
            "MongoAuthDb argument "
            "must be a string representing a authenticate database.";
    }

    config = (shorturl_server_config_t *)
        ap_get_module_config(parms->server->module_config, &shorturl_module);
    config->auth_db = apr_pstrdup(parms->pool, arg);

    return NULL;
}

static const char*
mongo_set_auth_user(cmd_parms *parms, void *conf, char *arg)
{
    shorturl_server_config_t *config;

    if (strlen(arg) == 0) {
        return
            "MongoAuthUser argument "
            "must be a string representing a authenticate user.";
    }

    config = (shorturl_server_config_t *)
        ap_get_module_config(parms->server->module_config, &shorturl_module);
    config->auth_user = apr_pstrdup(parms->pool, arg);

    return NULL;
}

static const char*
mongo_set_auth_password(cmd_parms *parms, void *conf, char *arg)
{
    shorturl_server_config_t *config;

    if (strlen(arg) == 0) {
        return
            "MongoAuthUser argument "
            "must be a string representing a authenticate user.";
    }

    config = (shorturl_server_config_t *)
        ap_get_module_config(parms->server->module_config, &shorturl_module);
    config->auth_password = apr_pstrdup(parms->pool, arg);

    return NULL;
}

/* create server config */
static void*
shorturl_create_server_config(apr_pool_t *p, server_rec *s)
{
    shorturl_server_config_t *config = (shorturl_server_config_t *)
        apr_pcalloc(p, sizeof(shorturl_server_config_t));

    apr_pool_create(&config->pool, p);

    config->host = NULL;
    config->timeout = MONGO_CONFIG_UNSET;
    config->replset = NULL;
    config->db = NULL;
    config->collection = NULL;
    config->auth_db = NULL;
    config->auth_user = NULL;
    config->auth_password = NULL;
    config->cli = NULL;

    return (void *)config;
}

/* merge server config */
static void*
shorturl_merge_server_config(apr_pool_t *p,
                            void *base_server, void *override_server)
{
    shorturl_server_config_t *config = (shorturl_server_config_t *)
        apr_pcalloc(p, sizeof(shorturl_server_config_t));
    shorturl_server_config_t *base = (shorturl_server_config_t *)base_server;
    shorturl_server_config_t *override =
        (shorturl_server_config_t *)override_server;

    config->pool = base->pool;

    if (override->host) {
        config->host = override->host;
    } else {
        config->host = (char *)MONGO_DEFAULT_HOST;
    }

    if (override->timeout == MONGO_CONFIG_UNSET) {
        config->timeout = MONGO_DEFAULT_TIMEOUT;
    } else {
        config->timeout = override->timeout;
    }

    if (override->replset) {
        config->replset = override->replset;
    } else {
        config->replset = NULL;
    }

    if (override->db) {
        config->db = override->db;
    } else {
        config->db = NULL;
    }

    if (override->collection) {
        config->collection = override->collection;
    } else {
        config->collection = NULL;
    }

    if (override->auth_db) {
        config->auth_db = override->auth_db;
    } else {
        config->auth_db = NULL;
    }

    if (override->auth_user) {
        config->auth_user = override->auth_user;
    } else {
        config->auth_user = NULL;
    }

    if (override->auth_password) {
        config->auth_password = override->auth_password;
    } else {
        config->auth_password = NULL;
    }

    return (void *)config;
}

/* post config
static int
shorturl_post_config(apr_pool_t *p, apr_pool_t *plog,
                    apr_pool_t *ptemp, server_rec *s)
{
    const char *userdata_key = "shorturl_post_config";
    void *user_data;
    shorturl_server_config_t *config;

    apr_pool_userdata_get(&user_data, userdata_key, s->process->pool);
    if (!user_data) {
        apr_pool_userdata_set((const void *)(1), userdata_key,
                              apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    config = (shorturl_server_config_t *)
        ap_get_module_config(s->module_config, &shorturl_module);

    return OK ;
}
*/

/* mongo initialize */
static apr_status_t
mongo_init(shorturl_server_config_t *config)
{
    std::string errmsg;

    if (config->cli && config->replset) {
        try {
            bool isMaster = false;
            if (!config->cli->isMaster(isMaster, NULL)) {
                delete config->cli;
                config->cli = NULL;
            }
        } catch(mongo::MsgAssertionException &e) {
            _PERR(config->pool, "%s", e.what());
            delete config->cli;
            config->cli = NULL;
        } catch(mongo::UserException &e) {
            _PERR(config->pool, "%s", e.what());
            delete config->cli;
            config->cli = NULL;
        } catch(mongo::DBException &e) {
            _PERR(config->pool, "%s", e.what());
            delete config->cli;
            config->cli = NULL;
        }
    }

    if (!config->cli) {
        if (!config->host) {
            _PERR(config->pool, "host unknown.");
            return APR_EGENERAL;
        }

        /* ReplicaSet */
        if (config->replset) {
            char *repl = apr_psprintf(config->pool, "%s/%s",
                                      config->replset, config->host);
            try {
                mongo::ConnectionString cs =
                    mongo::ConnectionString::parse(repl, errmsg);
                if (!cs.isValid()) {
                    _PERR(config->pool, "%s", errmsg.c_str());
                    return APR_EGENERAL;
                }

                mongo::DBClientReplicaSet *rep =
                    dynamic_cast<mongo::DBClientReplicaSet*>(
                        cs.connect(errmsg, config->timeout));
                if (!rep) {
                    _PERR(config->pool, "%s", errmsg.c_str());
                    return APR_EGENERAL;
                }

                config->cli =
                    dynamic_cast<mongo::DBClientConnection*>(&rep->masterConn());
            } catch(mongo::MsgAssertionException &e) {
                _PERR(config->pool, "%s", e.what()) ;
                return APR_EGENERAL;
            } catch(mongo::UserException &e) {
                _PERR(config->pool, "%s", e.what()) ;
                return APR_EGENERAL;
            } catch(mongo::DBException &e) {
                _PERR(config->pool, "%s", e.what()) ;
                return APR_EGENERAL;
            }

            _PDEBUG(config->pool, "Connectionn mongo database: %s(%d)",
                    repl, config->timeout);
        } else {
            char *connect = apr_psprintf(config->pool, "%s", config->host);
            try {
                config->cli = new mongo::DBClientConnection(true, 0,
                                                            config->timeout);
                config->cli->connect(connect);
            } catch(mongo::MsgAssertionException &e) {
                _PERR(config->pool, "%s", e.what()) ;
                return APR_EGENERAL;
            } catch(mongo::UserException &e) {
                _PERR(config->pool, "%s", e.what()) ;
                return APR_EGENERAL;
            } catch(mongo::DBException &e) {
                _PERR(config->pool, "%s", e.what()) ;
                return APR_EGENERAL;
            }

            _PDEBUG(config->pool, "Connectionn mongo database: %s(%d)",
                    connect, config->timeout);
        }
    }

    /* auth */
    if (config->auth_db && config->auth_user && config->auth_password) {
        try {
            if (!config->cli->auth(config->auth_db, config->auth_user,
                                   config->auth_password, errmsg, true)) {
                _PERR(config->pool, "%s", errmsg.c_str());
                return APR_EGENERAL;
            }
        } catch(mongo::MsgAssertionException &e) {
            _PERR(config->pool, "%s", e.what()) ;
            return APR_EGENERAL;
        } catch(mongo::UserException &e) {
            _PERR(config->pool, "%s", e.what()) ;
            return APR_EGENERAL;
        } catch(mongo::DBException &e) {
            _PERR(config->pool, "%s", e.what()) ;
            delete config->cli;
            config->cli = NULL;
            return APR_EGENERAL;
        }
    }

    return APR_SUCCESS;
}

/* child init */
static void
shorturl_child_init(apr_pool_t *p, server_rec *s)
{
    shorturl_server_config_t *config = (shorturl_server_config_t *)
        ap_get_module_config(s->module_config, &shorturl_module);

    apr_pool_cleanup_register(p, (void *)config, mongo_cleanup,
                              apr_pool_cleanup_null);
}

/* content handler */
static int
shorturl_handler(request_rec *r)
{
    int retval = OK;

    if (strcmp(r->handler, "shorturl")) {
        return DECLINED;
    }

    /* server config */
    shorturl_server_config_t *config =
        (shorturl_server_config_t *)ap_get_module_config(
            r->server->module_config, &shorturl_module);

    /* init */
    if (mongo_init(config) != APR_SUCCESS) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    mongo::BSONObjBuilder command;

    if (!config->db || !config->collection)
    {
        _RERR(r, "unknown db or collection");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    command.append("findAndModify", config->collection);

    //query
    char *query = apr_psprintf(r->pool,
                               "{\"_id\":\"%s%s\"}", r->hostname, r->uri);
    command.append("query", mongo::fromjson(query));

    //update
    command.append("update", mongo::fromjson("{$inc:{\"accessNum\":1}}"));

    //new
    command.append("new", true);

    //fields
    command.append("fields", mongo::fromjson("{\"_id\":0,\"url\":1}"));

    try {
        mongo::BSONObj obj;
        if (config->cli->runCommand(config->db, command.obj(), obj)) {
            if (!obj.isEmpty() && obj.hasField("value")) {
                mongo::BSONObj shorturl = obj.getObjectField("value");
                const char *url = shorturl.getStringField("url");
                if (url && strlen(url) > 0) {
                    apr_table_set(r->headers_out, "Location", url);
                    return HTTP_MOVED_PERMANENTLY;
                }
            }
            return HTTP_NOT_FOUND;
        } else {
            _RERR(r, "runCommand: %s: %s",
                  config->cli->getLastError().c_str(), r->filename);
        }
    } catch(mongo::MsgAssertionException &e) {
        _RERR(r, "runCommand: %s", e.what()) ;
    } catch(mongo::UserException &e) {
        _RERR(r, "runCommand: %s", e.what()) ;
    } catch(mongo::DBException &e) {
        _RERR(r, "runCommand: %s", e.what()) ;
        delete config->cli;
        config->cli = NULL;
    }

    return HTTP_INTERNAL_SERVER_ERROR;
}
