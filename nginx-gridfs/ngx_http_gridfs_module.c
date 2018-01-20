#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <mongoc.h>
#include <signal.h>
#include <stdio.h>

#define TRUE 1
#define FALSE 0
#define ALLOC_BUFFER_SIZE 4096

/* Parse config directive */
static char * ngx_http_mongo(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy);

/* Parse config directive */
static char* ngx_http_gridfs(ngx_conf_t* directive, ngx_command_t* command, void* gridfs_conf);

static void* ngx_http_gridfs_create_main_conf(ngx_conf_t* directive);

static void* ngx_http_gridfs_create_loc_conf(ngx_conf_t* directive);

static char* ngx_http_gridfs_merge_loc_conf(ngx_conf_t* directive, void* parent, void* child);

static ngx_int_t ngx_http_gridfs_init_worker(ngx_cycle_t* cycle);

static ngx_int_t ngx_http_gridfs_handler(ngx_http_request_t* request);

typedef struct {
    ngx_str_t db;
    ngx_str_t root_collection;
    ngx_str_t mongo;
} ngx_http_gridfs_loc_conf_t;

typedef struct {
    ngx_str_t name;
    mongoc_client_t* conn;
} ngx_http_mongo_connection_t;

typedef struct {
    ngx_array_t loc_confs; /* ngx_http_gridfs_loc_conf_t */
} ngx_http_gridfs_main_conf_t;


/* Array specifying how to handle configuration directives. */
static ngx_command_t ngx_http_gridfs_commands[] = {

    {
        ngx_string("mongo"),
        NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
        ngx_http_mongo,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    {
        ngx_string("gridfs"),
        NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
        ngx_http_gridfs,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    ngx_null_command
};

/* Module context. */
static ngx_http_module_t ngx_http_gridfs_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */
    ngx_http_gridfs_create_main_conf,
    NULL, /* init main configuration */
    NULL, /* create server configuration */
    NULL, /* init serever configuration */
    ngx_http_gridfs_create_loc_conf,
    ngx_http_gridfs_merge_loc_conf
};

/* Module definition. */
ngx_module_t ngx_http_gridfs_module = {
    NGX_MODULE_V1,
    &ngx_http_gridfs_module_ctx,
    ngx_http_gridfs_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    ngx_http_gridfs_init_worker,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

ngx_array_t ngx_http_mongo_connections;

/* Parse the 'mongo' directive. */
static char * ngx_http_mongo(ngx_conf_t *cf, ngx_command_t *cmd, void *void_conf) {
    ngx_str_t *value;
    ngx_http_gridfs_loc_conf_t *gridfs_loc_conf;

    gridfs_loc_conf = void_conf;

    value = cf->args->elts;
    gridfs_loc_conf->mongo = value[1];

    return NGX_CONF_OK;
}

/* Parse the 'gridfs' directive. */
static char* ngx_http_gridfs(ngx_conf_t* cf, ngx_command_t* command, void* void_conf) {
    ngx_http_gridfs_loc_conf_t *gridfs_loc_conf = void_conf;
    ngx_http_core_loc_conf_t* core_conf;
    ngx_str_t *value;
    volatile ngx_uint_t i;

    core_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    core_conf-> handler = ngx_http_gridfs_handler;

    value = cf->args->elts;
    gridfs_loc_conf->db = value[1];

    /* Parse the parameters */
    for (i = 2; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "root_collection=", 16) == 0) { 
            gridfs_loc_conf->root_collection.data = (u_char *) &value[i].data[16];
            gridfs_loc_conf->root_collection.len = ngx_strlen(&value[i].data[16]);
            continue;
        }
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static void *ngx_http_gridfs_create_main_conf(ngx_conf_t *cf) {
    ngx_http_gridfs_main_conf_t  *gridfs_main_conf;

    gridfs_main_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_gridfs_main_conf_t));
    if (gridfs_main_conf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&gridfs_main_conf->loc_confs, cf->pool, 4,
                       sizeof(ngx_http_gridfs_loc_conf_t *))
        != NGX_OK) {
        return NULL;
    }

    return gridfs_main_conf;
}

static void* ngx_http_gridfs_create_loc_conf(ngx_conf_t* directive) {
    ngx_http_gridfs_loc_conf_t* gridfs_conf;
    gridfs_conf = ngx_pcalloc(directive->pool, sizeof(ngx_http_gridfs_loc_conf_t));
    if (gridfs_conf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, directive, 0,
                           "Failed to allocate memory for GridFS Location Config.");
        return NGX_CONF_ERROR;
    }

    gridfs_conf->db.data = NULL;
    gridfs_conf->db.len = 0;
    gridfs_conf->root_collection.data = NULL;
    gridfs_conf->root_collection.len = 0;
    gridfs_conf->mongo.data = NULL;
    gridfs_conf->mongo.len = 0;

    return gridfs_conf;
}

static char* ngx_http_gridfs_merge_loc_conf(ngx_conf_t* cf, void* void_parent, void* void_child) {
    ngx_http_gridfs_loc_conf_t *parent = void_parent;
    ngx_http_gridfs_loc_conf_t *child = void_child;
    ngx_http_gridfs_main_conf_t *gridfs_main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_gridfs_module);
    ngx_http_gridfs_loc_conf_t **gridfs_loc_conf;

    ngx_conf_merge_str_value(child->db, parent->db, NULL);
    ngx_conf_merge_str_value(child->root_collection, parent->root_collection, "fs");
    ngx_conf_merge_str_value(child->mongo, parent->mongo, "127.0.0.1:27017");


    // Add the local gridfs conf to the main gridfs conf
    if (child->db.data) {
        gridfs_loc_conf = ngx_array_push(&gridfs_main_conf->loc_confs);
        *gridfs_loc_conf = child;
    }

    return NGX_CONF_OK;
}

ngx_http_mongo_connection_t* ngx_http_get_mongo_connection( ngx_str_t name ) {
    ngx_http_mongo_connection_t *mongo_conns;
    ngx_uint_t i;

    mongo_conns = ngx_http_mongo_connections.elts;

    for ( i = 0; i < ngx_http_mongo_connections.nelts; i++ ) {
        if ( name.len == mongo_conns[i].name.len
             && ngx_strncmp(name.data, mongo_conns[i].name.data, name.len) == 0 ) {
            return &mongo_conns[i];
        }
    }

    return NULL;
}


static ngx_int_t ngx_http_mongo_add_connection(ngx_cycle_t* cycle, ngx_http_gridfs_loc_conf_t* gridfs_loc_conf) {
    ngx_http_mongo_connection_t* mongo_conn;
    u_char host[255];
    mongo_conn = ngx_http_get_mongo_connection( gridfs_loc_conf->mongo );
    if (mongo_conn != NULL) {
        return NGX_OK;
    }

    mongo_conn = ngx_array_push(&ngx_http_mongo_connections);
    if (mongo_conn == NULL) {
        return NGX_ERROR;
    }
    ngx_cpystrn( host, gridfs_loc_conf->mongo.data, gridfs_loc_conf->mongo.len + 1 );
    mongo_conn->name = gridfs_loc_conf->mongo;
    mongo_conn->conn = mongoc_client_new((const char*)host);
    if(!mongo_conn->conn){
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "Mongo Exception: Failed to parse URI");
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_gridfs_init_worker(ngx_cycle_t* cycle) {
    ngx_http_gridfs_main_conf_t* gridfs_main_conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_gridfs_module);
    ngx_http_gridfs_loc_conf_t** gridfs_loc_confs;
    ngx_uint_t i;

    signal(SIGPIPE, SIG_IGN);

    mongoc_init();

    gridfs_loc_confs = gridfs_main_conf->loc_confs.elts;

    ngx_array_init(&ngx_http_mongo_connections, cycle->pool, 4, sizeof(ngx_http_mongo_connection_t));

    for (i = 0; i < gridfs_main_conf->loc_confs.nelts; i++) {
        if (ngx_http_mongo_add_connection(cycle, gridfs_loc_confs[i]) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

static char h_digit(char hex) {
    return (hex >= '0' && hex <= '9') ? hex - '0': ngx_tolower(hex)-'a'+10;
}

static int htoi(char* h) {
    char ok[] = "0123456789AaBbCcDdEeFf";

    if (ngx_strchr(ok, h[0]) == NULL || ngx_strchr(ok,h[1]) == NULL) { return -1; }
    return h_digit(h[0])*16 + h_digit(h[1]);
}

static int url_decode(char * filename) {
    char * read = filename;
    char * write = filename;
    char hex[3];
    int c;

    hex[2] = '\0';
    while (*read != '\0'){
        if (*read == '%') {
            hex[0] = *(++read);
            if (hex[0] == '\0') return 0;
            hex[1] = *(++read);
            if (hex[1] == '\0') return 0;
            c = htoi(hex);
            if (c == -1) return 0;
            *write = (char)c;
        }
        else *write = *read;
        read++;
        write++;
    }
    *write = '\0';
    return 1;
}

static ngx_int_t ngx_http_gridfs_handler(ngx_http_request_t* request) {
    ngx_http_gridfs_loc_conf_t* gridfs_conf;
    ngx_http_core_loc_conf_t* core_conf;
    ngx_buf_t* buffer=NULL;
    ngx_chain_t out;
    ngx_str_t location_name;
    ngx_str_t full_uri;
    u_char* value;
    ngx_http_mongo_connection_t *mongo_conn;
    mongoc_gridfs_file_t *gfile;
    mongoc_gridfs_t *gridfs;
    bson_error_t error;
    int64_t gfile_length;
    char* gfile_contenttype;
    u_char * gbuffer;
    mongoc_stream_t *stream;
    mongoc_iovec_t iov;
    volatile ssize_t r;
    volatile ssize_t recv_length=0;
    ngx_int_t rc = NGX_OK;
    bson_t filter;
    bson_oid_t oid;

    gridfs_conf = ngx_http_get_module_loc_conf(request, ngx_http_gridfs_module);
    core_conf = ngx_http_get_module_loc_conf(request, ngx_http_core_module);

    // ---------- ENSURE MONGO CONNECTION ---------- //

    mongo_conn = ngx_http_get_mongo_connection( gridfs_conf->mongo );
    if (mongo_conn == NULL) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Mongo Connection not found: \"%V\"", &gridfs_conf->mongo);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    // ---------- RETRIEVE KEY ---------- //

    location_name = core_conf->name;
    full_uri = request->uri;

    if (full_uri.len < location_name.len) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Invalid location name or uri.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    value = ngx_pcalloc(request->pool,sizeof(char) * (full_uri.len - location_name.len + 1));
    if (value == NULL) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Failed to allocate memory for value buffer.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    memcpy(value, full_uri.data + location_name.len, full_uri.len - location_name.len);
    value[full_uri.len - location_name.len] = '\0';

    if (!url_decode((char*)value)) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Malformed request.");
        return NGX_HTTP_BAD_REQUEST;
    }

    // ---------- RETRIEVE GRIDFILE ---------- //
    gridfs = mongoc_client_get_gridfs(mongo_conn->conn,
    				(const char*)gridfs_conf->db.data,
				(const char*)gridfs_conf->root_collection.data,
				&error);
    if (!gridfs) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "cannot access gridfs");
        return NGX_HTTP_BAD_REQUEST;
    }
    bson_init(&filter);
    bson_oid_init_from_string(&oid, (const char*)value);
    bson_append_oid(&filter, "_id", -1, &oid);
    gfile = mongoc_gridfs_find_one(gridfs, &filter, &error);

    bson_destroy (&filter);

    if(!gfile){
        return NGX_HTTP_NOT_FOUND;
    }

    /* Get information about the file */
    gfile_length = mongoc_gridfs_file_get_length(gfile);
    gfile_contenttype = (char*)mongoc_gridfs_file_get_content_type(gfile);

    // ---------- SEND THE HEADERS ---------- //

    request->headers_out.status = NGX_HTTP_OK;
    request->headers_out.content_length_n = gfile_length;
    if (gfile_contenttype != NULL) {
        request->headers_out.content_type.len = strlen(gfile_contenttype);
        request->headers_out.content_type.data = (u_char*)gfile_contenttype;
    }
    else ngx_http_set_content_type(request);

    ngx_http_send_header(request);


    // ---------- SEND THE BODY ---------- //
    stream = mongoc_stream_gridfs_new (gfile);
    assert (stream);
    for (;;) {
    		gbuffer = ngx_pcalloc(request->pool,ALLOC_BUFFER_SIZE);
    		if(gbuffer==NULL){
    			ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
    						  "Failed to allocate response buffer");
    			return NGX_HTTP_INTERNAL_SERVER_ERROR;
    		}
    	    iov.iov_base = (void *) gbuffer;
    	    iov.iov_len = ALLOC_BUFFER_SIZE;
    		r = mongoc_stream_readv(stream, &iov, 1, -1, 0);
    		assert (r>=0);
    		if (r==0){
   			break;
    		}
    		recv_length += r;
    		buffer = ngx_pcalloc(request->pool, sizeof(ngx_buf_t));
		if (buffer == NULL) {
			ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
						  "Failed to allocate response buffer");
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		buffer->pos = (u_char*)iov.iov_base;
		buffer->last = (u_char*)iov.iov_base + r;
		buffer->memory = 1;
		buffer->last_buf = (recv_length==gfile_length);
		out.buf = buffer;
		out.next = NULL;
        rc = ngx_http_output_filter(request, &out);
        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }
    }
    mongoc_stream_destroy(stream);
    mongoc_gridfs_file_destroy(gfile);
    mongoc_gridfs_destroy(gridfs);
    return NGX_OK;
}
