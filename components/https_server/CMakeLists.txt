idf_component_register(SRCS "https_server.c"
                    REQUIRES esp_https_server 
                    INCLUDE_DIRS "."
                    EMBED_TXTFILES "certs/servercert.pem"
                                   "certs/prvtkey.pem"
                                   "login.html")
