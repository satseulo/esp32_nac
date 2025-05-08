idf_component_register(SRCS "hello_world_main.c"
                    PRIV_REQUIRES spi_flash
                    INCLUDE_DIRS "."
                    REQUIRES enc28j60 esp_netif nac https_server)
