#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>

int main(){
    int myFd,client_fd;
    struct sockaddr_in server, client;
    int client_size;
    int error = 0, wrote = 0;
    char buffer[] = "Hello there! Welcome to the SSL test server.\n";
    char buff[128]; 
    SSL_METHOD *my_ssl_method;
    SSL_CTX *ssl_ctx;
    SSL *my_ssl;
    time_t ticks;
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    my_ssl_method = TLS_server_method();
    if( ( ssl_ctx = SSL_CTX_new(my_ssl_method) ) == NULL ) {
        ERR_print_errors_fp(stderr);
    exit(-1);
    }
    SSL_CTX_use_certificate_file(ssl_ctx,"server.pem",SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ssl_ctx,"server.pem",SSL_FILETYPE_PEM);
    if( !SSL_CTX_check_private_key(ssl_ctx) ) {
        fprintf(stderr,"Private key does not match certificate\n");
        exit(-1);
    }
    myFd = socket(PF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(5353);
    server.sin_addr.s_addr = INADDR_ANY;
    bind(myFd, (struct sockaddr *)&server, sizeof(server));
    listen(myFd, 5);
    printf("Waiting new client...\n");
    for( ;; ) {
        client_size = sizeof(client);
        bzero(&client,sizeof(client));
        client_fd = accept(myFd, (struct sockaddr *)&client, (socklen_t *)&client_size);
        if((my_ssl = SSL_new(ssl_ctx)) == NULL) {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    SSL_set_fd(my_ssl,client_fd);
    if(SSL_accept(my_ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    printf("New client:\n");
    ticks = time(NULL);
    snprintf(buff, sizeof(buff), "%.24s\r\n", ctime(&ticks));
    struct hostent *hostName;
    struct in_addr ip_addr;
    inet_aton(inet_ntoa(client.sin_addr), & ip_addr);  
    hostName = gethostbyaddr(&ip_addr, sizeof(ip_addr), AF_INET); //IP address of client convert the name
    printf("Host name: %s\n", hostName->h_name); 
    printf("Connection time: %s", buff);
    printf("[%s,%s]\n",SSL_get_version(my_ssl),SSL_get_cipher(my_ssl));
    printf("*******************\n");
    
    for(wrote = 0; wrote < strlen(buffer); wrote += error) {
        error = SSL_write(my_ssl,buffer+wrote,strlen(buffer)-wrote);
        if(error <= 0)
        break;
    }
    
    for(wrote = 0; wrote < strlen(buff); wrote += error) {
        error = SSL_write(my_ssl,buff+wrote,strlen(buff)-wrote);
        if(error <= 0)
        break;
    }
    SSL_shutdown(my_ssl);
    SSL_free(my_ssl);
    close(client_fd);
    }
    SSL_CTX_free(ssl_ctx);
    return 0;
}