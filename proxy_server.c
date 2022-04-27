#include "threadpool.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <pthread.h>
#include <assert.h>
#include <unistd.h>

#define FILTER_LIST_ELEM_SIZE 100
#define CLIENT_MSG_SIZE 2000
#define UNUSED_PORT 0
#define DEFAULT_PORT 8888
#define HTTP_SERVER_PORT 80

#define CRLF "\r\n"
#define HEADER_HOST_STR "Host: "

#define HTTP_0_9 "HTTP/0.9"
#define HTTP_1_0 "HTTP/1.0"
#define HTTP_1_1 "HTTP/1.1"
#define HTTP_2 "HTTP/2"

#define GET_METHOD_STR "GET"

#define HEADER_LINE_SIZE 150

// HTTP Headers
#define CONTENT_TYPE "Content-Type: "
#define CONNECTION "Connection: close\r\n"
#define CONTENT_LENGTH "Content-Length: "
#define HTML_MIME_TYPE "text/html"

#define Http_StatusLine_200 "HTTP/1.0 200 OK\r\n"
#define Http_StatusLine_400 "HTTP/1.0 400 Bad Request\r\n"
#define Http_StatusLine_403 "HTTP/1.0 403 Forbidden\r\n"
#define Http_StatusLine_404 "HTTP/1.0 404 Not Found\r\n"
#define Http_StatusLine_500 "HTTP/1.0 500 Internal Server Error\r\n"
#define Http_StatusLine_501 "HTTP/1.0 501 Not supported\r\n"

#define Http_RespMsg_200_Sample "<html><body><h1>Hello, World!</h1></body></html>"
#define Http_RespMsg_400 "<HTML><HEAD><TITLE>400 Bad Request</TITLE></HEAD><BODY><H4>400 Bad request</H4>Bad Request.</BODY></HTML>"
#define Http_RespMsg_403 "<HTML><HEAD><TITLE>403 Forbidden</TITLE></HEAD><BODY><H4>403 Forbidden</H4>Access denied.</BODY></HTML>"
#define Http_RespMsg_404 "<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD><BODY><H4>404 Not Found</H4>File not found.</BODY></HTML>"
#define Http_RespMsg_500 "<HTML><HEAD><TITLE>500 Internal Server Error</TITLE></HEAD><BODY><H4>500 Internal Server Error</H4>Some server side error.</BODY></HTML>"
#define Http_RespMsg_501 "<HTML><HEAD><TITLE>501 Not supported</TITLE></HEAD><BODY><H4>501 Not supported</H4>Method is not supported.</BODY></HTML>"

#define DEFAULT_FILE "/index.html"

typedef enum HTTPMethod
{
    GET
} HTTPMethod;

typedef enum ServerResponseCode
{
    Http_Ok = 200,
    Http_Bad_Request = 400,
    Http_Forbidden = 403,
    Http_Not_Found = 404,
    Http_Internal_Server_Error = 500,
    Http_Method_Not_Implemented = 501
} ServerResponseCode;

typedef struct client_request_st {
    HTTPMethod method;
    char* request_URI;
    char* host_str;
    struct sockaddr_in client_addr;
} client_request_t;

 // Global structure that contains list of Hosts and IP addresses to filter

typedef struct filterList_st {
    size_t length;
    size_t size;
    char **filterListArray;

} filterList_t;
filterList_t filterList;


void usage()
{
    printf("Usage: proxyServer <port> <pool-size> <max-number-of-request> <filter>\n");
    exit(EXIT_FAILURE);
}

char *get_mime_type(char *name)
{
    char *ext = strrchr(name, '.');
    if (!ext) return NULL;
    if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0) return "text/html";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, ".gif") == 0) return "image/gif";
    if (strcmp(ext, ".png") == 0) return "image/png";
    if (strcmp(ext, ".css") == 0) return "text/css";
    if (strcmp(ext, ".au") == 0) return "audio/basic";
    if (strcmp(ext, ".wav") == 0) return "audio/wav";
    if (strcmp(ext, ".avi") == 0) return "video/x-msvideo";
    if (strcmp(ext, ".mpeg") == 0 || strcmp(ext, ".mpg") == 0) return "video/mpeg";
    if (strcmp(ext, ".mp3") == 0) return "audio/mpeg";
    return NULL;
}

//  Check if the char string in the "httpVersion" is one of the valid HTTP Version string. If not, returns 1 else 0

int checkHTTPVersions(char* httpVersion)
{
    if (strcmp(httpVersion, HTTP_0_9) == 0) return 1;
    if (strcmp(httpVersion, HTTP_1_0) == 0) return 1;
    if (strcmp(httpVersion, HTTP_1_1) == 0) return 1;
    if (strcmp(httpVersion, HTTP_2) == 0) return 1;

    return 0;
}

// Check the client host string & client IP address for a match in the filter list If match found, return 403 (Forbidden) else 200 (Ok)

ServerResponseCode checkInFilterList(char* client_host, uint32_t client_ip)
{
    char *filterItem;
    char token [10];
    char *strLoc = NULL;
    int i;
    int prefix;
    uint32_t netmask = 0;
    uint32_t net_ip = 0;
    struct sockaddr_in net_addr;
    int token_size;

    printf("Checking client host %s and its IP address %u in filter list\n",
           client_host, client_ip);
    // Traverse filter list
    for(i = 0; i < filterList.length; ++i)
    {
        // get filter item
        filterItem = filterList.filterListArray[i];
        printf("Filter item: %s\n", filterItem);

        // check if filter item is hostname or CIDR subnet
        if (!isdigit(filterItem[0]))
        {
            printf("Filter item is host string: %s\n", filterItem);
            // if (strncmp(filterItem, client_host, strlen(client_host)) == 0)
            // Check if client host is in the filter item
            strLoc = strstr(filterItem, client_host);
            if (strLoc != NULL)
            {
                printf("Filter item %s matches with client host %s\n",
                       filterItem, client_host);
                return Http_Forbidden;
            }
        }
        else
        {
            printf("Filter item is CIDR Subnet: %s\n",
                   filterItem);

            // Convert CIDR subnet mask to netmask
            // Get IP Address from filter item
            strLoc = strstr(filterItem, "/");
            if (strLoc == NULL)
                return Http_Internal_Server_Error;

            token_size = (strLoc - filterItem);
            strncpy(token, filterItem, token_size);
            token[token_size] = '\0';
            printf("Filter item IP Address token: %s\n", token);

            if (inet_pton(AF_INET, token, &(net_addr.sin_addr)) != 1)
            {
                printf("Filter item, invalid IP address: %s\n", token);
                perror("Error: inet_pton\n");
                return Http_Internal_Server_Error;
            }

            strLoc = strstr(filterItem, "/");
            if (strLoc == NULL)
                return Http_Internal_Server_Error;

            strLoc++;
            printf("Filter item, prefix string: %s\n", strLoc);
            prefix = strtol(strLoc, NULL, 10);
            if ((errno == EINVAL) || (errno == ERANGE))
            {
                perror("error: strtol\n");
                return Http_Internal_Server_Error;
            }
            netmask = 0xffffffff << (32 - prefix);

            net_ip = ntohl(net_addr.sin_addr.s_addr);
            printf("Subnet IP: %X, netmask: %X, client IP: %X\n",
                   net_ip, netmask, client_ip);

            printf("(net_ip & netmask): %X, (client_ip & netmask): %X\n",
                   (net_ip & netmask), (client_ip & netmask));

            // uint32_t client_ip = ...; // value to check
            // uint32_t netip = ...; // network ip to compare with
            // uint32_t netmask = ...; // network ip subnet mask
            if ((net_ip & netmask) == (client_ip & netmask))
                return Http_Forbidden;
        }
    }

    return Http_Ok;
}

// Validates the client request.Checks if the request is HTTP\GET method, If not HTTP, return 400. if HTTP but not GET, return 501
ServerResponseCode validateHTTPRequest(const char *requestBody,
                                       client_request_t *clientRequest)
{
    int newLineLoc;
    char *requestLine = NULL;
    char *token = NULL;
    char *strLoc = NULL;
    char *strLoc2 = NULL;
    struct hostent *he = NULL;
    ServerResponseCode respCode = Http_Ok;

    if (requestBody == NULL)
        return Http_Bad_Request;

    // Read the first line
    strLoc = strstr(requestBody, CRLF);
    if (strLoc == NULL)
        return Http_Bad_Request;
    newLineLoc = (int)(strLoc - requestBody);
    //printf("newLineLoc: %d\n", newLineLoc);

    requestLine = (char*) malloc(sizeof(char) * (newLineLoc+2));
    // requestLine = (char*) malloc(sizeof(char) *
    //                  (strlen("GET /hypertext/WWW/TheProject.html HTTP/1.1")));
    if (requestLine == NULL)
    {
        perror("error: malloc\n");
        respCode = Http_Internal_Server_Error;
        goto VALIDATE_END;
    }
    strncpy(requestLine, requestBody, newLineLoc+1);
    requestLine[newLineLoc+1] = 0;
    // strncpy(requestLine, "GET /hypertext/WWW/TheProject.html HTTP/1.1",
    //     (strlen("GET /hypertext/WWW/TheProject.html HTTP/1.1")));

    printf("Request Line: %s\n", requestLine);

    // tokenize the requestLine
    token = strtok (requestLine," ");
    if (token == NULL)
    {
        respCode = Http_Bad_Request;
        goto VALIDATE_END;
    }

    if (strcmp(token, GET_METHOD_STR) != 0)
    {
        respCode = Http_Method_Not_Implemented; // Not a GET method;
        goto VALIDATE_END;
    }
    else
    {
        clientRequest->method = GET;
    }
    printf("Method: %s\n", token); // Method

    token = strtok (NULL, " ");
    if (token == NULL)
        return Http_Bad_Request;
    printf("Request-URI: %s\n", token);
    clientRequest->request_URI = (char*) malloc(sizeof(char) * strlen(token));
    if (clientRequest->request_URI == NULL)
    {
        perror("error: malloc\n");
        respCode = Http_Internal_Server_Error;
        goto VALIDATE_END;
    }
    else
    {
        strncpy(clientRequest->request_URI, token, strlen(token));
    }

    token = strtok (NULL, "\r");
    if (token == NULL)
    {
        respCode = Http_Bad_Request;
        goto VALIDATE_END;
    }

    if (checkHTTPVersions(token))
    {
        printf("Valid HTTP-Version: %s\n", token); // HTTP-Version
    }
    else
    {
        printf("Invalid HTTP-Version: %s\n", token); // HTTP-Version
        respCode = Http_Bad_Request; // Not Valid HTTP-Version
        goto VALIDATE_END;
    }

    // Parse and get Host info from header
    token = NULL;
    strLoc = strstr(requestBody, HEADER_HOST_STR);
    if (strLoc == NULL)
        return Http_Bad_Request;
    strLoc += strlen(HEADER_HOST_STR) ;
    strLoc2 = strstr(strLoc, CRLF);
    if (strLoc2 == NULL)
    {
        respCode = Http_Bad_Request;
        goto VALIDATE_END;
    }
    clientRequest->host_str = (char*) malloc(sizeof(char) * ((int)(strLoc2 - strLoc) + 1));
    if (clientRequest->host_str == NULL)
    {
        perror("error: malloc\n");
        respCode = Http_Internal_Server_Error;
        goto VALIDATE_END;
    }
    strncpy(clientRequest->host_str, strLoc, (int)(strLoc2 - strLoc));
    clientRequest->host_str[(int)(strLoc2 - strLoc)] = 0;
    // strncpy(clientRequest->host_str, "info.cern.ch", strlen("info.cern.ch"));
    // strncpy(clientRequest->host_str, "www.cnn.com", strlen("www.cnn.com"));
    // strncpy(clientRequest->host_str, "45.34.58.121", strlen("45.34.58.121"));
    printf("Client Host: %s\n", clientRequest->host_str);

    // get the host info
    he = gethostbyname(clientRequest->host_str);
    if (he == NULL)
    {
        perror("error: gethostbyname\n");
        // Unable to get the IP of the host (from the URL)
        respCode = Http_Not_Found;
        goto VALIDATE_END;
    }
    // Retrieve the client address
    clientRequest->client_addr.sin_addr = *((struct in_addr *)he->h_addr);

    printf("Client Host: %s and its IP: %s\n",
           clientRequest->host_str,
           inet_ntoa(clientRequest->client_addr.sin_addr));

    // Check in filter list
    respCode = checkInFilterList(clientRequest->host_str,
                                 ntohl(clientRequest->client_addr.sin_addr.s_addr));

    VALIDATE_END:
    if (requestLine != NULL)
        free(requestLine);
    return respCode;

}

char* getHttpResponse(char* HttpStatusLine, char* HttpRespMessageBody, char* mimeType)
{
    char* response = NULL;
    int respSize = 0;
    char contentLenStr[10];

    // create response
    respSize = (sizeof(char) * (strlen(HttpStatusLine)
                                + (HEADER_LINE_SIZE * 3)
                                + strlen(HttpRespMessageBody)) );
    response = (char*) malloc(respSize);
    if (response == NULL)
    {
        perror("error: malloc\n");
    }
    else
    {
        memset(response, '\0', respSize);
        // Status line
        strcat(response, HttpStatusLine);

        //Content type
        if (mimeType)
        {
            strcat(response, CONTENT_TYPE);
            strcat(response, mimeType);
            strcat(response, CRLF);
        }

        // Connection: close
        strcat(response, CONNECTION);
        // Content-Length: message body size
        strcat(response, CONTENT_LENGTH);
        sprintf(contentLenStr, "%zu", strlen(HttpRespMessageBody));
        strcat(response, contentLenStr);
        strcat(response, CRLF);

        strcat(response, CRLF);
        // Message body
        strcat(response, HttpRespMessageBody);
    }

    printf("\n Total response bytes: %zu\n", strlen(response));
    return response;
}

uint8_t exist_in_local_filesystem(char* filePath)
{
    struct stat buffer;
    // Checks if the given file exist in the filesystem or  not
    int exist = stat(filePath, &buffer);
    if(exist == 0) return 1;
    else return 0;
}

char* getFileContentsFromLocalFileSystem(char* filePath)
{
    char* fileContents = NULL;
    struct stat st;
    FILE *fp;
    //Calculate Content-length from the saved web page file in the directory
    if(stat(filePath, &st) != 0)
    {
        perror("error: stat\n");
        return NULL;
    }
    printf("File %s size: %zu\n", filePath, st.st_size);

    fileContents = (char*) malloc(sizeof(char) * st.st_size);
    fp = fopen(filePath, "rb");
    if(fp == NULL)
    {
        perror("error: fopen\n");
        return NULL;
    }
    // Read the file
    if (fread(fileContents, st.st_size, 1, fp) != 1)
    {
        perror("error: fread\n");
        free(fileContents);
        fileContents = NULL;
    }
    fileContents[st.st_size] = 0;

    fclose(fp);
    printf("filePath: %s\nfileContents:\n%s\n", filePath, fileContents);
    return fileContents;
}

void create_dir_file(client_request_t *clientRequest)
{
    char cmd[530]={0};
    char query[512]={0};
    char dir[512]={0};

    sprintf(query,"%s%s", clientRequest->host_str, clientRequest->request_URI);

    char* fileName = strrchr(query,'/');

    // Extract the file path excluding filename
    strncpy(dir, query, (int) (fileName - query));

    // create diretory
    sprintf(cmd,"mkdir -p %s", dir);    // Makes a new directory
    system(cmd);

    sprintf(cmd,"touch %s", query);  // Makes a new blank file
    system(cmd);
}

void dump_content_in_file(client_request_t *clientRequest,
                          char * buffer, ssize_t nbytes_total)
{
    char file_path[512]={0};
    sprintf(file_path,"%s%s", clientRequest->host_str, clientRequest->request_URI);

    FILE *fp = NULL;
    fp = fopen(file_path,"a");
    if(fp != NULL)
    {
        fwrite(buffer,1,nbytes_total,fp);  //write n bytes in the given file
    }
    fclose(fp);
}

uint64_t find_offset(const char* buffer, uint64_t len)
{
    uint64_t offset = 0;
    while(offset<len){
        if(buffer[offset]==0x0d && buffer[offset+1]==0x0a
           && buffer[offset+2]==0x0d && buffer[offset+3]==0x0a)
        {   // look for \r\n\r\n
            return offset + 4;   //traverse \r\n\r\n
        }
        offset++;
    }
    return 0;
}

int generate_http_request(client_request_t *clientRequest)
{
    char buffer[BUFSIZ]={0};
    enum CONSTEXPR { MAX_REQUEST_LEN = 1024};
    char request_string[MAX_REQUEST_LEN];
    char request_template[] = "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n";
    struct protoent *protoent;
    in_addr_t in_addr;
    int request_len;
    int socket_file_descriptor;
    ssize_t nbytes_total, nbytes_last;
    struct hostent *hostent;
    struct sockaddr_in sockaddr_in;
    int error = 0;

    request_len = snprintf(request_string, MAX_REQUEST_LEN,
                           request_template,
                           clientRequest->request_URI,
                           clientRequest->host_str);

    if (request_len >= MAX_REQUEST_LEN) {
        fprintf(stderr, "request length large: %d\n", request_len);
        return -1;
    }
    /* Builds the socket */
    protoent = getprotobyname("tcp");
    if (protoent == NULL) {
        perror("error: getprotobyname\n");
        return -1;
    }

    // creates a socket to send/receive packets
    socket_file_descriptor = socket(AF_INET, SOCK_STREAM, protoent->p_proto);
    if (socket_file_descriptor == -1)
    {
        perror("error: socket\n");
        return -1;
    }
    /* Builds the address */
    //resolve the input domain e.g., www.ptsv2.com
    hostent = gethostbyname(clientRequest->host_str);
    if (hostent == NULL) {
        herror("error: gethostbyname\n");
        fprintf(stderr, "error: gethostbyname(\"%s\")\n", clientRequest->host_str);
        error = -1;
        goto HTTP_REQ_END;
    }
    //generate a IPv4 packet and set system mac address
    in_addr = inet_addr(inet_ntoa(*(struct in_addr*)*(hostent->h_addr_list)));
    if (in_addr == (in_addr_t)-1) {
        fprintf(stderr,"error: inet_addr(\"%s\")\n", *(hostent->h_addr_list));
        error = -1;
        goto HTTP_REQ_END;
    }
    sockaddr_in.sin_addr.s_addr = in_addr;   //set addresses
    sockaddr_in.sin_family = AF_INET;     //IPv4
    sockaddr_in.sin_port = htons(HTTP_SERVER_PORT); // use always port 80

    /* Connects */
    //Connects to the web server
    if (connect(socket_file_descriptor, (struct sockaddr*) &sockaddr_in,
                sizeof(sockaddr_in)) == -1)
    {
        perror("error: connect\n");
        error = -1;
        goto HTTP_REQ_END;
    }

    /* Sends HTTP request */
    nbytes_total = 0;
    //Send HTTP request packet to the webServer
    nbytes_last = write(socket_file_descriptor, request_string + nbytes_total,
                        request_len - nbytes_total);
    if (nbytes_last == -1) {
        perror("error: write\n");
        goto HTTP_REQ_END;
    }

    uint8_t flag=0;
    char* file_start = NULL;  //pointer to find the index of \r\n\r\n
    uint8_t first_loop=0;
    uint64_t total_response = 0;
    while ((nbytes_total = read(socket_file_descriptor, buffer, BUFSIZ)) > 0)
    {    //reads the data/HTTP response from the socket
        total_response += nbytes_total;
        first_loop++;
        if(first_loop==1){
            create_dir_file(clientRequest);
            printf("HTTP request =\n%sLEN = %d\n", request_string, request_len);
            first_loop=1;
        }
        write(STDOUT_FILENO, buffer, nbytes_total);    // print the received data on screen
        if(flag==1)
        {
            // Continue dumping of the received data in the file
            //dump the received data in the file
            dump_content_in_file(clientRequest, buffer,nbytes_total);
            continue;
        }
        if(flag==0)
            file_start = strstr(buffer,"\r\n\r\n");
        if(file_start!=NULL)
        {
            uint64_t offset = find_offset(buffer,nbytes_total);
            dump_content_in_file(clientRequest,
                                 file_start+4, nbytes_total-offset);
            flag=1; //The body content has been started
        }
    }
    printf("\nTotal response size: %lu\n",total_response);
    if (nbytes_total == -1)
    {
        perror("error: read\n");
        error = -1;
    }
    HTTP_REQ_END:
    error = 0;
    close(socket_file_descriptor);
    return error;
}

char* getServerResponse(ServerResponseCode respCode,
                        client_request_t *clientRequest)
{
    char *response = NULL;
    char *filePath = NULL;
    char *fileContents = NULL;
    char *mimeType;

    switch (respCode)
    {
        case Http_Ok:
            // create response
            // Get the file from the request
            // If only "/" in path, set default file path
            if (strcmp("/", clientRequest->request_URI) == 0)
            {
                size_t filePathSize = strlen(clientRequest->host_str)
                                      + strlen(clientRequest->request_URI)
                                      + strlen(DEFAULT_FILE) + 2;

                filePath = malloc(sizeof(char) * filePathSize);
                if (filePath == NULL)
                {
                    perror("error: malloc\n");
                    return getHttpResponse(Http_StatusLine_500, Http_RespMsg_500,
                                           HTML_MIME_TYPE);
                }

                sprintf(filePath, "%s%s%s", clientRequest->host_str,
                        clientRequest->request_URI, DEFAULT_FILE);
                filePath[filePathSize] = 0;
            }
            else
            {
                size_t filePathSize = strlen(clientRequest->host_str)
                                      + strlen(clientRequest->request_URI);

                filePath = malloc(sizeof(char) * filePathSize);
                if (filePath == NULL)
                {
                    perror("error: malloc\n");
                    return getHttpResponse(Http_StatusLine_500, Http_RespMsg_500,
                                           HTML_MIME_TYPE);
                }

                sprintf(filePath, "%s%s%s", clientRequest->host_str,
                        clientRequest->request_URI, DEFAULT_FILE);

                filePath[filePathSize] = 0;
            }


            printf("filePath: %s\n", filePath);

            // get mime type
            mimeType = get_mime_type(filePath);

            // Check if file exists locally
            if (exist_in_local_filesystem(filePath))
            {
                printf("File is given from local filesystem\n");
                fileContents = getFileContentsFromLocalFileSystem(filePath);
            }
            else
            {
                // else fetch remotely
                // generate_http_request(&request);
                if (generate_http_request(clientRequest) != 0)
                {
                    if (filePath != NULL)
                        free(filePath);

                    return getHttpResponse(Http_StatusLine_500, Http_RespMsg_500,
                                           HTML_MIME_TYPE);
                }

                printf("File is given from origin server\n");
                fileContents = getFileContentsFromLocalFileSystem(filePath);
            }
            if (filePath != NULL)
                free(filePath);

            // generate response message body with fileContents
            if (fileContents != NULL)
                response = getHttpResponse(Http_StatusLine_200, fileContents, mimeType);
            else
                return getHttpResponse(Http_StatusLine_500, Http_RespMsg_500,
                                       HTML_MIME_TYPE);
            break;

        case Http_Bad_Request:
            response = getHttpResponse(Http_StatusLine_400, Http_RespMsg_400,
                                       HTML_MIME_TYPE);
            break;

        case Http_Forbidden:
            response = getHttpResponse(Http_StatusLine_403, Http_RespMsg_403,
                                       HTML_MIME_TYPE);;
            break;

        case Http_Not_Found:
            response = getHttpResponse(Http_StatusLine_404, Http_RespMsg_404,
                                       HTML_MIME_TYPE);
            break;

        case Http_Internal_Server_Error:
            response = getHttpResponse(Http_StatusLine_500, Http_RespMsg_500,
                                       HTML_MIME_TYPE);
            break;

        case Http_Method_Not_Implemented:
            response = getHttpResponse(Http_StatusLine_501, Http_RespMsg_501,
                                       HTML_MIME_TYPE);
            break;
    }

    printf("\n*** Response:\n%s\n", response);
    return response;
}

// serviceClientRequest services the client request using the passed client socket(exectuted by a thread of the threadpool).
int serviceClientRequest(void *arg) {
    int client_sock = *((int*) arg);
    char *client_message = NULL;
    client_request_t clientRequest;
    char *response = NULL;
    ServerResponseCode respCode;
    int error = -1;

    clientRequest.request_URI = NULL;
    clientRequest.host_str = NULL;

    printf("Servicing client request...\n");
    client_message = (char*) malloc(sizeof(char) * CLIENT_MSG_SIZE);
    if (client_message == NULL)
    {
        perror("error: malloc\n");
        goto end;
    }
    memset(client_message, '\0', (sizeof(char) * CLIENT_MSG_SIZE));

    // Receive client's message:
    if (recv(client_sock, client_message, CLIENT_MSG_SIZE, 0) < 0)
    {
        perror("error: recv from client\n");
        goto end;
    }
    printf("Message size; %zu\n", strlen(client_message));
    printf("Msg from client:\n%s\n", client_message);

    respCode = validateHTTPRequest(client_message, &clientRequest);
    printf("Response Code: %d\n", respCode);
    if (respCode == Http_Ok)
    {
        //  print request
        printf("HTTP request =\n%s\nLEN = %zu\n",
               client_message, strlen(client_message));
    }
    // Respond to client:
    response = getServerResponse(respCode, &clientRequest);
    if (response == NULL)
    {
        printf("Couldn't create response\n");
        goto end;
    }

    if (send(client_sock, response, strlen(response), 0) < 0)
    {
        perror("error: send to client\n");
        goto end;
    }
    error = 0; // Success

    end:
    close(client_sock);
    if (clientRequest.request_URI != NULL)
        free(clientRequest.request_URI);

    if (clientRequest.host_str != NULL)
        free(clientRequest.host_str);

    if (response != NULL)
        free(response);

    if (client_message != NULL)
        free(client_message);

    return error;
}

//Read the filter file and fill in the filter list. Exit on failure
void readFilterFile(char* filterFile)
{
    char *line = NULL;
    size_t len = 0;
    size_t numLines = 0;
    int i;

    // Read the filter file
    FILE *fp = fopen(filterFile, "r");
    if(fp == NULL)
    {
        perror("error: fopen\n");
        usage();
    }

    printf("\nReading filter file: %s", filterFile);
    // Get num. of lines in filter file
    while(getline(&line, &len, fp) != -1) {
        numLines++;
    }
    if (!numLines)
    {
        printf("File empty\n");
        usage();
    }
    // rewind the filter file
    rewind(fp);
    // allocate FILTER_BLOCK_SIZE memory for filterlist
    filterList.filterListArray = NULL;
    filterList.length = 0;
    filterList.size = sizeof(char)
                      * FILTER_LIST_ELEM_SIZE
                      * numLines;
    filterList.filterListArray = (char**) malloc(filterList.size);
    if (filterList.filterListArray == NULL)
    {
        perror("error: malloc\n");
        exit(EXIT_FAILURE);
    }

    // Read filter file line by line and store each item in filterList
    while(getline(&line, &len, fp) != -1) {
        //printf("\nline %s", line);
        filterList.filterListArray[filterList.length]
                = (char*) malloc(len);
        strncpy(filterList.filterListArray[filterList.length],
                line, len);
        //printf("\ncurr item:  %s", filterList.filterListArray[filterList.length]);
        ++filterList.length;
    }

    printf("\nDone reading filter file: %s\n", filterFile);
    fclose(fp);
    free(line);

    printf("\n*** filter list: \n");
    for(i = 0; i < filterList.length; ++i) {
        printf("item: %s", filterList.filterListArray[i]);
    }
    printf("\nfilter list end\n");
}

int main(int argc , char *argv[])
{
    uint32_t port = DEFAULT_PORT;
    uint32_t pool_size = 3;
    uint32_t max_num_requests = 5;
    char* filterFile = "./filter.txt";
    int i;

    // Thread stuff
    threadpool* tp = NULL;

    int server_sock, client_sock;
    socklen_t client_size;
    struct sockaddr_in server_addr, client_addr;
    int yes=1;
    struct sockaddr_in localAddress;
    socklen_t addressLength;

    // read & validate cmd-line arguments
    // proxyServer <port> <pool-size> <max-number-of-request> <filter>
    if(argc != 5)
        usage();

    // get the port num
    port = atoi(argv[1]);
    if (port == 0) {
        usage();
    }
    // get the pool-size
    pool_size = atoi(argv[2]);
    if (pool_size == 0) {
        usage();
    }
    // get the max_num_requests
    max_num_requests = atoi(argv[3]);
    if (max_num_requests == 0) {
        usage();
    }

    // get filter file name
    filterFile = argv[4];

    // Read the filter file
    readFilterFile(filterFile);

    // creates pool of threads, threads wait for jobs.
    tp = create_threadpool(pool_size);
    if (tp == NULL)
    {
        printf("error creating thread pool, exiting...\n");
        exit(EXIT_FAILURE);
    }

    // Create socket
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(server_sock < 0){
        perror("error: socket\n");
        goto END;
    }
    printf("Socket created successfully\n");

    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &yes,
                   sizeof(int)) == -1) {

        perror("error: setsockopt\n");
        goto END1;
    }

    // Set port and IP:
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);
    memset(server_addr.sin_zero, '\0', sizeof server_addr.sin_zero);

    // Bind to the set port and IP:
    if(bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr))<0)
    {
        perror("error: bind\n");
        goto END1;
    }
    printf("Done with binding\n");

    // Get local address and port
    addressLength = sizeof(localAddress);
    getsockname(server_sock, (struct sockaddr*) &localAddress,
                &addressLength);

    printf("Server running at IP: %s and port: %i\n",
           inet_ntoa(localAddress.sin_addr), ntohs(localAddress.sin_port));

    // Listen for clients
    if(listen(server_sock, SOMAXCONN) < 0){
        perror("error: listen\n");
        goto END1;
    }

    client_size = sizeof(client_addr);

    while(max_num_requests)
    {
        // printf("\nListening for incoming connections.....on port: %d\n", port);
        // Accept an incoming connection:
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_size);
        if (client_sock < 0){
            perror("error: listen\n");
            goto END1;
        }
        max_num_requests--;
        printf("Num of request remain: %d\n", max_num_requests);

        printf("Client connected at IP: %s and port: %i\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        //serviceClientRequest(&client_sock);
        // Queue the client connection in threadpool to service it
        dispatch(tp, serviceClientRequest, &client_sock);
    }

    END1:
    // Closing the socket:
    close(server_sock);

    END:
    printf("Exiting...\n");
    destroy_threadpool(tp);

    for(i = 0; i < filterList.length; ++i) {
        if (filterList.filterListArray[i] != NULL)
            free(filterList.filterListArray[i]);
    }
    free(filterList.filterListArray);
    filterList.filterListArray = NULL;

    return 0;
}

