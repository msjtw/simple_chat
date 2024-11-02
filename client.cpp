#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <cstring>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

const char PORT[] = "3490";
const int MAXDATASIZE = 100;

void *get_in_addr(sockaddr *sa){
    if(sa->sa_family == AF_INET){
        return &(((sockaddr_in *)sa)->sin_addr);
    }

    return &(((sockaddr_in6 *)sa)->sin6_addr);
}

int main (int argc, char *argv[]) {
    int socket_fd;
    addrinfo hints, *servinfo, *p;
    char s[INET6_ADDRSTRLEN];

    if(argc != 2){
        std::cerr << "usage: clinet hostname" << std::endl;
        exit(1);
    }

    std::memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int gai_error_code;
    if((gai_error_code = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0){
        std::cerr << "getaddrinfo: " << gai_strerror(gai_error_code);
    }

    for(p = servinfo; p != NULL; p = p->ai_next){
    if((socket_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
            perror("client: socket");
            continue;
        }
        if(connect(socket_fd, p->ai_addr, p->ai_addrlen) == -1){
            perror("client connect");
            close(socket_fd);
            continue;
        }

        break;
    }

    if(p == NULL){
        std::cerr << "client: failed to connect" << std::endl;
        exit(2);
    }

    inet_ntop(p->ai_family, get_in_addr((sockaddr *)p->ai_addr), s, sizeof s);
    std::cout << "client connected to: " << s << std::endl;

    freeaddrinfo(servinfo);

    while(true){
        std::string messg_send;
        std::cin >> messg_send;
        std::cout << "client sending: " << messg_send << ", size: " << messg_send.size() << std::endl;
        
        if(send(socket_fd, messg_send.c_str(), messg_send.length(), 0) == -1){
            perror("send");
            exit(1);
        }

        if(messg_send == "exit"){
            break;
        }

        std::string messg_recv;
        char buff_recv[MAXDATASIZE];
        int recv_byes;
        if((recv_byes = recv(socket_fd, buff_recv, MAXDATASIZE-1, 0)) == -1){
            perror("recv");
            exit(1);
        }

        buff_recv[recv_byes] = '\0';
        messg_recv = std::string(buff_recv);

        std::cout << "client recieved: " << messg_recv << std::endl;

    }

    close(socket_fd);

    return 0;
}
