#include <asm-generic/socket.h>
#include <csignal>
#include <cstdio>
#include <iostream>
#include <string>
#include <sys/wait.h>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <cerrno>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

const char PORT[] = "3490";
const int BACKLOG = 10;
const int MAXDATASIZE = 100;

void sigchld_handler(int s){
(void)s; // quiet unused variable warning

	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while(waitpid(-1,NULL, WNOHANG) > 0);

	errno = saved_errno;
}

void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main (int argc, char *argv[]) {
    int socket_fd, new_fd;
    addrinfo hints, *serv_info;
    sockaddr_storage their_addr;
    socklen_t sin_size;
    char s[INET6_ADDRSTRLEN];

    std::memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int gai_error_code;
    if((gai_error_code = getaddrinfo(NULL, PORT, &hints, &serv_info)) != 0){
        std::cerr << "getaddresinfo: " << gai_strerror(gai_error_code) << std::endl;
        return 1;
    }

    for(addrinfo *p = serv_info; p != NULL; p = p->ai_next){
        if((socket_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
            perror("server scoket: ");
            continue;
        }
        int yes = 1;
        if(setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1){
            perror("server setsockopt: ");
            exit(1);
        }
        if(bind(socket_fd, p->ai_addr, p->ai_addrlen) == -1){
            close(socket_fd);
            perror("server bind: ");
            continue;
        }

        if(p->ai_next == NULL){
            std::cerr << "server failed to bind" << std::endl;
            exit(1);
        }

        break;

    }


    freeaddrinfo(serv_info);

    if(listen(socket_fd, BACKLOG) == -1){
        perror("server listen: ");
        exit(1);
    }

    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
            perror("sigaction");
            exit(1);
    }

    std::cout << "Waiting for connections..." << std::endl;

    while(true){
        sin_size = sizeof their_addr;
        new_fd = accept(socket_fd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept: ");
            continue;
        }
        
        // get their ip adress from their_addr and convert it into string
        inet_ntop(their_addr.ss_family, 
                  get_in_addr((sockaddr *)&their_addr), s, sizeof s);
        std::cout << "Got connection from: " << s  << std::endl;

        if(!fork()){
            close(socket_fd);
            std::string messg;
            char buff[MAXDATASIZE];
            int recv_bytes;

            while((recv_bytes = recv(new_fd, buff, MAXDATASIZE, 0)) > 0){
                buff[recv_bytes] = '\0';
                messg = std::string(buff);
                std::cout << "server recieved: " << buff << std::endl;
                if(messg == "exit"){
                    break;
                }
                if(send(new_fd, messg.c_str(), messg.length(), 0) == -1){
                    perror("send");
                }
                std::cout << "server send: " << messg << std::endl;
            }

            close(new_fd);
            exit(0);

        }

        close(new_fd);
    }

    return 0;
}
