#include <asm-generic/socket.h>
#include <csignal>
#include <cstdio>
#include <iostream>
#include <map>
#include <queue>
#include <string>
#include <sys/poll.h>
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
#include <poll.h>

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

void *get_in_addr(struct sockaddr *sa){
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int get_listener_socket(){
    int socket_fd;
    addrinfo hints, *serv_info, *p;
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

    for(p = serv_info; p != NULL; p = p->ai_next){
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
        break;
    }

    if(p->ai_next == NULL){
        std::cerr << "server failed to bind" << std::endl;
        exit(1);
    }

    freeaddrinfo(serv_info);

    if(listen(socket_fd, BACKLOG) == -1){
        perror("server listen: ");
        exit(1);
    }

    return socket_fd;
}

class pfds_set{
private:
        pollfd *pfds;
        int fd_size;
        int fd_count;
public:
    pfds_set(){
        fd_size = 1;
        fd_count = 0;
        pfds = (pollfd *)malloc(sizeof *pfds * fd_size);
    }

    ~pfds_set(){
        delete [] pfds;
    }

    void insert(int fd){
        if(fd_count == fd_size){
            fd_size <<= 1;
            pfds = (pollfd *)realloc(pfds, sizeof(*pfds)*(fd_size));
        }
        pfds[fd_count].fd = fd;
        pfds[fd_count].events = POLL_IN;
        fd_count++;
    }

    int erase(int fd){
        int i = 0;
        for(; i < fd_size and pfds[i].fd != fd; i++);
        if(pfds[i].fd == fd){
            pfds[i] = pfds[fd_count-1];
            fd_count--;
            return fd_count;
        }
        return -1;
    }

    int size(){
        return fd_count;
    }

    pollfd * begin(){
        return pfds;
    }

    pollfd * end(){
        return pfds + fd_count*sizeof(*pfds);
    }
};

struct message{
    int type;
    unsigned int size;
    char source[16];
    char destination[16];
    std::string content;
};

class connection{

private:
    std::queue<char> bytes;
    unsigned int left_to_read = 0;
    int fd;

public:
    std::queue<message> messages;
    std::string user;
    connection(){
        left_to_read = 0;
    }
    connection(int fd){
        this->fd = fd;
        left_to_read = 0;
    }

    void process_bytes(char c[], int n){
        for(int i = 0; i < n; i++){
            bytes.push(c[i]);
        }
        if(bytes.size() >= 4 and left_to_read == 0){
            for(int i = 0; i < 4; i++){
                left_to_read <<= 8;
                left_to_read += bytes.front();
                bytes.pop();
            }
        }
        if(bytes.size() >= left_to_read){
            messages.push(get_message());
        }
    }

    message get_message(){
        message m;
        m.size = left_to_read;
        m.type = bytes.front();
        bytes.pop();
        for(int i = 0; i < 16; i++){
            m.source[i] = bytes.front();
            bytes.pop();
        }
        for(int i = 0; i < 16; i++){
            m.destination[i] = bytes.front();
            bytes.pop();
        }
        for(int i = 0; i < m.size-33; i++){
            m.content += bytes.front();
            bytes.pop();
        }
        return m;
    }

    int send_message(message m){
        int curr_byte = 0;
        char *bmessg = (char *)malloc(m.size+4 * sizeof(char));

        uint byte_mask = 1111U << 24;
        char byte = (m.size & byte_mask) >> 24;
        bmessg[curr_byte] = byte;
        curr_byte++;
        for(int i = 16; i >= 0; i-=8){
            byte_mask >>= 8;
            byte = (m.size & byte_mask) >> i;
            bmessg[curr_byte] = byte;
            curr_byte++;
        }

        for(int i = 0; i < 16; i++){
            bmessg[curr_byte] = m.source[i];
            curr_byte++;
        }
        for(int i = 0; i < 16; i++){
            bmessg[curr_byte] = m.destination[i];
            curr_byte++;
        }
        for(char c : m.content){
            bmessg[curr_byte] = c;
            curr_byte = 0;
        }

        int total = 0;
        int bytes_left = m.size;
        int n;

        while(total < m.size+4){
            n = send(fd, bmessg+total, bytes_left, 0);
            if(n == -1){
                return total;
            }
            total += n;
            bytes_left -= n;
        }

        delete [] bmessg;
        return 0;
    }
};




int main (int argc, char *argv[]) {
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
            perror("sigaction");
            exit(1);
    }

    int listener = get_listener_socket();

    pfds_set pfds;
    pfds.insert(listener);

    std::map<int, connection> socket_connection_map;
    std::map<std::string, int> user_socket_map;

    std::cout << "waiting for connections..." << std::endl;

    while(true){
        int poll_count = poll(pfds.begin(), pfds.size(), -1);
        if(poll_count == -1){
            perror("poll");
            exit(1);
        }
        for(int i = 0; i < pfds.size(); i++){
            auto pollres = pfds.begin()[i];
            if(!(pollres.revents & POLLIN))
                continue;
            int fd = pollres.fd;
            if(fd == listener){
                int new_fd;
                sockaddr_storage remote_addr;
                socklen_t addrlen;
                char remoteIP[INET6_ADDRSTRLEN];

                addrlen = sizeof remote_addr;
                new_fd = accept(listener, (sockaddr *)&remote_addr, &addrlen);

                if(new_fd == -1){
                    perror("accept");
                }
                else{
                    pfds.insert(new_fd);
                    connection c(new_fd);
                    socket_connection_map.insert({new_fd, c});
                    std::cout << "server: new connection from " << inet_ntop(remote_addr.ss_family, get_in_addr((struct sockaddr*)&remote_addr), remoteIP , INET6_ADDRSTRLEN) << ", on socket: " << new_fd <<  std::endl;
                }

            }
            else{
                char buff[MAXDATASIZE];
                std::string messg;
                int recv_bytes = recv(fd, buff, sizeof buff, 0);
                buff[recv_bytes] = '\0';
                messg = std::string(buff);

                if(recv_bytes <= 0){
                    if(recv_bytes == 0){
                        user_socket_map.erase(socket_connection_map[fd].user);
                        socket_connection_map.erase(fd);
                        std::cout << "server: socket " << fd << " hung up. BYE!" << std::endl;
                    }
                    else{
                        std::cout << fd << " ";
                        perror("recv");
                    }
                    close(fd);
                    pfds.erase(fd);
                }
                else{
                    socket_connection_map[fd].process_bytes(buff, recv_bytes);
                    while(!socket_connection_map[fd].messages.empty()){
                        message m = socket_connection_map[fd].messages.front();
                        socket_connection_map[fd].messages.pop();
                        if(m.type == 0){
                            socket_connection_map[user_socket_map[std::string(m.destination)]].send_message(m);
                        }
                        else{
                            user_socket_map[m.source] = fd;
                            socket_connection_map[fd].user = std::string(m.source);
                        }
                    }
                }
            }
        }
    }

    return 0;
}
