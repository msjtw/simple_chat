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
#include <poll.h>
#include <arpa/inet.h>
#include <cerrno>
#include <queue>
#include <bitset>
#include <fcntl.h>

using namespace  std;

const char PORT[] = "3490";
const int MAXDATASIZE = 256;

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
        pfds[fd_count].events = POLLIN;
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

    message(){
        for(int i = 0; i < 16; i++){
            source[i] = '\0';
            destination[i] = '\0';
        }
    }
};

class connection{

private:
    std::queue<char> bytes;
    unsigned int left_to_read = 0;
    int fd;

public:
    std::queue<message> messages;
    char user[16];
    connection(){
        left_to_read = 0;
        for(int i = 0 ; i < 16; i++){
            user[i] = '\0';
        }
    }
    connection(int fd){
        this->fd = fd;
        left_to_read = 0;
        for(int i = 0 ; i < 16; i++){
            user[i] = '\0';
        }
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
        left_to_read = 0;
        return m;
    }

    int send_message(message m){
        int curr_byte = 0;
        char *bmessg = (char *)malloc((m.size+10) * sizeof(char));
        uint byte_mask = ((1<<8)-1) << 24;
        char byte = (m.size & byte_mask) >> 24;
        bmessg[curr_byte] = byte;
        curr_byte++;
        for(int i = 16; i >= 0; i-=8){
            byte_mask >>= 8;
            byte = (m.size & byte_mask) >> i;
            bmessg[curr_byte] = byte;
            curr_byte++;
        }

        bmessg[curr_byte] = m.type;
        curr_byte++;

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
            curr_byte++;
        }

        int total = 0;
        int bytes_left = m.size+4;
        
        while(total < m.size+4){
            int n = send(fd, bmessg+total, bytes_left, 0);
            if(n == -1){
                return total;
            }
            total += n;
            bytes_left -= n;
        }

        delete [] bmessg;
        cout << "send ok" << endl;
        return 0;
    }

    message process_input(std::string input){
        message m;
        if(input[0] != '/'){

        }
        else{
            string command;
            int pos = 0;
            while(input[pos] != ' '){
                command += input[pos];
                pos ++;
            }
            pos ++;
            if(command == "/to"){
                string dest;
                while(input[pos] != ' '){
                    dest += input[pos];
                    pos++;
                }
                pos ++;
                std::string messg = input.substr(pos, string::npos);
                
                m.type = 0;
                m.size = 33 + messg.size();
                strcpy(m.source, user);
                strcpy(m.destination, dest.c_str());
                m.content = messg;
            }
        }

        return m;
    }
};

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

    if(argc != 3){
        std::cerr << "usage: clinet hostname username" << std::endl;
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

    pfds_set pfds;
    pfds.insert(socket_fd);
    pfds.insert(0);

    connection c(socket_fd);
    strcpy(c.user, argv[2]);
    message auth_messg;
    auth_messg.size = 33;
    auth_messg.type = 1;
    strcpy(auth_messg.source, c.user);
    strcpy(auth_messg.destination, c.user);
    c.send_message(auth_messg);

    while(true){

        int poll_count = poll(pfds.begin(), pfds.size(), -1);
        if(poll_count == -1){
            std::perror("poll");
            exit(1);
        }
        for(int i = 0; i < pfds.size(); i++){
            auto pollres = pfds.begin()[i];
            if(!(pollres.revents & POLLIN))
                continue;
            int fd = pollres.fd;
            if(fd == 0){
                char buff[MAXDATASIZE];
                std::string messg;
                int recv_bytes = read(fd, buff, sizeof buff);
                buff[recv_bytes-1] = '\0';
                messg = std::string(buff);

                if(messg.size() > MAXDATASIZE){
                    std::cout << "hold up, cowboy" << std::endl;
                    continue;
                }
                c.send_message(c.process_input(messg));
            }
            else{
                char buff[MAXDATASIZE];
                std::string messg;
                int recv_bytes = recv(fd, buff, sizeof buff, 0);
                buff[recv_bytes] = '\0';
                messg = std::string(buff);

                if(recv_bytes <= 0){
                    perror("recv");
                    close(socket_fd);
                    exit(1);
                }
                else{
                    c.process_bytes(buff, recv_bytes);
                    while(!c.messages.empty()){
                        message m = c.messages.front();
                        c.messages.pop();
                        std::cout << "got message from: " << m.source << " \"" << m.content << "\"" << std::endl;
                    }
                }
            }
        }
    }

    close(socket_fd);

    return 0;
}
