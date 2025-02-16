#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4996);

using namespace std;

const short data_size = 32;
const short max_data_size = 64;
const short packets_qty = 4;
const short ttl = 30;
const short timeout = 4000;
const short send_interval = 1000;

const char symbols[]  = "abcdefghijklmnopqrstuvwxyz0123456789";

const BYTE ICMP_ECHO_REQUEST = 8;
const BYTE ICMP_DEST_UNREACH = 3;
const BYTE ICMP_TTL_EXPIRE = 11;
const BYTE ICMP_ECHO_REPLY = 0;

const short PING_SUCCESS = 0;
const short STOP_PING = 1;
const short IP_FAILED = 2;
const short SELECT_FAILED = 3;


class icmp_packet{
    void generate_random_data(BYTE* data, short length){
        for(short i=0; i<length; i++){
            data[i] = symbols[rand() % (sizeof(symbols) - 1)];
        }
        data[length] = '\0';
    }

    USHORT generate_checksum(USHORT* buffer, int size) {
        unsigned long cksum = 0;

        while (size > 1){
            cksum += *buffer++;
            size -= sizeof(USHORT);
        }
        if (size){
            cksum += *(UCHAR*)buffer;
        }

        cksum = (cksum >> 16) + (cksum & 0xffff);
        cksum += (cksum >> 16);

        return (USHORT)(~cksum);
    }

public:
    BYTE type;
    BYTE code;
    USHORT checksum;
    USHORT id;
    USHORT seq;
    BYTE data[max_data_size + 1];

    icmp_packet(BYTE type, BYTE code, USHORT id, USHORT seq){
        this->type = type;
        this->code = code;
        this->checksum = 0;
        this->id = id;
        this->seq = seq;
        generate_random_data(this->data, data_size);
        this->checksum = generate_checksum((USHORT*)this, data_size + 8);
    }

    int send_packet(SOCKET sd, sockaddr_in dest, int delay=0){


        this_thread::sleep_for(chrono::milliseconds(delay));
        return sendto(sd, (char*)this, data_size + 8, 0,(sockaddr*)&dest, sizeof(dest));
    }
};

class ip_packet {
public:
    BYTE h_len_version;
    BYTE tos;
    USHORT total_len;
    USHORT ident;
    USHORT flags;
    BYTE ttl;
    BYTE proto;
    USHORT checksum;
    ULONG source_ip;
    ULONG dest_ip;
    icmp_packet icmp = icmp_packet(0, 0, 0, 0);

    int recv_packet(SOCKET sd, sockaddr_in source){
        int fromlen = sizeof(source);
        return recvfrom(sd, (char*)this, sizeof(ip_packet), 0, (sockaddr*)&source, &fromlen);
    }

    bool is_mine(BYTE type, icmp_packet* packets_to_send[], int* times, int packets_qty, USHORT seq){
        if(seq >= packets_qty || !times[seq] || times[seq] == -1)
            return false;

        if(this->icmp.type == ICMP_ECHO_REPLY){
            return strcmp(
                reinterpret_cast<const char*>(packets_to_send[seq]->data),
                reinterpret_cast<const char*>(this->icmp.data)) == 0;
        }
        else{
            ip_packet* err_packet = (ip_packet*)this->icmp.data;
            return err_packet->icmp.type == packets_to_send[seq]->type &&
                err_packet->icmp.code == packets_to_send[seq]->code &&
                err_packet->icmp.id == packets_to_send[seq]->id &&
                err_packet->icmp.seq == packets_to_send[seq]->seq &&
                err_packet->icmp.checksum == packets_to_send[seq]->checksum;
        }
    }
};

bool is_all_processed(int* times, int packets_qty){
    for(int i=0; i<packets_qty; i++){
        if(times[i] && times[i] != -1)
            return false;
    }
    return true;
}

void print_stat(int* times, int packets_qty, char* ip){
    int rec_qty = 0;
    int lost_qty = 0;
    for(int i=0; i<packets_qty; i++){
        if(!times[i])
            rec_qty++;
        else if(times[i] == -1)
            lost_qty++;
    }

    cout<<endl<<"Stats for "<<ip<<":"<<endl;
    cout<<"Packets: sended="<<packets_qty<<" recieved="<<rec_qty<<" lost="<<lost_qty<<endl;
    cout<<"(lost "<<int(lost_qty*100/packets_qty)<<"%)"<<endl<<endl;
}

short ping(SOCKET sd, sockaddr_in &dest, sockaddr_in& source){
    char ip[32];
    cout<<"Enter IP to ping : ";
    cin>>ip;

    if(strcmp(ip, "stop") == 0)
        return STOP_PING;

    unsigned int addr = inet_addr(ip);
    if (addr != INADDR_NONE) {
        // It was a dotted quad number, so save result
        dest.sin_addr.s_addr = addr;
    }
    else {
        // Not in dotted quad form, so try and look it up
        hostent* hp = gethostbyname(ip);
        if (hp != 0) {
            // Found an address for that host, so save it
            memcpy(&(dest.sin_addr), hp->h_addr, hp->h_length);
        }
        else {
            // Not a recognized hostname either!
            return IP_FAILED;
        }
    }


    icmp_packet* packets_to_send[packets_qty];
    USHORT id = (USHORT)GetCurrentProcessId();

    int times[packets_qty];
    for(int i=0; i<packets_qty; i++){
        times[i] = 1;
    }


    fd_set read_s;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 1;

    int selectResult;
    short send_counter = 0;
    while(!is_all_processed(times, packets_qty)){
        int current_time = GetTickCount64();
        if(!send_counter || (send_counter < packets_qty && current_time - times[send_counter-1] >= send_interval)){
            FD_ZERO(&read_s);
            FD_SET(sd, &read_s);
            selectResult = select(0, NULL, &read_s, NULL, &tv);
            if(selectResult > 0){
                packets_to_send[send_counter] = new icmp_packet(ICMP_ECHO_REQUEST, 0, id, send_counter);
                packets_to_send[send_counter]->send_packet(sd, dest);
                times[send_counter] = GetTickCount64();
                send_counter++;
            }
            else if (selectResult == SOCKET_ERROR){
                return SELECT_FAILED;
            }
        }
        FD_ZERO(&read_s);
        FD_SET(sd, &read_s);
        selectResult = select(0, &read_s, NULL, NULL, &tv);
        if(selectResult > 0){
            current_time = GetTickCount64();
            ip_packet* recv_packet = new ip_packet;
            recv_packet->recv_packet(sd, source);

            USHORT seq = recv_packet->icmp.type == ICMP_ECHO_REPLY ? recv_packet->icmp.seq : ((ip_packet*)recv_packet->icmp.data)->icmp.seq;
            switch(recv_packet->icmp.type){
                case ICMP_ECHO_REPLY:
                    if(recv_packet->is_mine(ICMP_ECHO_REPLY, packets_to_send, times, packets_qty, seq)){
                        cout<<"Reply from "<<ip<<": bytes="<<data_size<<" time="<<current_time - times[seq]<<"ms "
                        <<"TTL="<<int(recv_packet->ttl)<<" seq="<<seq<<endl;
                        times[seq] = 0;
                        break;
                    }
                case ICMP_DEST_UNREACH:
                    if(recv_packet->is_mine(ICMP_DEST_UNREACH, packets_to_send, times, packets_qty, seq)){
                        cout << "Destination unreachable seq=" << seq << endl;
                        times[seq] = -1;
                        break;
                    }
                case ICMP_TTL_EXPIRE:
                    if(recv_packet->is_mine(ICMP_DEST_UNREACH, packets_to_send, times, packets_qty, seq)){
                        cout << "TTL expired seq=" << seq << endl;
                        times[seq] = -1;
                        break;
                    }
            }
        }
        else if(selectResult == 0){
            current_time = GetTickCount64();
            for(int i=0; i<packets_qty; i++){
                if(times[i] != 1 && times[i] && times[i] != -1 && current_time - times[i] >= timeout){
                    times[i] = -1;
                    cout<<"Timeout seq="<<i<<endl;
                }
            }
        }
        else if (selectResult == SOCKET_ERROR){
            return SELECT_FAILED;
        }
    }

    print_stat(times, packets_qty, ip);
    return PING_SUCCESS;
}

int main(){
    WSAData wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cout << "Failed to find Winsock 2.2 or better." << endl;
        return -1;
    }

    SOCKET sd = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, 0, 0, 0);

    if (sd == INVALID_SOCKET) {
        cout << "Failed to create raw socket: " << WSAGetLastError() << endl;
        return -1;
    }

    if (setsockopt(sd, IPPROTO_IP, IP_TTL, (const char*)&ttl, sizeof(ttl)) == SOCKET_ERROR) {
        cout << "TTL setsockopt failed: " << WSAGetLastError() << endl;
        return -1;
    }

    ULONG i_mode = 1;
    if(ioctlsocket(sd, FIONBIO, &i_mode) == SOCKET_ERROR){
        cout << "Failed to configure socket: " << WSAGetLastError() << endl;
        return -1;
    }

    sockaddr_in dest, source;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;

    bool flag = true;
    while(flag){
        switch(ping(sd, dest, source)){
            case PING_SUCCESS:
                break;
            case IP_FAILED:
                cout << "Failed to resolve current ip" << endl;
                flag = false;
                break;
            case SELECT_FAILED:
                cout << "Select failed: " << WSAGetLastError() << endl;
                flag = false;
                break;
            case STOP_PING:
                cout << "Program stoped" << endl;
                flag = false;
                break;
        }
    }
    WSACleanup();
    return 0;
}
