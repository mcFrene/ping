#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <cstring>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4996)

using namespace std;

const short max_data_size = 72;
const short packets_qty = 4;
const short default_ttl = 30;
const short timeout = 4000;
const short send_interval = 1000;

const BYTE ICMP_ECHO_REQUEST = 8;
const BYTE ICMP_DEST_UNREACH = 3;
const BYTE ICMP_TTL_EXPIRE = 11;
const BYTE ICMP_ECHO_REPLY = 0;

const short PING_SUCCESS = 0;
const short IP_FAILED = 1;
const short SELECT_FAILED = 2;
const short SEND_FAILED = 3;


struct icmp_packet{
    BYTE type;
    BYTE code;
    USHORT checksum;
    USHORT id;
    USHORT seq;
    GUID data;
};

struct packets_time{
    struct icmp_packet* packet;
    int time;
    bool status;
};

struct ip_packet{
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
    icmp_packet icmp;
};

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

void icmp_packet_init(icmp_packet* packet, BYTE type, BYTE code, USHORT id, USHORT seq){
    packet->type = type;
    packet->code = code;
    packet->checksum = 0;
    packet->id = id;
    packet->seq = seq;
    CoCreateGuid(&packet->data);
    packet->checksum = generate_checksum((USHORT*)packet, sizeof(icmp_packet));
}

int send_packet(icmp_packet* packet, SOCKET sd, sockaddr_in dest){
    return sendto(sd, (char*)packet, sizeof(icmp_packet), 0,(sockaddr*)&dest, sizeof(dest));
}

int receive_packet(BYTE* recieve_buffer, SOCKET sd, sockaddr_in source){
    int fromlen = sizeof(source);
    return recvfrom(sd, (char*)recieve_buffer, max_data_size, 0, (sockaddr*)&source, &fromlen);
}

bool is_all_processed(vector<packets_time>& packets_to_send, int packets_qty){
    for(int i=0; i<packets_qty; i++){
        if(!packets_to_send[i].status)
            return false;
    }
    return true;
}

void print_stat(vector<packets_time>& packets_to_send, int packets_qty, char* ip){
    int rec_qty = 0;
    int lost_qty = 0;
    for(int i=0; i<packets_qty; i++){
        if(packets_to_send[i].status)
            rec_qty++;
        else
            lost_qty++;
    }

    cout<<endl<<"Stats for "<<ip<<":"<<endl;
    cout<<"Packets: sended="<<packets_qty<<" recieved="<<rec_qty<<" lost="<<lost_qty<<endl;
    cout<<"(lost "<<int(lost_qty*100/packets_qty)<<"%)"<<endl<<endl;
}

short ping(char* ip, short ttl, SOCKET sd, sockaddr_in &dest, sockaddr_in& source){
    unsigned int addr = inet_addr(ip);
    if (addr != INADDR_NONE)
        dest.sin_addr.s_addr = addr;
    else
        return IP_FAILED;

    vector<packets_time> packets_to_send(packets_qty);
    USHORT id = (USHORT)GetCurrentProcessId();
    for(int i=0; i<packets_qty; i++){
        packets_to_send[i].packet = new icmp_packet;
        icmp_packet_init(packets_to_send[i].packet, ICMP_ECHO_REQUEST, 0, id, i);
        packets_to_send[i].status = false;
    }

    fd_set read_s;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 1;

    int selectResult;
    short send_counter = 0;
    while(!is_all_processed(packets_to_send, packets_qty)){
        if(send_counter == 0 || (send_counter < packets_qty && GetTickCount64() - packets_to_send[send_counter-1].time >= send_interval)){

            if(send_packet(packets_to_send[send_counter].packet, sd, dest) == SOCKET_ERROR)
                return SEND_FAILED;

            packets_to_send[send_counter].time = GetTickCount64();
            send_counter++;
        }

        FD_ZERO(&read_s);
        FD_SET(sd, &read_s);
        selectResult = select(0, &read_s, NULL, NULL, &tv);
        if(FD_ISSET(sd, &read_s)){
            BYTE recieve_buffer[max_data_size];
            receive_packet(recieve_buffer, sd, source);

            ip_packet* received_packet = (ip_packet*)recieve_buffer;
            BYTE type = received_packet->icmp.type;

            vector<int> reply_ip;
            if(received_packet->icmp.type != ICMP_ECHO_REPLY){
                for(int i=0; i<4; i++)
                    reply_ip.push_back((received_packet->source_ip >> (8 * (3 - i))) & 0xFF);
                received_packet = (ip_packet*)(recieve_buffer+28);
            }
            USHORT seq = received_packet->icmp.seq;

            if(IsEqualGUID(packets_to_send[seq].packet->data, received_packet->icmp.data)){
                switch(type){
                    case ICMP_ECHO_REPLY:
                        cout<<"Reply from "<<ip<<": bytes="<<sizeof(icmp_packet)<<" time="<<GetTickCount64() - packets_to_send[seq].time<<"ms "
                             <<"TTL="<<int(received_packet->ttl)<<" seq="<<seq<<endl;
                        break;
                    case ICMP_DEST_UNREACH:
                        cout<<"Reply from "<<reply_ip[0]<<"."<<reply_ip[1]<<"."<<reply_ip[2]<<"."<<reply_ip[3]<<": "
                            <<"Destination unreachable seq=" << seq << endl;
                        break;
                    case ICMP_TTL_EXPIRE:
                        cout<<"Reply from "<<reply_ip[0]<<"."<<reply_ip[1]<<"."<<reply_ip[2]<<"."<<reply_ip[3]<<": "
                            <<"TTL expired seq=" << seq << endl;
                        break;
                }
                packets_to_send[seq].status = true;
            }
        }
        else if(selectResult == 0){
            for(int i=0; i<send_counter; i++){
                if(!packets_to_send[i].status &&  GetTickCount64() - packets_to_send[i].time >= timeout){
                    cout<<"Timeout seq="<<i<<endl;
                    packets_to_send[i].status = true;
                }
            }
        }
        else if (selectResult == SOCKET_ERROR){
            return SELECT_FAILED;
        }
    }

    print_stat(packets_to_send, packets_qty, ip);

    for(int i = 0; i < packets_qty; i++){
        delete packets_to_send[i].packet;
    }

    return PING_SUCCESS;
}

int main(int argc, char* argv[]){
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

    if (setsockopt(sd, IPPROTO_IP, IP_TTL, (const char*)&default_ttl, sizeof(default_ttl)) == SOCKET_ERROR) {
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


    int flag;
    if(argc > 1){
        flag = ping(argv[1], default_ttl, sd, dest, source);
    }
    else{
        char ip[16];
        cout<<"IP for ping: ";
        cin>>ip;
        flag = ping(ip, default_ttl, sd, dest, source);
    }


    switch(flag){
        case IP_FAILED:
            cout << "Failed to resolve current ip" << endl;
            break;
        case SELECT_FAILED:
            cout << "Select failed: " << WSAGetLastError() << endl;
            break;
        case SEND_FAILED:
            cout << "Send failed: " << WSAGetLastError() << endl;
            break;
    }

    WSACleanup();
    return 0;
}
