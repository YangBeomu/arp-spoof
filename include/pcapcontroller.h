#ifndef PCAPCONTROLLER_H
#define PCAPCONTROLLER_H

#include <QObject>
#include <QString>
#include <QDebug>

#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <unistd.h>

#include <vector>
#include <string>
#include <iostream>

#include <thread>
#include <mutex>
#include <condition_variable>

#include <pcap.h>

#include "../../include/mac.h"
#include "../../include/ethhdr.h"
#include "../../include/arphdr.hpp"
#include "../../include/iphdr.hpp"
#include "../../include/tcphdr.hpp"


class PcapController : public QObject
{
    Q_OBJECT
protected:
    struct RecvData final {
        pcap_pkthdr* header{};
        u_char* buf{};

        bool empty() {
            if(header == NULL && buf == NULL) return true;

            return false;
        }
    };

private:
    struct InterfaceInfo final {
        std::string interfaceName_;
        Mac mac_;
    };



    //std::vector<pcap_t*> pcaps_{};
    pcap_t* pcap_ = nullptr;
    std::vector<InterfaceInfo> interfaceInfos_{};

    //std::vector<RecvData> recvDatas_{};
    RecvData recvData_{};

    void InitInterfaceInfo();
    void WarningMessage(const QString msg);

protected:
    InterfaceInfo cInterfaceInfo_{};

    enum {
        STATUS_ERROR,
        STATUS_INIT,
        STATUS_PAUSE,
        STATUS_PLAY,
        STATUS_END
    };

    std::thread hPThread_;
    std::mutex mtx_;
    std::condition_variable cv_;
    int status_ = STATUS_INIT;

    virtual void RecvPacketThreadFunc() = 0;
    void OpenThread();
    void play();
    void pause();
    void end();

    bool OpenPcap(std::string interface, const int timeout = 1);
    //Mac ResolveMac(const QString targetIP);
    bool ReadPacket();
    /*std::vector<uint8_t*> GetPacket(const uint16_t etherType, const QString ip,
                                     const IpHdr::PROTOCOL_ID_TYPE type, const uint16_t port);*/

    bool SendPacket(uint8_t* pPacket, uint32_t size);

    RecvData GetPacket(const uint16_t etherType, const std::string ip,
                       const IpHdr::PROTOCOL_ID_TYPE type, const uint16_t port);

public:
    explicit PcapController(QObject *parent = nullptr);
    ~PcapController();

    std::vector<QString> GetInterfaces();
    bool SetCurrentInterface(const QString& interface);
    QString GetCurrentInterface();

    //bool ArpSpoofing(const QString senderIP, const QString targetIP);

    void Stop();

signals:
};

#endif // PCAPCONTROLLER_H
