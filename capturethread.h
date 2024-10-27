#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H
#include <QThread>
#include "pcap.h"
#include "packageinfo.h"


class CaptureThread:public QThread
{
    Q_OBJECT

public:
    CaptureThread();
    static QString byteToString(u_char* string,int size);
    void run() override;
    //打开设备描述符的地址
    bool setPointer(pcap_t *pointer);
    void setFlag();
    void resetFlag();
    //19:00
    int handleEthernerPackage(const u_char *data,QString &type);
    int handleIpPackage(const u_char* data,int &ipPackage);//ipPackage为实际承载多少报文
    int handleTcpPackage(const u_char* data,QString &info,int ipPackage);
    //udp解析dns
    //udp包含数据长度，不需要ipPackage
    int handleUdpPackage(const u_char* data,QString &info);
    //arp
    QString handleArpPackage(const u_char* data);
    QString handleDnsPackage(const u_char* data);
    QString handleIcmpPackage(const u_char* data);

signals:
    //线程间发送数据
    void send(PackageInfo packageInfo);

private:
    pcap_t *pointer;
    //数据包头部
    struct pcap_pkthdr* header;
    //数据包内容
    const uchar* data;
    //时间
    time_t local_time_sec;
    struct tm local_time;
    char timeString[16];
    bool isDone;
};

#endif // CAPTURETHREAD_H