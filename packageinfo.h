#ifndef PACKAGEINFO_H
#define PACKAGEINFO_H
#include <QString>

//mac
//6byte desAdd 6byte sourceAdd 2byte type

typedef struct ether_header{
    unsigned char des_add[6];
    unsigned char sour_add[6];
    unsigned short type;
}ether_header;



//tcp
//16bit sour port     16bit des port
//32bit seq
//32bit ack
//4bit 头长  6bit 保留 6bit flags  16bit 窗口大小
//16bit 校验和   16bit 紧急数据的字节数 URG=1时有效
typedef struct tcp_header{
    unsigned short sour_port;
    unsigned short des_port;
    unsigned int seq;
    unsigned int ack;
    unsigned char headLength;
    unsigned char flags;
    unsigned short windowSize;
    unsigned short checksum;
    unsigned short urgentPointer;
}tcp_header;

//udp
//16bit source port    16bit des port
//16bit dataPackageLength  16bit checksum
typedef struct udp_header{
    unsigned short sour_port;
    unsigned short des_port;
    unsigned short dataLength;
    unsigned short checksum;
}udp_header;

//arp
//2byte type    2byte protocol  1byte ip_len    2byte op_type
//6byte source mac 4byte source ip 6byte    des mac 4byte des ip
typedef struct arp_header{
    unsigned short type;//硬件类型，为1表示以太网mac地址
    unsigned short protocol;//要映射协议地址类型
    unsigned char macLength;
    unsigned char ipLength;
    unsigned short op_code;//arp数据包类型 1为请求 2为应答
    unsigned char sour_eth_addr[6];
    unsigned char sour_ip_addr[4];
    unsigned char des_eth_addr[6];
    unsigned char des_ip_addr[4];
}arp_header;

//ICMP
//1byte type 1byte code(表示功能） 2byte checksum
//2byte identification 2byte seq确定报文顺序
//option可选项长度不固定
typedef struct icmp_header{
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short identification;
    unsigned short seq;
}icmp_header;

//4bit version   4bit headLength   8bit TypeOfService   16bit totalLength
//16bit identification        R|D|M   offset(13bit)
//8bit TTL     8bit protocol   16bit 校验和
//32bit source add
//32bit des add
typedef struct ip_header{
    //不满一个字节的按一个字节算
    unsigned char versionAndHLength;
    unsigned char TOS;
    unsigned short totalLength;
    unsigned short identification;
    unsigned short FlagsAndOffet;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned int sour_add;
    unsigned int des_add;

}ip_header;

typedef struct ipv6_address
{
    unsigned short a1;
    unsigned short a2;
    unsigned short a3;
    unsigned short a4;
    unsigned short a5;
    unsigned short a6;
    unsigned short a7;
    unsigned short a8;
}ipv6_address;

//ipv6
typedef struct ipv6_header{
    //不满一个字节的按一个字节算
    unsigned int ver_tc_fl;
    unsigned short len;
    unsigned char next_header;
    unsigned char hop_limit;
    ipv6_address sour_addr;
    ipv6_address des_addr;

}ipv6_header;




//dns
//16bit identification    16bit flags(1b QR 1响应2查询||4b op 查询与响应的类型……）
//16bit question询问的数量  16bit Answer 应答数量
//16bit Authority  16bit Additional
typedef struct dns_header{
    unsigned short identification;//标识查询与应答
    unsigned short flags;
    unsigned short question;
    unsigned short answer;
    unsigned short authority;
    unsigned short additional;
}dns_header;


class PackageInfo
{
public:
    PackageInfo();

    //通过指针显示详细信息
    const unsigned char* package;
    const unsigned char* header;
    int len;


    //字节数据转换为16进制
    static QString byteToString(unsigned char* string,int size);
    static QString unsignedShortToString(unsigned short value);

    void setDataLength(unsigned int data_length);
    void setTimeStamp(QString timeStamp);
    void setPackageType(int type);
    void setPointer(const unsigned char* package,int size);
    void setInfo(QString info);

    QString getDataLength();
    QString getTimeStamp();
    QString getPackageType();
//    QString getPointer();
    QString getInfo();

    QString getSourAdd();
    QString getDesAdd();
    QString getSourMac();
    QString getDesMac();
    QString getSourIp();
    QString getDesIp();
    QString getSourIpv6();
    QString getDesIpv6();

    //为树形结构编写的辅助函数
    QString getMacType();
    QString getIpVersion();
    QString getIpHeaderLen();
    QString getIpChecksum();
    QString getIpTos();
    QString getIpId();
    QString getIpTtl();
    QString getFlags();
    QString getFrag();
    QString getSourcePort();
    QString getDesPort();
    QString getTcpAck();
    QString getTcpSeq();
    QString getTcpHeaderLength();
    QString getTcpFlags();
    QString getTcpSyn();
    QString getTcpAckFlag();
    QString getTcpWindowSize();
    QString getTcpChecksum();
    QString getTcpUrgentP();
    QString getUdpSourPort();
    QString getUdpDesPort();
    QString getUdpLen();
    QString getUdpChecksum();
    QString getIcmpType();
    QString getIcmpCode();
    QString getIcmpChecksum();
    QString getIcmpIden();
    QString getIcmpSeq();
    QString getIcmpData(int size);
private:
    unsigned int data_length;
    QString timestamp;
    //eth上层封装的数据包类型
    QString info;
    int package_type;

};

#endif // PACKAGEINFO_H
