#include "packageinfo.h"
#include <QMetaType>
#include "winsock2.h"
#include <QDebug>

PackageInfo::PackageInfo()
{
    //自定义类型想在槽函数中传递需注册
    qRegisterMetaType<PackageInfo>("PackageInfo");
    this->timestamp = "";
    this->data_length = 0;
    this->package_type = 0;
}
void PackageInfo::setInfo(QString info){
    this->info = info;
}
void PackageInfo::setPointer(const u_char *package,int size){
    //不可以直接赋值，需要显示申请内存
    this->package = (u_char*)malloc(size);
    //需要把数据存储在内存里，方便后续操作
    memcpy((char*)(this->package),package,size);
}
void PackageInfo::setDataLength(u_int data_length){
    this->data_length = data_length;
}
void PackageInfo::setTimeStamp(QString timeStamp){
    this->timestamp = timeStamp;
}
void PackageInfo::setPackageType(int type){
    this->package_type = type;
}
QString PackageInfo::getTimeStamp(){
    return this->timestamp;
}
QString PackageInfo::getInfo(){
    return this->info;
}
QString PackageInfo::getDataLength(){
    return QString::number(this->data_length);
}
QString PackageInfo::getPackageType(){
    //返回数据包类型的协议
    if(this->package_type == 1){
        return "APR";
    }
    if(this->package_type == 2){
        return "ICMP";
    }
    if(this->package_type == 3){
        return "TCP";
    }
    if(this->package_type == 4){
        return "UDP";
    }
    if(this->package_type == 5){
        return "DNS";
    }
    if(this->package_type == 6){
        return "TLS";
    }
    if(this->package_type == 7){
        return "SSL";
    }
    if(this->package_type == 8){
        return "IPv6";
    }
    else{
        return "";
    }
}

QString PackageInfo::getSourMac(){
    ether_header *eth;
    eth = (ether_header*)package;
    u_char* addr = eth->sour_add;
    if(addr){
        QString res = byteToString(addr,1) + ":";
        res += byteToString(addr+1,1) + ":";
        res += byteToString(addr+2,1) + ":";
        res += byteToString(addr+3,1) + ":";
        res += byteToString(addr+4,1) + ":";
        res += byteToString(addr+5,1);
        //广播
        if(res == "FF:FF:FF:FF:FF:FF") res += "(broadcast)";
        return res;

    }
}

QString PackageInfo::getDesMac(){
    ether_header *eth;
    eth = (ether_header*)package;
    u_char* addr = eth->des_add;
    if(addr){
        QString res = byteToString(addr,1) + ":";
        res += byteToString(addr+1,1) + ":";
        res += byteToString(addr+2,1) + ":";
        res += byteToString(addr+3,1) + ":";
        res += byteToString(addr+4,1) + ":";
        res += byteToString(addr+5,1);
        //广播
        if(res == "FF:FF:FF:FF:FF:FF") res += "(broadcast)";
        return res;

    }
}

QString PackageInfo::getSourIp(){
    ip_header* ip;
    ip = (ip_header*)(package + 14);
    sockaddr_in sourIp;
    sourIp.sin_addr.s_addr = ip->sour_add;
    return QString(inet_ntoa(sourIp.sin_addr));
}

QString PackageInfo::getDesIp(){
    ip_header* ip;
    ip = (ip_header*)(package + 14);
    sockaddr_in desIp;
    desIp.sin_addr.s_addr = ip->des_add;
    return QString(inet_ntoa(desIp.sin_addr));
}

QString PackageInfo::getSourAdd(){
    if(this->package_type == 1) return this->getSourMac();
    else return this->getSourIp();
}

QString PackageInfo::getDesAdd(){
    if(this->package_type == 1) return this->getDesMac();
    else return this->getDesIp();
}

QString PackageInfo::getMacType(){
    ether_header* eth;
    eth = (ether_header*)package;
    u_short type = ntohs(eth->type);
    //ipv4
    if(type == 0x0800){
        return "IPv4(0x0800)";
    }
    else if(type == 0x0806){
        return "ARP(0x0806)";
    }
    else return "";
}

QString PackageInfo::getIpVersion(){
    ip_header*ip = (ip_header*)(package+14);
    unsigned char ip_v = ip->versionAndHLength >> 4;
    QString ip_v_string = QString::number(ip_v);
    return ip_v_string;
}

QString PackageInfo::getIpHeaderLen(){
    ip_header*ip = (ip_header*)(package+14);
    QString res = "";
    int length = ip->versionAndHLength & 0x0F;
    if(length == 5) res = "20 bytes (5)";
    else res = QString::number(length*5) + "bytes";
    return res;
}

QString PackageInfo::getIpTos(){
    ip_header*ip = (ip_header*)(package+14);
    QString res = QString::number(ntohs(ip->TOS));
    return res;
}

QString PackageInfo::getIpId(){
    ip_header*ip = (ip_header*)(package+14);
    QString res = QString::number(ntohs(ip->identification),16);
    return res;
}

QString PackageInfo::getIpTtl(){
    ip_header*ip = (ip_header*)(package+14);
    QString res = QString::number(ntohs(ip->totalLength));
    return res;
}

QString PackageInfo::byteToString(u_char *string, int size){
    QString res = "";
    for(int i=0;i<size;i++){
        //字节高位
        char one = string[i]>>4;
        //与字符转换
        if(one>=0x0A){
            one += 0x41-0x0A;
        }
        else{
            one += 0x30;
        }
        //低4位
        char two = string[i]&0xF;
        if(two>=0x0A){
            two += 0x41-0x0A;
        }else{
            two += 0x30;
        }
        res.append(one);
        res.append(two);
    }
    return res;
}
