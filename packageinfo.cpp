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
    this->is6 = false;
}
void PackageInfo::setInfo(QString info){
    this->info = info;
}
void PackageInfo::setIs6(bool i){
    this->is6 = i;
}
void PackageInfo::setPointer(const unsigned char *package,int size){
    //不可以直接赋值，需要显示申请内存
    this->package = (unsigned char*)malloc(size);
    //需要把数据存储在内存里，方便后续操作
    memcpy((char*)(this->package),package,size);
}
void PackageInfo::setDataLength(unsigned int data_length){
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
        return "ARP";
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
    if(this->package_type == 2+8){
        return "ICMPv6";
    }
    if(this->package_type == 3+8){
        return "TCPv6";
    }
    if(this->package_type == 4+8){
        return "UDPv6";
    }
    if(this->package_type == 5+8){
        return "DNSv6";
    }
    if(this->package_type == 6+8){
        return "TLSv6";
    }
    if(this->package_type == 7+8){
        return "SSLv6";
    }
    else{
        return "";
    }
}
bool PackageInfo::getIs6(){
    return is6;
}
QString PackageInfo::getSourMac(){
    ether_header *eth;
    eth = (ether_header*)package;
    unsigned char* addr = eth->sour_add;
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
    unsigned char* addr = eth->des_add;
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

QString PackageInfo::getSourIpv6(){
    ipv6_header* ip;
    ip = (ipv6_header*)(package + 14);
    QString sour_addr = QString::asprintf("%X:%X:%X:%X:%X:%X:%X:%X",
                                          ip->sour_addr.a1,
                                          ip->sour_addr.a2,
                                          ip->sour_addr.a3,
                                          ip->sour_addr.a4,
                                          ip->sour_addr.a5,
                                          ip->sour_addr.a6,
                                          ip->sour_addr.a7,
                                          ip->sour_addr.a8);
    return sour_addr;
}

QString PackageInfo::getDesIpv6(){
    ipv6_header* ip;
    ip = (ipv6_header*)(package + 14);
    QString des_addr = QString::asprintf("%X:%X:%X:%X:%X:%X:%X:%X",
                                          ip->des_addr.a1,
                                          ip->des_addr.a2,
                                          ip->des_addr.a3,
                                          ip->des_addr.a4,
                                          ip->des_addr.a5,
                                          ip->des_addr.a6,
                                          ip->des_addr.a7,
                                          ip->des_addr.a8);
    return des_addr;
}

QString PackageInfo::getSourAdd(){
    if(this->package_type == 1) return this->getSourMac();
    else if(this->package_type == 8) return getSourIpv6();
    else return this->getSourIp();
}

QString PackageInfo::getDesAdd(){
    if(this->package_type == 1) return this->getDesMac();
    else if(this->package_type == 8) return getDesIpv6();
    else return this->getDesIp();
}

QString PackageInfo::getMacType(){
    ether_header* eth;
    eth = (ether_header*)package;
    unsigned short type = ntohs(eth->type);
    //ipv4
    if(type == 0x0800){
        return "IPv4(0x0800)";
    }
    else if(type == 0x0806){
        return "ARP(0x0806)";
    }
    else if(type == 0x086DD){
        return "IPv6(0x86DD)";
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
    res = QString::number(length*4) + " bytes";
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

QString PackageInfo::getFlags(){
    ip_header*ip = (ip_header*)(package+14);
    QString res = QString::number((ntohs(ip->FlagsAndOffet)& 0xe000) >> 8,16);
    return res;
}

QString PackageInfo::getFrag(){
    ip_header*ip = (ip_header*)(package+14);
    QString res = QString::number(ntohs(ip->FlagsAndOffet) & 0x1FFF);
    return res;
}

QString PackageInfo::getIpChecksum(){
    ip_header*ip = (ip_header*)(package+14);
    QString res = QString::number(ntohs(ip->checksum),16);
    qDebug()<<res;
    return res;
}

QString PackageInfo::getSourcePort(){
    tcp_header* tcp;
    if(is6) tcp = (tcp_header*)(package+14+40);
    else{
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        tcp = (tcp_header*)(package+14+ip_len);
    }
    int port = ntohs(tcp->sour_port);
    if(port == 443) return "443(https)";
    QString res = QString::number(port);
    return res;
}

QString PackageInfo::getDesPort(){
    tcp_header* tcp;
    if(is6) tcp = (tcp_header*)(package+14+40);
    else{
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        tcp = (tcp_header*)(package+14+ip_len);
    }
    int port = ntohs(tcp->des_port);
    if(port == 443) return "443(https)";
    QString res = QString::number(port);
    return res;
}

QString PackageInfo::getTcpSeq(){
    tcp_header* tcp;
    if(is6) tcp = (tcp_header*)(package+14+40);
    else{
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        tcp = (tcp_header*)(package+14+ip_len);
    }
    QString res = QString::number(ntohl(tcp->seq));
    return res;
}

QString PackageInfo::getTcpAck(){
    tcp_header* tcp;
    if(is6) tcp = (tcp_header*)(package+14+40);
    else{
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        tcp = (tcp_header*)(package+14+ip_len);
    }
    QString res = QString::number(ntohl(tcp->ack));
    return res;
}

QString PackageInfo::getTcpHeaderLength(){
    tcp_header* tcp;
    if(is6) tcp = (tcp_header*)(package+14+40);
    else{
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        tcp = (tcp_header*)(package+14+ip_len);
    }
    int length = (tcp->headLength >> 4);
    QString res = QString::number(length*4);
    return res;
}

QString PackageInfo::getTcpFlags(){
    tcp_header* tcp;
    if(is6) tcp = (tcp_header*)(package+14+40);
    else{
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        tcp = (tcp_header*)(package+14+ip_len);
    }
    QString res = QString::number(tcp->flags,16);
    return res;
}

QString PackageInfo::getTcpSyn(){
    tcp_header* tcp;
    if(is6) tcp = (tcp_header*)(package+14+40);
    else{
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        tcp = (tcp_header*)(package+14+ip_len);
    }
    QString res = QString::number(((tcp->flags) & 0x02) >> 1);
    return res;
}

QString PackageInfo::getTcpAckFlag(){
    tcp_header* tcp;
    if(is6) tcp = (tcp_header*)(package+14+40);
    else{
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        tcp = (tcp_header*)(package+14+ip_len);
    }
    QString res = QString::number(((tcp->flags) & 0x10) >> 4);
    return res;
}

QString PackageInfo::getTcpWindowSize(){
    tcp_header* tcp;
    if(is6) tcp = (tcp_header*)(package+14+40);
    else{
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        tcp = (tcp_header*)(package+14+ip_len);
    }
    QString res = QString::number(ntohs(tcp->windowSize));
    return res;
}

QString PackageInfo::getTcpChecksum(){
    tcp_header* tcp;
    if(is6) tcp = (tcp_header*)(package+14+40);
    else{
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        tcp = (tcp_header*)(package+14+ip_len);
    }
    QString res = QString::number(ntohs(tcp->checksum),16);
    return res;
}

QString PackageInfo::getTcpUrgentP(){
    tcp_header* tcp;
    if(is6) tcp = (tcp_header*)(package+14+40);
    else{
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        tcp = (tcp_header*)(package+14+ip_len);
    }
    QString res = QString::number(ntohs(tcp->urgentPointer));
    return res;
}

QString PackageInfo::getUdpSourPort(){
    udp_header* udp;
    if(is6) udp = (udp_header*)(package+14+40);
    else{
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        udp = (udp_header*)(package+14+ip_len);
    }
    int port = ntohs(udp->sour_port);
    QString res = QString::number(port);
    if(port == 53) res += " (DNS)";
    return res;
}

QString PackageInfo::getUdpDesPort(){
    udp_header* udp;
    if(is6) udp = (udp_header*)(package+14+40);
    else{
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        udp = (udp_header*)(package+14+ip_len);
    }
    int port = ntohs(udp->des_port);
    QString res = QString::number(port);
    if(port == 53) res += " (DNS)";
    return res;
}

QString PackageInfo::getUdpLen(){
    udp_header* udp;
    if(is6) udp = (udp_header*)(package+14+40);
    else{
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        udp = (udp_header*)(package+14+ip_len);
    }
    QString res = QString::number(ntohs(udp->dataLength));
    return res;
}

QString PackageInfo::getUdpChecksum(){
    udp_header* udp;
    if(is6) udp = (udp_header*)(package+14+40);
    else{
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        udp = (udp_header*)(package+14+ip_len);
    }
    QString res = QString::number(ntohs(udp->checksum),16);
    return res;
}

QString PackageInfo::getIcmpType(){
    icmp_header* icmp;
    if(is6) icmp = (icmp_header*)(package+14+40);
    else {
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        icmp = (icmp_header*)(package+14+ip_len);
    }

    QString res = QString::number(ntohs(icmp->type));
    return res;
}

QString PackageInfo::getIcmpCode(){
    icmp_header* icmp;
    if(is6) icmp = (icmp_header*)(package+14+40);
    else {
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        icmp = (icmp_header*)(package+14+ip_len);
    }
    QString res = QString::number(ntohs(icmp->code));
    return res;
}

QString PackageInfo::getIcmpChecksum(){
    icmp_header* icmp;
    if(is6) icmp = (icmp_header*)(package+14+40);
    else {
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        icmp = (icmp_header*)(package+14+ip_len);
    }
    QString res = QString::number(ntohs(icmp->checksum),16);
    return res;
}

QString PackageInfo::getIcmpIden(){
    icmp_header* icmp;
    if(is6) icmp = (icmp_header*)(package+14+40);
    else {
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        icmp = (icmp_header*)(package+14+ip_len);
    }
    QString res = QString::number(ntohs(icmp->identification));
    return res;
}

QString PackageInfo::getIcmpSeq(){
    icmp_header* icmp;
    if(is6) icmp = (icmp_header*)(package+14+40);
    else {
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        icmp = (icmp_header*)(package+14+ip_len);
    }
    QString res = QString::number(ntohs(icmp->seq));
    return res;
}

QString PackageInfo::getIcmpData(int size){
    char* icmp;
    if(is6) icmp = (char*)(package+14+40);
    else {
        ip_header* ip;
        ip = (ip_header*)(package + 14);
        int ip_len = ((ip->versionAndHLength)&0x0F)*4;
        icmp = (char*)(package+14+ip_len);
    }
    QString res= "";
    for(int i = 0;i < size;i++){
        qDebug()<<"i:"<<QString::number(i);
        if (isprint(*icmp)) {
             res += (*icmp);
        } else {
            res += '.';
        }
        icmp++;
    }
    return res;
}

QString PackageInfo::getArpType(){
    arp_header* arp = (arp_header*)(package + 14);
    int type = ntohs(arp->type);
    QString res = QString::number(type);
    return res;
}

QString PackageInfo::getArpProtocol(){
    arp_header* arp = (arp_header*)(package + 14);
    int type = ntohs(arp->protocol);
    QString res = QString::number(type);
    return res;
}

QString PackageInfo::getArpMacLen(){
    arp_header* arp = (arp_header*)(package + 14);
    QString res = QString::number(arp->macLength);
    return res;
}

QString PackageInfo::getArpIpLen(){
    arp_header* arp = (arp_header*)(package + 14);
    QString res = QString::number(arp->ipLength);
    return res;
}

QString PackageInfo::getArpOpCode(){
    arp_header* arp = (arp_header*)(package + 14);
    int code = ntohs(arp->op_code);
    QString res = "";
    if(code == 1) res  = "1(request)";
    else if(code == 2) res = "2(reply)";
    return res;
}

QString PackageInfo::getArpSourMacAddr(){
    arp_header* arp = (arp_header*)(package + 14);
    unsigned char* sour_eth_add = arp->sour_eth_addr;
    QString sourEth = byteToString(sour_eth_add,1)+":";
    sourEth += byteToString((sour_eth_add+1),1)+":";
    sourEth += byteToString((sour_eth_add+2),1)+":";
    sourEth += byteToString((sour_eth_add+3),1)+":";
    sourEth += byteToString((sour_eth_add+4),1)+":";
    sourEth += byteToString((sour_eth_add+5),1);
    return sourEth;
}

QString PackageInfo::getArpDesMacAddr(){
    arp_header* arp = (arp_header*)(package + 14);
    unsigned char* des_eth_add = arp->des_eth_addr;
    QString desEth = byteToString(des_eth_add,1)+":";
    desEth += byteToString((des_eth_add+1),1)+":";
    desEth += byteToString((des_eth_add+2),1)+":";
    desEth += byteToString((des_eth_add+3),1)+":";
    desEth += byteToString((des_eth_add+4),1)+":";
    desEth += byteToString((des_eth_add+5),1);
    return desEth;
}

QString PackageInfo::getArpSourIpAddr(){
    arp_header* arp = (arp_header*)(package + 14);
    unsigned char* sour_ip_add = arp->sour_ip_addr;
    QString sourIP = QString::number(*sour_ip_add)+".";
    sourIP += QString::number(*(sour_ip_add+1))+".";
    sourIP += QString::number(*(sour_ip_add+2))+".";
    sourIP += QString::number(*(sour_ip_add+3));
    return sourIP;
}

QString PackageInfo::getArpDesIpAddr(){
    arp_header* arp = (arp_header*)(package + 14);
    unsigned char* des_ip_add = arp->des_ip_addr;
    QString desIP = QString::number(*des_ip_add)+".";
    desIP += QString::number(*(des_ip_add+1))+".";
    desIP += QString::number(*(des_ip_add+2))+".";
    desIP += QString::number(*(des_ip_add+3));
    return desIP;
}

QString PackageInfo::byteToString(unsigned char *string, int size){
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

//转16进制
QString PackageInfo::unsignedShortToString(unsigned short value) {
    QString res = "";
    // 设置输出格式为十六进制并填充为两位
    res += QString::number(value, 16).toUpper().rightJustified(4, '0');
    return res;
}
