#include "capturethread.h"
#include <QDebug>
#include "packageinfo.h"

CaptureThread::CaptureThread()
{
    this->isDone = true;
    this->filter = false;
    this->filterPro = "";
}
bool CaptureThread::setPointer(pcap_t *pointer){
    this->pointer = pointer;
    if(pointer!=NULL){
        return true;
    }
    else
        return false;

}
void CaptureThread::setFlag(){
    this->isDone = false;
}
void CaptureThread::resetFlag(){
    this->isDone = true;
}
void CaptureThread::setFilter(bool index){
    this->filter = index;
}
void CaptureThread::setFilterPro(string filterPro){
    this->filterPro = filterPro;
}
void CaptureThread::run(){
    while(true){
        if(isDone)
            break;
        else{
            qDebug()<<QString::fromStdString(filterPro);

            if(filter&&filterPro!=""){
                // 设置过滤器
                   struct bpf_program filter;
                   const char *filter_exp = this->filterPro.c_str(); // 只捕获 TCP 包
                   if (pcap_compile(pointer, &filter, filter_exp, 0, 0) == -1) {
                       fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(pointer));
                       pcap_close(pointer);
                       qDebug()<<"33333333333333333333333";
                       qDebug()<<QString::fromStdString(filterPro);
                       return;
                   }

                   if (pcap_setfilter(pointer, &filter) == -1) {
                       fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(pointer));
                       pcap_freecode(&filter);
                       pcap_close(pointer);
                       return;
                   }

            }
            qDebug()<<"333333333333333333333334444444444444444";
            qDebug()<<QString::fromStdString(filterPro);
            //获取数据
            int res = pcap_next_ex(pointer,&header,&data);
            //如果没有捕获到就继续捕获
            if(res == 0)
                continue;



            //时间戳
            local_time_sec = header->ts.tv_sec;

            //处理时间格式
            localtime_s(&local_time,&local_time_sec);
            strftime(timeString,sizeof(timeString),"%H:%M:%S",&local_time);
            //qDebug()<<timeString;
            QString info = "";
            int t = handleEthernerPackage(data,info);
            if(t){
                PackageInfo packageInfo;
                packageInfo.len = header->len;

                unsigned int len = header->len;
                packageInfo.setInfo(info);
                packageInfo.setDataLength(len);
                packageInfo.setTimeStamp(timeString);
                if(t>=8) packageInfo.setIs6(true);
                else packageInfo.setIs6(false);
                packageInfo.setPackageType(t);
                packageInfo.setPointer(data,len);
                emit send(packageInfo);
            }
        }
    }
}

int CaptureThread::handleEthernerPackage(const unsigned char *data, QString &info){
    ether_header * eth;
    unsigned short content_type;
    eth = (ether_header *)data;
    //一个16位数由网络字节顺序转换为主机字节顺序
    //数据包类型
    content_type = ntohs(eth->type);
    //上层封装ipv4
    if(content_type == 0x0800){
        //type = "ip";
        //有效载荷
        int ipPackage = 0;
        int res = handleIpPackage(data,ipPackage);
        if(res ==1){
            //ICMP
            info = handleIcmpPackage(data);
            return 2;
        }
        if(res ==6){
            //TCP
            return handleTcpPackage(data,info,ipPackage);
        }
        if(res ==17){
            //UDP
            return handleUdpPackage(data,info);
        }
        return 1;
    }
    if(content_type == 0x86DD){
        //上层封装ipv6
        info = handleIpv6Package(data);
        //return 8;
        return handleIpv6PackageNext(data,info);
    }
    if(content_type == 0x0806){
//        info = "arp";
        info = handleArpPackage(data);
        return 1;
    }
    return 0;
}
int CaptureThread::handleIpPackage(const unsigned char *data, int &ipPackage){
    //data指向最开始的数据包，需要跳过mac,即跳过14
    ip_header* ip;
    ip = (ip_header*)(data + 14);
    //ip数据包中封装的上层的协议
    int protocol = ip->protocol;
    //实际有效载荷 减掉的头需要按位取出来,单位为4字节，要乘4
    ipPackage = ntohs((ip->totalLength - (((ip->versionAndHLength)&0x0F)*4)));
    return protocol;
}

QString CaptureThread::handleIpv6Package(const unsigned char *data){
    //data指向最开始的数据包，需要跳过mac,即跳过14
    ipv6_header* ip;
    ip = (ipv6_header*)(data + 14);
    QString res = "";
    QString sour_addr = QString::asprintf("%X:%X:%X:%X:%X:%X:%X:%X",
                                          ip->sour_addr.a1,
                                          ip->sour_addr.a2,
                                          ip->sour_addr.a3,
                                          ip->sour_addr.a4,
                                          ip->sour_addr.a5,
                                          ip->sour_addr.a6,
                                          ip->sour_addr.a7,
                                          ip->sour_addr.a8);
    QString des_addr = QString::asprintf("%X:%X:%X:%X:%X:%X:%X:%X",
                                          ip->des_addr.a1,
                                          ip->des_addr.a2,
                                          ip->des_addr.a3,
                                          ip->des_addr.a4,
                                          ip->des_addr.a5,
                                          ip->des_addr.a6,
                                          ip->des_addr.a7,
                                          ip->des_addr.a8);
    res += "ipv6 source addr:"+ sour_addr + " destination addr:"+des_addr;
//    unsigned char next_header = ip->next_header;

//        // 判断下一层协议
//        switch (next_header) {
//            case 6:
//                res += " | Next Header: TCP";
//                break;
//            case 17:
//                res += " | Next Header: UDP";
//                break;
//            case 58:
//                res += " | Next Header: ICMPv6";
//                break;
//            default:
//                res += " | Next Header: Unknown (" + QString::number(next_header) + ")";
//                break;
//        }

//        return res;
    return res;
}
int CaptureThread::handleIpv6PackageNext(const unsigned char *data,QString &info){
    //data指向最开始的数据包，需要跳过mac,即跳过14
    ipv6_header* ip;
    ip = (ipv6_header*)(data + 14);
    QString res = "";
    QString sour_addr = QString::asprintf("%X:%X:%X:%X:%X:%X:%X:%X",
                                          ip->sour_addr.a1,
                                          ip->sour_addr.a2,
                                          ip->sour_addr.a3,
                                          ip->sour_addr.a4,
                                          ip->sour_addr.a5,
                                          ip->sour_addr.a6,
                                          ip->sour_addr.a7,
                                          ip->sour_addr.a8);
    QString des_addr = QString::asprintf("%X:%X:%X:%X:%X:%X:%X:%X",
                                          ip->des_addr.a1,
                                          ip->des_addr.a2,
                                          ip->des_addr.a3,
                                          ip->des_addr.a4,
                                          ip->des_addr.a5,
                                          ip->des_addr.a6,
                                          ip->des_addr.a7,
                                          ip->des_addr.a8);
    res += "ipv6 source addr:"+ sour_addr + " destination addr:"+des_addr;
    unsigned char next_header = ip->next_header;
    if(next_header == 6){
        res += " | Next Header: TCP";
        tcp_header * tcp;
        //跳过mac和ip
        tcp = (tcp_header*)(data+14+40);
        unsigned short sour_port = ntohs(tcp->sour_port);
        unsigned short des_port = ntohs(tcp ->des_port);
        QString proSend = "";
        QString proRecei = "";
        int type = 3;
        int tcpHeaderLength = (tcp->headLength>>4)*4;
        //https
        if(sour_port == 443||des_port == 443){
            if(sour_port==443) proSend = "(https)";
            else proRecei = "(https)";
            unsigned char*ssl=(unsigned char*)(data+14+40+tcpHeaderLength);
            unsigned char isTls = (*ssl);
            ssl++;
            unsigned short* pointer = (unsigned short*)ssl;
            unsigned short version = ntohs(*pointer);
            if(isTls>=20&&isTls<=23&&version>=0x0301&&version<=0x0304){
                type = 6;
                if(isTls==20){
                    res+="Change Cipher Spec";//交换密钥
                }
                if(isTls==21){
                    res+="Alert";
                }
                if(isTls==22){
                    res+="Hand shake";
                    ssl+=4;
                    unsigned char t = (*ssl);
                    if(t==1){
                        res+="Client Hello";
                    }
                    if(t==2){
                        res+="Server Hello";
                    }
                }
                if(isTls==23){
                    res += "Application Data";
                }
            }
            else type = 7;
            if(type==7) res += "Continuation Data";
        }
        //需要交给应用层处理
        res += QString::number(sour_port) + proSend+"->"+QString::number(des_port)+proRecei;
        QString flags = "";
        //通过位运算获得标志位
        if(tcp->flags & 0x08) flags += "PSH,";
        if(tcp->flags & 0x10) flags += "ACK,";
        if(tcp->flags & 0x02) flags += "SYN,";
        if(tcp->flags & 0x20) flags += "URG,";
        if(tcp->flags & 0x01) flags += "FIN,";
        if(tcp->flags & 0x04) flags += "RST,";
        if(flags!=""){
            //去掉最后的逗号
            flags = flags.left(flags.length()-1);
            res+= "["+flags+"]";
        }
        unsigned int seq = ntohl(tcp->seq);
        unsigned int ack = ntohl(tcp->ack);
        unsigned short windowSize = ntohs(tcp->windowSize);
        res+= " Seq=" + QString::number(seq);
        res+= "ACK=" + QString::number(ack);
        res+= "win=" + QString::number(windowSize);
        info = res;
        return type+8;
    }
    else if(next_header==17){
        udp_header* udp;

        //跳过mac和ip
        udp = (udp_header*)(data+14+40);
        unsigned short sour_port = ntohs(udp->sour_port);
        unsigned short des_port = ntohs(udp->des_port);

        //dns用53端口
        if(sour_port==53||des_port == 53) {
            res += handleDnsPackage(data);
            info = res;
            return 5+8;
        }
        else{
            res += QString::number(sour_port) + "->" + QString::number(des_port);
            unsigned short dataLength = ntohs(udp->dataLength);
            res += "len = "+QString::number(dataLength);
            info = res;
            return 4+8;
        }
    }
    else if(next_header==58){
        icmp_header* icmp;
        icmp = (icmp_header*)(data + 14 + 40);
        unsigned char type = icmp->type;
        qDebug()<<"icmpv6 type"<<type;
        unsigned char code = icmp->code;
        QString res="";

        if(type==1){
            if(code==0){
                res = "There is no route to the destination";
            }
            else if(code==1){
                res = "Communication with the target is prohibited by the management policy";
            }
            else if(code==3){
                res = "Address unreachable";
            }
            else if(code==4){
                res = "Port unreachable";
            }
        }
        else if(type==2){
            if(code==0){
                res = "too large package";
            }
        }
        else if(type==3){
            res = "time out";
        }
        else if(type==128){
            if(code==0){
                res = "echo request";
            }
        }
        else if(type==129){
            if(code==0){
                res = "echo response";
            }
        }
        else if(type==133){
            if(code==0){
                res = "Device request message";
            }
        }
        else if(type==134){
            if(code==0){
                res = "Device notification message";
            }
        }
        else if(type==135){
            if(code==0){
                res = "Neighbor request message";
            }
        }
        else if(type==136){
            if(code==0){
                res = "Neighbor notification message";
            }
        }
        else if(type==137){
            if(code==0){
                res = "Redirect message";
            }
        }
        else res = "icmpv6";
        info = res;
        return 2+8;
    }
    info = res;
    return 8;
}
int CaptureThread::handleTcpPackage(const unsigned char *data, QString &info, int ipPackage){
    tcp_header * tcp;
    //跳过mac和ip
    ip_header* ip;
    ip = (ip_header*)(data + 14);
    int ip_len = ((ip->versionAndHLength)&0x0F)*4;
    tcp = (tcp_header*)(data+14+ip_len);
    unsigned short sour_port = ntohs(tcp->sour_port);
    unsigned short des_port = ntohs(tcp ->des_port);
    QString proSend = "";
    QString proRecei = "";
    int type = 3;
    int tcpHeaderLength = (tcp->headLength>>4)*4;
    int tcpLoader = ipPackage - tcpHeaderLength;
    //https
    if(sour_port == 443||des_port == 443){
        if(sour_port==443) proSend = "(https)";
        else proRecei = "(https)";
        unsigned char*ssl=(unsigned char*)(data+14+20+tcpHeaderLength);
        unsigned char isTls = (*ssl);
        ssl++;
        unsigned short* pointer = (unsigned short*)ssl;
        unsigned short version = ntohs(*pointer);
        if(isTls>=20&&isTls<=23&&version>=0x0301&&version<=0x0304){
            type = 6;
            if(isTls==20){
                info="Change Cipher Spec";//交换密钥
            }
            if(isTls==21){
                info="Alert";
            }
            if(isTls==22){
                info="Hand shake";
                ssl+=4;
                unsigned char t = (*ssl);
                if(t==1){
                    info+="Client Hello";
                }
                if(t==2){
                    info+="Server Hello";
                }
            }
            if(isTls==23){
                info = "Application Data";
            }
        }
        else type = 7;
        if(type==7) info = "Continuation Data";
    }
    //需要交给应用层处理
    info += QString::number(sour_port) + proSend+"->"+QString::number(des_port)+proRecei;
    QString flags = "";
    //通过位运算获得标志位
    if(tcp->flags & 0x08) flags += "PSH,";
    if(tcp->flags & 0x10) flags += "ACK,";
    if(tcp->flags & 0x02) flags += "SYN,";
    if(tcp->flags & 0x20) flags += "URG,";
    if(tcp->flags & 0x01) flags += "FIN,";
    if(tcp->flags & 0x04) flags += "RST,";
    if(flags!=""){
        //去掉最后的逗号
        flags = flags.left(flags.length()-1);
        info += "["+flags+"]";
    }
    unsigned int seq = ntohl(tcp->seq);
    unsigned int ack = ntohl(tcp->ack);
    unsigned short windowSize = ntohs(tcp->windowSize);
    info += " Seq=" + QString::number(seq);
    info += "ACK=" + QString::number(ack);
    info += "win=" + QString::number(windowSize);
    info += "len=" + QString::number(tcpLoader);
    return type;


}

int CaptureThread::handleUdpPackage(const unsigned char *data, QString &info){
    udp_header* udp;
    ip_header* ip;
    ip = (ip_header*)(data + 14);
    int ip_len = ((ip->versionAndHLength)&0x0F)*4;
    //跳过mac和ip
    udp = (udp_header*)(data+14+ip_len);
    unsigned short sour_port = ntohs(udp->sour_port);
    unsigned short des_port = ntohs(udp->des_port);

    //dns用53端口
    if(sour_port==53||des_port == 53) {
        info = handleDnsPackage(data);
        return 5;
    }
    else{
        info += QString::number(sour_port) + "->" + QString::number(des_port);
        unsigned short dataLength = ntohs(udp->dataLength);
        info += "len = "+QString::number(dataLength);
        return 4;
    }
}

QString CaptureThread::handleArpPackage(const unsigned char *data){
    arp_header *arp;
    //arp被封装在mac帧里，与ip同层
    arp = (arp_header*)(data+14);
    unsigned short op = ntohs(arp->op_code);
    QString res = "";

    unsigned char* sour_ip_add = arp->sour_ip_addr;
    QString sourIP = QString::number(*sour_ip_add)+".";
    sourIP += QString::number(*(sour_ip_add+1))+".";
    sourIP += QString::number(*(sour_ip_add+2))+".";
    sourIP += QString::number(*(sour_ip_add+3));

    unsigned char* des_ip_add = arp->des_ip_addr;
    QString desIP = QString::number(*des_ip_add)+".";
    desIP += QString::number(*(des_ip_add+1))+".";
    desIP += QString::number(*(des_ip_add+2))+".";
    desIP += QString::number(*(des_ip_add+3));

    unsigned char* sour_eth_add = arp->sour_eth_addr;
    QString sourEth = byteToString(sour_eth_add,1)+":";
    sourEth += byteToString((sour_eth_add+1),1)+":";
    sourEth += byteToString((sour_eth_add+2),1)+":";
    sourEth += byteToString((sour_eth_add+3),1)+":";
    sourEth += byteToString((sour_eth_add+4),1)+":";
    sourEth += byteToString((sour_eth_add+5),1);

    if(op == 1){
        //请求字段
        res = "who has " + desIP + "? Tell " + sourIP;
    }
    else if(op==2){
        //应答
        res = sourIP + " is at " + sourEth;
    }
    return res;
}

QString CaptureThread::handleDnsPackage(const unsigned char *data){
    dns_header* dns;
    //跳过mac ip udp
    ip_header* ip;
    ip = (ip_header*)(data + 14);
    int ip_len = ((ip->versionAndHLength)&0x0F)*4;
    dns = (dns_header*)(data + 14+ip_len+8);
    unsigned short identification = ntohs(dns->identification);
    unsigned short flags = ntohs(dns->flags);
    QString info = "";
    //查询
    if((flags & 0xf800) == 0x0000){
        //第一个为0为查询，第二个为0为标准
        info = "Standard query";
    }
    if((flags & 0xf800) == 0x8000){
        info = "Standard query response";
    }
    QString dName = "";
    //跳过mac ip udp dns头
    char* domain = (char*)(data+14+20+8+12);
    while(*domain != 0x00){
        //标识长度
        if(domain && (*domain)<=64){
            int len = *domain;
            domain++;
            for(int l=0;l<len;l++){
                dName += (*domain);
                domain++;
            }
            dName += ".";
        }
        else break;
    }
    if(dName != "") dName = dName.left(dName.length()-1);
    info += " 0x"+QString::number(identification,16)+" "+dName;
    return info;
}

QString CaptureThread::handleIcmpPackage(const unsigned char *data){
    icmp_header* icmp;
    //icmp被封装在ip里
    ip_header* ip;
    ip = (ip_header*)(data + 14);
    int ip_len = ((ip->versionAndHLength)&0x0F)*4;
    icmp = (icmp_header*)(data + 14 + ip_len);
    unsigned char type = icmp->type;
    unsigned char code = icmp->code;
    QString info="";
    if(type==0&&code==0){
        info = "Echo response(ping command response";
    }
    else if(type==3){
        if(code==0){
            info = "Network unreachable";
        }
        else if(code==1){
            info = "Host unreachable";
        }
        else if(code==2){
            info = "Protocol unreachable";
        }
        else if(code==3){
            info = "Port unreachable";
        }
        else if(code==4){
            info = "Fragmentation is required, but DF is set";
        }
        else if(code==5){
            info = "Source route selection failed";
        }
        else if(code==6){
            info = "Unknown target network";
        }
    }
    else if(type==4&&code==0){
        info = "Source station suppression [congestion control]";
    }
    else if(type==5){
        info = "Relocation";
    }
    else if(type==8&&code==0){
        info = "Echo request(ping command request)";
    }
    else info = "icmp";
    return info;
}

QString CaptureThread::byteToString(unsigned char *string, int size){
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
