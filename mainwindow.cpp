#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "capturethread.h"
#include <iostream>
#include "QDebug"
#include "QRect"
#include <iomanip>
#include <cctype>
#include <QGuiApplication>
#include <QScreen>
#include <string>
#include <QMessageBox>
#include <QContextMenuEvent>
#include <QScrollArea>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    //右键table cell弹出菜单
    ui->tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);

    index = false;
    filter = false;
    setWindowIcon(QIcon(":/gkd.png"));
    setWindowTitle("mySniffer");
    resize(2000, 1400);
    setMinimumSize(1200, 1000);
    //居中
    //获取屏幕尺寸
    QRect screenGeometry = QGuiApplication::primaryScreen()->geometry();
    int x = (screenGeometry.width() - this->width()) / 2;
    int y = (screenGeometry.height() - this->height()) / 2;
    //设置窗口位置
    this->move(x, y);
//    QRect screenGeometry = QDesktopWidget().screenGeometry();
//    int x = (screenGeometry.width() - this->width()) / 2;
//    int y = (screenGeometry.height() - this->height()) / 2;

    // 设置窗口位置
    this->move(x, y);
    ui->textEdit->setReadOnly(true);
    ui->textEdit->setFixedHeight(250); // 设置固定高度为 300 像素
    showNIC();
    count = 0;
    selectedRow = -1;
    statusBar()->showMessage("welcome!");
    ui->toolBar->addAction(ui->actionstart);
    ui->toolBar->addAction(ui->actionstop);
    ui->toolBar->addAction(ui->actionclear);
    ui->toolBar->setMovable(false);
    //共7列
    ui->tableWidget->setColumnCount(7);
    //设置行高
    ui->tableWidget->verticalHeader()->setDefaultSectionSize(30);
    //表头
    QStringList title = {"No.","Time","Source","Destination","Protocol","Length","Tnfo"};
    ui->tableWidget->setHorizontalHeaderLabels(title);
    //设置列宽
    ui->tableWidget->setColumnWidth(0,50);
    ui->tableWidget->setColumnWidth(1,100);
    ui->tableWidget->setColumnWidth(2,300);
    ui->tableWidget->setColumnWidth(3,300);
    ui->tableWidget->setColumnWidth(4,100);
    ui->tableWidget->setColumnWidth(5,100);
    ui->tableWidget->setColumnWidth(6,1000);
    //去掉表格自带编号
    ui->tableWidget->verticalHeader()->setVisible(false);
    //点中单元格选中一行
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->treeWidget->setHeaderHidden(true);


    //子线程与主线程隔离，不需要挂载在对象树上
    CaptureThread* thread = new CaptureThread;
    index = true;
    //点击开始按钮
    connect(ui->actionstart,&QAction::triggered,this,[=](){
        if(index){

            //清空
            count = 0;
            ui->tableWidget->clearContents();
            ui->tableWidget->setRowCount(0);
            //释放QVector
            for(int i=0;i<this->packageInfoVec.size();i++){
                free((char*)(this->packageInfoVec[i].package));
                this->packageInfoVec[i].package = nullptr;
            }
            //释放dataPackage
            QVector<PackageInfo>().swap(packageInfoVec);

            ui->textEdit->setText("");
            ui->treeWidget->clear();
            thread->setFilter(false);
            thread->setFilterPro("");


            index = false;
//            statusBar()->showMessage(device->name);
            //开始抓包
            int ret = chooseNIC();
            if(ret!=-1 && pointer){
                //正常获取网卡后才捕获
                thread->setPointer(pointer);
                //如果有过滤器
                QString pro = ui->lineEdit->text().toUpper();
                if(pro == "ARP"||pro == "ICMP"||pro == "ICMPV6"||pro == "TCP"||pro == "TCPV6"||pro == "UDP"||pro == "UDPV6"||pro == "DNS"||pro == "DNSV6"||pro == "TLS"||pro == "SSL"||pro == "TLSV6"||pro == "SSLV6"||pro == "IPV6"||pro == ""){
                    QString search = pro.toLower();
                    qDebug()<<"pro"<<pro;
                    qDebug()<<"sea"<<search;
                    if(pro=="DNS") search = "udp and port 53";
                    if(pro=="DNSV6") search = "ip6 and udp and port 53";
                    if(pro=="TLS"||pro=="SSL") {
                        search = "tcp port 443";
                        qDebug()<<"sea3"<<search;
                    }
                    if(pro=="TLSV6"||pro=="SSLV6") {
                        search = "ip6 and tcp port 443";
                        qDebug()<<"sea3"<<search;
                    }
                    if(pro=="IPV6") search = "ip6";
                    if(pro=="TCP") search = "tcp";
                    if(pro=="UDP") search = "udp";
                    if(pro=="TCPV6") search = "ip6 and tcp";
                    if(pro=="UDPV6") search = "ip6 and udp";
                    if(pro=="ICMPV6") search = "icmp6";
                    if(pro=="ICMP") search = "icmp or icmp6";

            //        qDebug()<<"222";
                     qDebug()<<"sea2"<<search;
                    if(search!="") {
                        qDebug()<<"filter";
                        qDebug()<<search;
                        thread->setFilter(true);
                        thread->setFilterPro(search.toStdString());
                }}
                thread->setFlag();
                thread->start();

                //捕获开始时不能随意更改网卡
                ui->comboBox->setEnabled(false);
                ui->actionclear->setEnabled(false);
            }
            else{
                //打开网卡有问题
                count = 0;
                index = true;
            }
        }
    });
    //点击停止按钮
    connect(ui->actionstop,&QAction::triggered,this,[=](){
        //index为false时能停止
        //cout<<index;
        if(!index){
            index = true;
            thread->resetFlag();
            thread->setFilter(false);
            thread->setFilterPro("");
            thread->quit();
            thread->wait();
            //网卡可更换
            ui->comboBox->setEnabled(true);
            ui->actionclear->setEnabled(true);
            //释放pointer
            pcap_close(pointer);
            pointer = nullptr;
        }
    });
    //清空
    connect(ui->actionclear,&QAction::triggered,this,[=](){
        //清空
        count = 0;
        ui->tableWidget->clearContents();
        ui->tableWidget->setRowCount(0);
        //释放QVector
        for(int i=0;i<this->packageInfoVec.size();i++){
            free((char*)(this->packageInfoVec[i].package));
            this->packageInfoVec[i].package = nullptr;
        }
        //释放dataPackage
        QVector<PackageInfo>().swap(packageInfoVec);

        ui->textEdit->setText("");
        ui->treeWidget->clear();
        });
    //发送者 地址 接收者 地址
    connect(thread,&CaptureThread::send,this,&MainWindow::handleMessage);
    connect(ui->lineEdit,&QLineEdit::textChanged,this,&MainWindow::on_lineEdit_textChanged);
//    ui->lineEdit->setStyleSheet("QLineEdit { background-color: red; }");
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::showNIC(){
    int n = pcap_findalldevs(&all_devices,errbuf);
    qDebug()<<n;
    qDebug()<<QString(errbuf);
    if(n==-1||0){
        ui->comboBox->addItem("error:" + QString(errbuf));
    }
    else{
        ui->comboBox->clear();
        ui->comboBox->addItem("请选择网卡");
//        qDebug()<<all_devices->name;
        if(all_devices == nullptr){
            qDebug()<<"wuwuwu";
        }
        for(pcap_if_t* d = all_devices;d!=nullptr;d = d->next){
            qDebug()<<QString(d->name);
            QString dName = d->name;
            dName.replace("\\Device\\","");
            QString desc = d->description;
            QString deviceString = dName+desc;
            ui->comboBox->addItem(deviceString);
        }
    }
}

void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    int i=0;
    if(index!=0){
        for(device = all_devices;i<index-1;device = device->next,i++);
    }
    return;
}

int MainWindow::chooseNIC(){
    if(device){
        qDebug()<<device->name;
        pointer = pcap_open_live(device->name,65536,1,1000,errbuf);
    }
    else return -1;
    if(!pointer){
        //释放
        pcap_freealldevs(all_devices);
        device = nullptr;
        return -1;
    }
    else{
        //留下主流的数据包
        if(pcap_datalink(pointer)!= DLT_EN10MB){
            pcap_close(pointer);
            pcap_freealldevs(all_devices);
            device = nullptr;
            pointer = nullptr;
            return -1;
        }
        printf(device->name);
        statusBar()->showMessage(device->name);
    }
    return 0;
}

void MainWindow::handleMessage(PackageInfo pI){
    //qDebug()<<dataP.getTimeStamp()<<" "<<dataP.getInfo();
    //每个数据包都会触发槽函数，这里只需要处理一个数据包的内容
    ui->tableWidget->insertRow(count);
    this->packageInfoVec.push_back(pI);
    QString type = pI.getPackageType();
    QColor color;
    if(type == "TCP"||type == "SSL"||type == "TLS")
        color = QColor(216,200,216);
    else if(type == "UDP")
        color = QColor(217,236,255);
    else if(type == "ARP")
        color = QColor(250,236,216);
    else if(type == "DNS")
        color = QColor(255,255,224);
    else
        color = QColor(255,218,185);
//        color = QColor(255,0,0);

    ui->tableWidget->setItem(count,0,new QTableWidgetItem(QString::number(count)));
    ui->tableWidget->setItem(count,1,new QTableWidgetItem(pI.getTimeStamp()));
    ui->tableWidget->setItem(count,2,new QTableWidgetItem(pI.getSourAdd()));
    ui->tableWidget->setItem(count,3,new QTableWidgetItem(pI.getDesAdd()));
    ui->tableWidget->setItem(count,4,new QTableWidgetItem(type));
    ui->tableWidget->setItem(count,5,new QTableWidgetItem(pI.getDataLength()));
    ui->tableWidget->setItem(count,6,new QTableWidgetItem(pI.getInfo()));
    for(int i=0;i<7;i++){
        ui->tableWidget->item(count,i)->setBackground(color);
    }
    count++;

}
void MainWindow::on_tableWidget_cellClicked(int row, int column)
{
    //与上次点击相同
    if(row == selectedRow||row < 0) return;
    selectedRow = row;
    ui->treeWidget->clear();
    ui->textEdit->clear();
    if (selectedRow < 0 || selectedRow >= packageInfoVec.size()) {
        qDebug()<<"error selected row";
        return;
    }
    showPacket(packageInfoVec[selectedRow].package,packageInfoVec[selectedRow].len);
    ui->textEdit->setText(dataPackageText);

    if(selectedRow<0||selectedRow>count) return;
    QString sourMac = packageInfoVec[selectedRow].getSourMac();
    QString desMac = packageInfoVec[selectedRow].getDesMac();
    QString type = packageInfoVec[selectedRow].getMacType();
    QString node = "Ethernet,Source:"+sourMac +" Destination:"+desMac;
    QTreeWidgetItem *eth_item = new QTreeWidgetItem(QStringList()<<node);
    ui->treeWidget->addTopLevelItem(eth_item);
    eth_item -> addChild(new QTreeWidgetItem(QStringList()<<("Source:" + sourMac)));
    eth_item -> addChild(new QTreeWidgetItem(QStringList()<<("Destination:" + desMac)));
    eth_item -> addChild(new QTreeWidgetItem(QStringList()<<("Type:" + type)));

    QString packageType = packageInfoVec[selectedRow].getPackageType();
    if(packageType != "ARP"){
        if(packageInfoVec[selectedRow].getIs6()){
            QString sourIpv6 = packageInfoVec[selectedRow].getSourIpv6();
            QString desIpv6 = packageInfoVec[selectedRow].getDesIpv6();
            QString version2 = packageInfoVec[selectedRow].getIpVersion();
            QTreeWidgetItem* ipv6_item = new QTreeWidgetItem(QStringList()<<"Internet Protocol, Src:" + sourIpv6 + ", Dst:" + desIpv6);
            ipv6_item->addChild(new QTreeWidgetItem(QStringList()<<"SourAdd:" + sourIpv6));
            ipv6_item->addChild(new QTreeWidgetItem(QStringList()<<"DesAdd:" + desIpv6));
            ipv6_item->addChild(new QTreeWidgetItem(QStringList()<<"Version:" + version2));
            ui->treeWidget->addTopLevelItem(ipv6_item);
        }
        else{
            QString sourIp = packageInfoVec[selectedRow].getSourIp();
            QString desIp = packageInfoVec[selectedRow].getDesIp();
            QString version = packageInfoVec[selectedRow].getIpVersion();
            QString headerLen = packageInfoVec[selectedRow].getIpHeaderLen();
            QString checksum = "0x" + packageInfoVec[selectedRow].getIpChecksum();
            QString Tos = packageInfoVec[selectedRow].getIpTos();
            QString iden = packageInfoVec[selectedRow].getIpId();
            QString ttl = packageInfoVec[selectedRow].getIpTtl();
            int payload = ttl.toUtf8().toInt() - 20;
            QString flags = packageInfoVec[selectedRow].getFlags();
            QString frag = packageInfoVec[selectedRow].getFrag();
            QTreeWidgetItem* ip_item = new QTreeWidgetItem(QStringList()<<"Internet Protocol, Sour:" + sourIp + ", Des:" + desIp);
            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"SourAdd:" + sourIp));
            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"DesAdd:" + desIp));
            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Version:" + version));
            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Header Length:" + headerLen));
            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Header checksum:" + checksum));
            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"TOS:" + Tos));
            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Identification:" + iden));
            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Total Length:" + ttl));
            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Flags:" + flags));
            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Frag:" + frag));
            ui->treeWidget->addTopLevelItem(ip_item);
        }
        if(packageType == "TCP" || packageType == "TLS" || packageType == "SSL"||packageType == "TCPv6" || packageType == "TLSv6" || packageType == "SSLv6"){
            QString sourPort = packageInfoVec[selectedRow].getSourcePort();
            QString desPort = packageInfoVec[selectedRow].getDesPort();
            QString seq = packageInfoVec[selectedRow].getTcpSeq();
            QString ack = packageInfoVec[selectedRow].getTcpAck();
            int headerLen = packageInfoVec[selectedRow].getTcpHeaderLength().toUtf8().toInt();
            QString flags = packageInfoVec[selectedRow].getTcpFlags();
            while(flags.size()<2)
                flags = "0" + flags;
            flags = "0x" + flags;
            QString syn = packageInfoVec[selectedRow].getTcpSyn();
            QString ackNumber = packageInfoVec[selectedRow].getTcpAckFlag();
            QString windowSize = packageInfoVec[selectedRow].getTcpWindowSize();
            QString checksum = "0x" + packageInfoVec[selectedRow].getTcpChecksum();
            QString urgentP = packageInfoVec[selectedRow].getTcpUrgentP();

            QTreeWidgetItem* tcp_item = new QTreeWidgetItem(QStringList()<<"TCP, Src Port:" + sourPort + ", DesPort:" + desPort + ",Seq:" + seq + ", Ack:" + ack);

            ui->treeWidget->addTopLevelItem(tcp_item);
            tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:" + sourPort));
            tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"Des Port:" + desPort));
            tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"Seq:" + seq));
            tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"Ack:" + ack));
            tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"header length:" + QString::number(headerLen)+" bytes"));
            tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"Flags:" + flags));
            tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"SYN Flags" + syn));
            tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"ACK Flag:" + ackNumber));
            tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"window size:" + windowSize));
            tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"checksum:" + checksum));
            tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"urgent pointer:" + urgentP));

            if(!packageInfoVec[selectedRow].getIs6()){
                QString ttl = packageInfoVec[selectedRow].getIpTtl();
                int payload = ttl.toUtf8().toInt() - 20;
                payload -= (headerLen * 4);
                if(payload>0) tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"TCP Payload:" + QString::number(payload)));
            }
        }
        if(packageType == "UDP" || packageType == "DNS"||packageType == "UDPv6" || packageType == "DNSv6"){
            QString srcPort = packageInfoVec[selectedRow].getUdpSourPort();
            QString desPort = packageInfoVec[selectedRow].getUdpDesPort();
            QString Length = packageInfoVec[selectedRow].getUdpLen();
            QString checksum = "0x" + packageInfoVec[selectedRow].getUdpChecksum();
            QTreeWidgetItem* udp_item = new QTreeWidgetItem(QStringList()<<"UDP, sour Port:" + srcPort + ", des Port:" + desPort);
            ui->treeWidget->addTopLevelItem(udp_item);
            udp_item->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:" + srcPort));
            udp_item->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:" + desPort));
            udp_item->addChild(new QTreeWidgetItem(QStringList()<<"length:" + Length));
            udp_item->addChild(new QTreeWidgetItem(QStringList()<<"checksum:" + checksum));
            int udpLength = Length.toUtf8().toInt();
            if(udpLength > 0){
                udp_item->addChild(new QTreeWidgetItem(QStringList()<<"UDP PayLoad (" + QString::number(udpLength - 8) + " bytes)"));
            }
        }
        if(packageType == "ICMP"||packageType == "ICMPv6"){
                QTreeWidgetItem* icmp_item = new QTreeWidgetItem(QStringList()<<"ICMP");
                ui->treeWidget->addTopLevelItem(icmp_item);
                QString type = packageInfoVec[selectedRow].getIcmpType();
                QString code = packageInfoVec[selectedRow].getIcmpCode();
                QString info = ui->tableWidget->item(row,6)->text();
                QString checksum = "0x" + packageInfoVec[selectedRow].getIcmpChecksum();
                QString id = packageInfoVec[selectedRow].getIcmpIden();
                QString seq = packageInfoVec[selectedRow].getIcmpSeq();
                icmp_item->addChild(new QTreeWidgetItem(QStringList()<<"type:" + type + "(" + info + ")"));
                icmp_item->addChild(new QTreeWidgetItem(QStringList()<<"code:" + code));
                icmp_item->addChild(new QTreeWidgetItem(QStringList()<<"checksum:" + checksum));
                icmp_item->addChild(new QTreeWidgetItem(QStringList()<<"iden:" + id));
                icmp_item->addChild(new QTreeWidgetItem(QStringList()<<"seq:" + seq));

                if(!packageInfoVec[selectedRow].getIs6()){
                    QString ttl = packageInfoVec[selectedRow].getIpTtl();
                    int payload = ttl.toUtf8().toInt() - 20;
                    payload -= 8;
                    if(payload > 0){
                        QTreeWidgetItem* dataItem = new QTreeWidgetItem(QStringList()<<"Data (" + QString::number(payload) + " bytes)");
                        icmp_item->addChild(dataItem);
                        QString icmpData = packageInfoVec[selectedRow].getIcmpData(payload);
                        dataItem->addChild(new QTreeWidgetItem(QStringList()<<icmpData));
                    }
                }
             }
//        if(packageType != "IPv6"){
//            QString sourIp = packageInfoVec[selectedRow].getSourIp();
//            QString desIp = packageInfoVec[selectedRow].getDesIp();
//            QString version = packageInfoVec[selectedRow].getIpVersion();
//            QString headerLen = packageInfoVec[selectedRow].getIpHeaderLen();
//            QString checksum = "0x" + packageInfoVec[selectedRow].getIpChecksum();
//            QString Tos = packageInfoVec[selectedRow].getIpTos();
//            QString iden = packageInfoVec[selectedRow].getIpId();
//            QString ttl = packageInfoVec[selectedRow].getIpTtl();
//            int payload = ttl.toUtf8().toInt() - 20;
//            QString flags = packageInfoVec[selectedRow].getFlags();
//            QString frag = packageInfoVec[selectedRow].getFrag();
//            QTreeWidgetItem* ip_item = new QTreeWidgetItem(QStringList()<<"Internet Protocol, Sour:" + sourIp + ", Des:" + desIp);
//            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"SourAdd:" + sourIp));
//            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"DesAdd:" + desIp));
//            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Version:" + version));
//            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Header Length:" + headerLen));
//            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Header checksum:" + checksum));
//            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"TOS:" + Tos));
//            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Identification:" + iden));
//            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Total Length:" + ttl));
//            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Flags:" + flags));
//            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Frag:" + frag));
//            ui->treeWidget->addTopLevelItem(ip_item);

//            if(packageType == "TCP" || packageType == "TLS" || packageType == "SSL"){

//                QString sourPort = packageInfoVec[selectedRow].getSourcePort();
//                QString desPort = packageInfoVec[selectedRow].getDesPort();
//                QString seq = packageInfoVec[selectedRow].getTcpSeq();
//                QString ack = packageInfoVec[selectedRow].getTcpAck();
//                int headerLen = packageInfoVec[selectedRow].getTcpHeaderLength().toUtf8().toInt();
//                QString flags = packageInfoVec[selectedRow].getTcpFlags();
//                while(flags.size()<2)
//                    flags = "0" + flags;
//                flags = "0x" + flags;
//                QString syn = packageInfoVec[selectedRow].getTcpSyn();
//                QString ackNumber = packageInfoVec[selectedRow].getTcpAckFlag();
//                QString windowSize = packageInfoVec[selectedRow].getTcpWindowSize();
//                QString checksum = "0x" + packageInfoVec[selectedRow].getTcpChecksum();
//                QString urgentP = packageInfoVec[selectedRow].getTcpUrgentP();
//                payload -= (headerLen * 4);
//                QTreeWidgetItem* tcp_item = new QTreeWidgetItem(QStringList()<<"TCP, Src Port:" + sourPort + ", DesPort:" + desPort + ",Seq:" + seq + ", Ack:" + ack);

//                ui->treeWidget->addTopLevelItem(tcp_item);
//                tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:" + sourPort));
//                tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"Des Port:" + desPort));
//                tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"Seq:" + seq));
//                tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"Ack:" + ack));
//                tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"header length:" + QString::number(headerLen)+" bytes"));
//                tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"Flags:" + flags));
//                tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"SYN Flags" + syn));
//                tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"ACK Flag:" + ackNumber));
//                tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"window size:" + windowSize));
//                tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"checksum:" + checksum));
//                tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"urgent pointer:" + urgentP));
//                if(payload>0) tcp_item->addChild(new QTreeWidgetItem(QStringList()<<"TCP Payload:" + QString::number(payload)));
//            }
//            if(packageType == "UDP" || packageType == "DNS"){
//                QString srcPort = packageInfoVec[selectedRow].getUdpSourPort();
//                QString desPort = packageInfoVec[selectedRow].getUdpDesPort();
//                QString Length = packageInfoVec[selectedRow].getUdpLen();
//                QString checksum = "0x" + packageInfoVec[selectedRow].getUdpChecksum();
//                QTreeWidgetItem* udp_item = new QTreeWidgetItem(QStringList()<<"UDP, sour Port:" + srcPort + ", des Port:" + desPort);
//                ui->treeWidget->addTopLevelItem(udp_item);
//                udp_item->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:" + srcPort));
//                udp_item->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:" + desPort));
//                udp_item->addChild(new QTreeWidgetItem(QStringList()<<"length:" + Length));
//                udp_item->addChild(new QTreeWidgetItem(QStringList()<<"checksum:" + checksum));
//                int udpLength = Length.toUtf8().toInt();
//                if(udpLength > 0){
//                    udp_item->addChild(new QTreeWidgetItem(QStringList()<<"UDP PayLoad (" + QString::number(udpLength - 8) + " bytes)"));
//                }
//            }
//            if(packageType == "ICMP"){
//                            payload -= 8;
//                            QTreeWidgetItem* icmp_item = new QTreeWidgetItem(QStringList()<<"ICMP");
//                            ui->treeWidget->addTopLevelItem(icmp_item);
//                            QString type = packageInfoVec[selectedRow].getIcmpType();
//                            QString code = packageInfoVec[selectedRow].getIcmpCode();
//                            QString info = ui->tableWidget->item(row,6)->text();
//                            QString checksum = "0x" + packageInfoVec[selectedRow].getIcmpChecksum();
//                            QString id = packageInfoVec[selectedRow].getIcmpIden();
//                            QString seq = packageInfoVec[selectedRow].getIcmpSeq();
//                            icmp_item->addChild(new QTreeWidgetItem(QStringList()<<"type:" + type + "(" + info + ")"));
//                            icmp_item->addChild(new QTreeWidgetItem(QStringList()<<"code:" + code));
//                            icmp_item->addChild(new QTreeWidgetItem(QStringList()<<"checksum:" + checksum));
//                            icmp_item->addChild(new QTreeWidgetItem(QStringList()<<"iden:" + id));
//                            icmp_item->addChild(new QTreeWidgetItem(QStringList()<<"seq:" + seq));
//                            if(payload > 0){
//                                QTreeWidgetItem* dataItem = new QTreeWidgetItem(QStringList()<<"Data (" + QString::number(payload) + " bytes)");
//                                icmp_item->addChild(dataItem);
//                                QString icmpData = packageInfoVec[selectedRow].getIcmpData(payload);
//                                dataItem->addChild(new QTreeWidgetItem(QStringList()<<icmpData));
//                            }
//                        }

//        }
//        else{
//            QString sourIpv6 = packageInfoVec[selectedRow].getSourIpv6();
//            QString desIpv6 = packageInfoVec[selectedRow].getDesIpv6();
//            QString version2 = packageInfoVec[selectedRow].getIpVersion();
//            QTreeWidgetItem* ipv6_item = new QTreeWidgetItem(QStringList()<<"Internet Protocol, Src:" + sourIpv6 + ", Dst:" + desIpv6);
//            ipv6_item->addChild(new QTreeWidgetItem(QStringList()<<"SourAdd:" + sourIpv6));
//            ipv6_item->addChild(new QTreeWidgetItem(QStringList()<<"DesAdd:" + desIpv6));
//            ipv6_item->addChild(new QTreeWidgetItem(QStringList()<<"Version:" + version2));
//            ui->treeWidget->addTopLevelItem(ipv6_item);
//        }

    }
    else{
        //arp
        QTreeWidgetItem* arp_item = new QTreeWidgetItem(QStringList()<<"ARP");
        ui->treeWidget->addTopLevelItem(arp_item);
        QString type = packageInfoVec[selectedRow].getArpType();
        QString protocol = packageInfoVec[selectedRow].getArpProtocol();
        QString macLen = packageInfoVec[selectedRow].getArpMacLen();
        QString ipLen = packageInfoVec[selectedRow].getArpIpLen();
        QString opCode = packageInfoVec[selectedRow].getArpOpCode();
        QString sourMacAddr = packageInfoVec[selectedRow].getArpSourMacAddr();
        QString desMacAddr = packageInfoVec[selectedRow].getArpDesMacAddr();
        QString sourIpAddr = packageInfoVec[selectedRow].getArpSourIpAddr();
        QString desIpAddr = packageInfoVec[selectedRow].getArpDesIpAddr();

        arp_item->addChild(new QTreeWidgetItem(QStringList()<<"hardware type:" + type));
        arp_item->addChild(new QTreeWidgetItem(QStringList()<<"protocol:" + protocol));
        arp_item->addChild(new QTreeWidgetItem(QStringList()<<"mac length:" + macLen));
        arp_item->addChild(new QTreeWidgetItem(QStringList()<<"protocol length:" + ipLen));
        arp_item->addChild(new QTreeWidgetItem(QStringList()<<"op code:" + opCode));
        arp_item->addChild(new QTreeWidgetItem(QStringList()<<"source mac address:" + sourMacAddr));
        arp_item->addChild(new QTreeWidgetItem(QStringList()<<"source ip address:" + sourIpAddr));
        arp_item->addChild(new QTreeWidgetItem(QStringList()<<"des MAC address:" + desMacAddr));
        arp_item->addChild(new QTreeWidgetItem(QStringList()<<"des IP address:" + desIpAddr));
        return;
    }



}



void MainWindow::showPacket(const unsigned char *data, int len) {
    QString result;
    // 输出十六进制
    result = "";
    result += "len:";
    result += QString::number(len);
    result += "\n";
       result += "Hex: ";
       for (int i = 0; i < len; i++) {
           if(i%30==0) result+="\n";
           result += QString::number(data[i], 16).rightJustified(2, '0') + " ";
       }
       result += "\n";

       // 输出 ASCII
       result += "ASCII: ";
       for (int i = 0; i < len; i++) {
           if(i%60==0) result+="\n";
           if (isprint(data[i])) {
               result += (char)data[i];
           } else {
               result += '.';
           }
       }
       result += "\n";
       dataPackageText = result;
}

void MainWindow::on_lineEdit_textChanged(const QString &arg1)
{
    QString pro = arg1;
    pro = arg1.toUpper();


    if(pro == "ARP"||pro == "ICMP"||pro == "ICMPV6"||pro == "TCP"||pro == "TCPV6"||pro == "UDP"||pro == "UDPV6"||pro == "DNS"||pro == "DNSV6"||pro == "TLS"||pro == "SSL"||pro == "TLSV6"||pro == "SSLV6"||pro == "IPV6"||pro == ""){
        ui->lineEdit->setStyleSheet("QLineEdit {background-color:rgb(192,255,203);}");
//        qDebug()<<"222";
    }else{
         ui->lineEdit->setStyleSheet("QLineEdit {background-color:rgb(255,192,203);}");
//         qDebug()<<"111";
    }

}

void MainWindow::on_lineEdit_returnPressed()
{
    QString pro = ui->lineEdit->text().toUpper();
    QString search = "";
    qDebug()<<pro;



   if(pro == "ARP"||pro == "ICMP"||pro == "ICMPV6"||pro == "TCP"||pro == "TCPV6"||pro == "UDP"||pro == "UDPV6"||pro == "DNS"||pro == "DNSV6"||pro == "TLS"||pro == "SSL"||pro == "TLSV6"||pro == "SSLV6"||pro == "IPV6"||pro == ""){
        ui->lineEdit->setStyleSheet("QLineEdit {background-color:rgb(192,255,203);}");
        search = pro;
//        qDebug()<<"222";
    }else{
         ui->lineEdit->setStyleSheet("QLineEdit {background-color:rgb(255,192,203);}");
//         qDebug()<<"111";
    }
    int count = 0;
    int number = ui->tableWidget->rowCount();
    //index为true是停止
    if(index){
        qDebug()<<"333";
        if(search!=""){
            for(int i = 0;i < number;i++){
                if(ui->tableWidget->item(i,4)->text() != search){
                    ui->tableWidget->setRowHidden(i,true);
//                    count--;
                }else{
                    ui->tableWidget->setRowHidden(i,false);
                    count++;
                }
            }
        }else if(search==""){
            qDebug()<<"444";
            for(int i = 0;i < number;i++){
                ui->tableWidget->setRowHidden(i,false);//显示
                count++;
            }
        }
    }

    double res = 0;
    if(number != 0)
        res = (count*100.0)/number;
    statusBar()->showMessage("Have show (" + QString::number(count) + ") " +QString::number(res,10,2) + "%");
}

void MainWindow::on_tableWidget_customContextMenuRequested(const QPoint &pos)
{
    QMenu menu;
       QAction *tracing = menu.addAction(tr("TCP流追踪"));

       connect(tracing, &QAction::triggered, [=](){
           //停止时才可以追踪
           if(index){
              QDialog *dialog = new QDialog(this);
              dialog->setWindowTitle("trace");
              dialog->setMinimumSize(1000, 800);
              dialog->setMaximumWidth(1000);
//              QScrollArea *scrollArea = new QScrollArea(dialog);
//              scrollArea->setWidgetResizable(true); // 使内容自适应滚动区域大小
              // 创建滚动区域
                  QScrollArea *scrollArea = new QScrollArea(dialog);
                  scrollArea->setWidgetResizable(true); // 使内容自适应滚动区域大小

                  // 创建一个 QWidget 作为滚动区域的内容
                  QWidget *contentWidget = new QWidget();
                  QVBoxLayout *layout = new QVBoxLayout(contentWidget);
//              QVBoxLayout *layout = new QVBoxLayout(dialog);

              int currentRow = ui->tableWidget->currentRow();
              if (currentRow < 0) {
                  QMessageBox::warning(this, "Warning", "Please select a row first.");
                  return;
              }

                  // 获取当前行的内容
                  QString ip_type="";
                  QString sour_ip="";
                  QString des_ip="";
                  if(packageInfoVec[currentRow].getIs6()){
                      sour_ip = packageInfoVec[currentRow].getSourIpv6();
                      des_ip = packageInfoVec[currentRow].getDesIpv6();
                  }
                  else{
                       sour_ip = packageInfoVec[currentRow].getSourIp();
                       des_ip = packageInfoVec[currentRow].getDesIp();
                  }

                  QString sour_port = packageInfoVec[currentRow].getSourcePort();
                  QString des_port = packageInfoVec[currentRow].getDesPort();
                  QString b_s_ip="";
                  QString b_d_ip="";
                  QString b_s_port="";
                  QString b_d_port="";
                  int number = ui->tableWidget->rowCount();
                  for(int i = 0;i < number;i++){
                      qDebug()<<"i:"<<i;
                      if(packageInfoVec[i].getIs6()){
                          b_s_ip = packageInfoVec[i].getSourIpv6();
                          b_d_ip = packageInfoVec[i].getDesIpv6();
                      }
                      else{
                           b_s_ip = packageInfoVec[i].getSourIp();
                           b_d_ip = packageInfoVec[i].getDesIp();
                      }

                      b_s_port = packageInfoVec[i].getSourcePort();
                      b_d_port = packageInfoVec[i].getDesPort();
                      qDebug()<<"sourip "<<sour_ip<<" bsip:"<<b_s_ip<<"sour port"<<sour_port<<"b_s_port"<<b_s_port<<"des ip"<<des_ip<<"bds ip"<<b_d_ip<<"des_port"<<des_port<<"bdport"<<b_d_port;
                      if(sour_ip==b_s_ip && sour_port==b_s_port && des_ip==b_d_ip && des_port==b_d_port){
                          qDebug()<<"trace1";
                          QString l = "";
                          l+="sour ip: "+b_s_ip + " des ip"+b_d_ip +"\n"+
                                  "sour port"+b_s_port+" des port"+b_d_port+"\n";
                          l+="Syn flag:"+packageInfoVec[i].getTcpSyn()+" TCP flag:"+packageInfoVec[i].getTcpAckFlag()+"\n";
                          l+="seq:"+packageInfoVec[i].getTcpSeq()+" ack:"+packageInfoVec[i].getTcpAck()+"\n";

                          QString result;
                          // 输出十六进制
                          result = "";
                          result += "len:";
                          int len = packageInfoVec[i].len;
                          const unsigned char *data = packageInfoVec[i].package;
                          result += QString::number(packageInfoVec[i].len);
                          result += "\n";
                             result += "Hex: ";
                             for (int i = 0; i < len; i++) {
                                 if(i%30==0) result+="\n";
                                 result += QString::number(data[i], 16).rightJustified(2, '0') + " ";
                             }
                             result += "\n";

                             // 输出 ASCII
                             result += "ASCII: ";
                             for (int i = 0; i < len; i++) {
                                 if(i%60==0) result+="\n";
                                 if (isprint(data[i])) {
                                     result += (char)data[i];
                                 } else {
                                     result += '.';
                                 }
                             }
                             result += "\n";


                          l+=result;

                          QLabel *label1 = new QLabel(l);
                          label1->setStyleSheet("QLabel {background-color:rgb(255,192,203);}");
                          layout->addWidget(label1);
                          dialog->setLayout(layout);
                          //dialog->exec(); // 显示对话框
                      }else if(sour_ip==b_d_ip && sour_port==b_d_port && des_ip==b_s_ip && des_port==b_s_port){
                          QString l = "";
                          l+="sour ip: "+b_s_ip + " des ip"+b_d_ip +" sour port"+b_s_port+" des port"+b_d_port+"\n";
                          l+="Seq flag:"+packageInfoVec[i].getTcpSeq()+" TCP flag:"+packageInfoVec[i].getTcpAckFlag()+"\n";
                          l+="syn:"+packageInfoVec[i].getTcpSyn()+" ack:"+packageInfoVec[i].getTcpAck()+"\n";

                          QString result;
                          // 输出十六进制
                          result = "";
                          result += "len:";
                          int len = packageInfoVec[i].len;
                          const unsigned char *data = packageInfoVec[i].package;
                          result += QString::number(packageInfoVec[i].len);
                          result += "\n";
                             result += "Hex: ";
                             for (int i = 0; i < len; i++) {
                                 if(i%30==0) result+="\n";
                                 result += QString::number(data[i], 16).rightJustified(2, '0') + " ";
                             }
                             result += "\n";

                             // 输出 ASCII
                             result += "ASCII: ";
                             for (int i = 0; i < len; i++) {
                                 if(i%60==0) result+="\n";
                                 if (isprint(data[i])) {
                                     result += (char)data[i];
                                 } else {
                                     result += '.';
                                 }
                             }
                             result += "\n";


                          l+=result;

                          QLabel *label1 = new QLabel(l);
                          label1->setStyleSheet("QLabel {background-color:rgb(192,203,255);}");
                          layout->addWidget(label1);
                          dialog->setLayout(layout);
                          //dialog->exec(); // 显示对话框
                          qDebug()<<"trace2";
                      }
                  }

                  contentWidget->setLayout(layout);
                  scrollArea->setWidget(contentWidget); // 将内容设置到滚动区域

                  // 设置主布局
                  QVBoxLayout *dialogLayout = new QVBoxLayout(dialog);
                  dialogLayout->addWidget(scrollArea);
                  dialog->setLayout(dialogLayout);

                  dialog->exec(); // 显示对话框

           }


              // 在这里实现 TCP 流追踪的逻辑
//              QString message = QString("Tracking TCP flow:\n%1:%2 -> %3:%4")
//                                    .arg(src_ip).arg(src_port).arg(dst_ip).arg(dst_port);
//              QMessageBox::information(this, "TCP流追踪", message);
       });


       menu.exec(QCursor::pos());
}
