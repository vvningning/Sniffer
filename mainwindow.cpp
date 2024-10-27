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

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
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
    static bool index = true;
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


            index = false;
//            statusBar()->showMessage(device->name);
            //开始抓包
            int ret = chooseNIC();
            if(ret!=-1 && pointer){
                //正常获取网卡后才捕获
                thread->setPointer(pointer);
                thread->setFlag();
                thread->start();

                //捕获开始时不能随意更改网卡
                ui->comboBox->setEnabled(false);
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
            thread->quit();
            thread->wait();
            //网卡可更换
            ui->comboBox->setEnabled(true);
            //释放pointer
            pcap_close(pointer);
            pointer = nullptr;
        }
    });
    //发送者 地址 接收者 地址
    connect(thread,&CaptureThread::send,this,&MainWindow::handleMessage);
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
    if(type == "TCP")
        color = QColor(216,191,216);
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
        if(packageType != "IPv6"){
            QString sourIp = packageInfoVec[selectedRow].getSourIp();
            QString desIp = packageInfoVec[selectedRow].getDesIp();
            QString version = packageInfoVec[selectedRow].getIpVersion();
            QString headerLen = packageInfoVec[selectedRow].getIpHeaderLen();
            QString Tos = packageInfoVec[selectedRow].getIpTos();
            QString iden = packageInfoVec[selectedRow].getIpId();
            QString ttl = packageInfoVec[selectedRow].getIpTtl();

    //        QString flags = packageInfo[selectedRow].getIpFlag();

            QTreeWidgetItem* ip_item = new QTreeWidgetItem(QStringList()<<"Internet Protocol, Src:" + sourIp + ", Dst:" + desIp);
            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"SourIp:" + sourIp));
            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"DesIp:" + desIp));
            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Version:" + version));
            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Header Length:" + headerLen));
            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"TOS:" + Tos));
            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Identification:" + iden));
            ip_item->addChild(new QTreeWidgetItem(QStringList()<<"Total Length:" + ttl));

            ui->treeWidget->addTopLevelItem(ip_item);
        }

    }

    showPacket(packageInfoVec[selectedRow].package,packageInfoVec[selectedRow].len);

    ui->textEdit->setText(dataPackageText);
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
           result += QString::number(data[i], 16).rightJustified(2, '0') + " ";
       }
       result += "\n";

       // 输出 ASCII
       result += "ASCII: ";
       for (int i = 0; i < len; i++) {
           if (isprint(data[i])) {
               result += (char)data[i];
           } else {
               result += '.';
           }
       }
       result += "\n";
       dataPackageText = result;
}
