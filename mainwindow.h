#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <stdio.h>
#include "pcap.h"
#include "winsock2.h"
#include "packageinfo.h"
#include <QVector>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    void showNIC();
    int chooseNIC();
    void showPacket(const unsigned char *data, int len);
    ~MainWindow();

private slots:
    void on_comboBox_currentIndexChanged(int index);

    void on_tableWidget_cellClicked(int row, int column);

public slots:
    void handleMessage(PackageInfo dataI);

private:
    Ui::MainWindow *ui;
    pcap_if_t* all_devices;
    pcap_if_t* device;
    pcap_t* pointer;
    char errbuf[PCAP_ERRBUF_SIZE];
    QVector<PackageInfo> packageInfoVec;
    int count;//数据包个数
    //选中的行
    int selectedRow;
    QString dataPackageText;
};
#endif // MAINWINDOW_H
