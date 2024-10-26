#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    statusBar()->showMessage("welcome!");
    //工具栏
    ui->toolBar->addAction(ui->actionstart);
    ui->toolBar->addAction(ui->actionstop);
    ui->toolBar->addAction(ui->actionclear);
    ui->toolBar->setMovable(false);

    //隐藏树的第一项
    ui->treeWidget->setHeaderHidden(true);
}

MainWindow::~MainWindow()
{
    delete ui;
}

