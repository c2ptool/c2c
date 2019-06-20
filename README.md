# c2c
### p2p database+script library

main source src/p2p

linux build:<br>

sudo apt-get install libtool autoconf automake libssl-dev

mkdir build & cd build<br>
cmake .. -DCMAKE_INSTALL_PREFIX=../../out -DCMAKE_BUILD_TYPE=Release<br>
make -j5 install<br>
