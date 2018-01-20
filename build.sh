# mongo-c-driver
yum install -y epel-release	# update repo, so mongo-c-driver can bo searched.
yum install -y mongo-c-driver-devel

# get and build nginx
yum install -y wget
yum install -y pcre-devel openssl-devel zlib-devel	# default nginx depends
yum install -y gcc make	# build nginx
wget http://nginx.org/download/nginx-1.12.2.tar.gz
tar -xf nginx-1.12.2.tar.gz
cd nginx-1.12.2
./configure --with-openssl=/usr/include/openssl --add-module=../nginx-gridfs/
make install
ln -s /usr/local/nginx/sbin/nginx /usr/sbin/nginx

# clear
rm -rf /tmp/*
yum clean all