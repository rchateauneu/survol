FROM docker.io/fedora

MAINTAINER contact@primhillcomputers.com

################################# Executables:
RUN yum -y install bash # bash-4.4.12-5.fc26.x86_64
# Potential conflict with coreutils , coreutils-8.27-5.fc26.x86_64
RUN yum -y install procps-ng # procps-ng-3.3.10-13.fc26.x86_64

################################# Dependencies by program type
# Dependencies: Binary programs
# Package installations:
RUN yum -y install bzip2-libs # bzip2-libs-1.0.6-22.fc26.x86_64
RUN yum -y install glibc # glibc-2.25-6.fc26.x86_64
RUN yum -y install libacl # libacl-2.2.52-15.fc26.x86_64
RUN yum -y install libattr # libattr-2.4.47-18.fc26.x86_64
RUN yum -y install libselinux # libselinux-2.6-6.fc26.x86_64
# Already installed procps-ng -> procps-ng-3.3.10-13.fc26.x86_64

# Non-packaged executable files copies:
# Origin file does not exist:/usr/lib64/libc-2.21.so
# Origin file does not exist:/usr/lib64/libcap.so.2.24
# Origin file does not exist:/usr/lib64/libdl-2.21.so
# Origin file does not exist:/usr/lib64/libdw-0.166.so
# Origin file does not exist:/usr/lib64/libelf-0.166.so
# Origin file does not exist:/usr/lib64/libgcc_s-5.3.1-20160406.so.1
# Origin file does not exist:/usr/lib64/libgcrypt.so.20.0.3
# Origin file does not exist:/usr/lib64/libgpg-error.so.0.17.0
# Origin file does not exist:/usr/lib64/liblzma.so.5.2.0
# Origin file does not exist:/usr/lib64/libm-2.21.so
# Origin file does not exist:/usr/lib64/libnss_files-2.21.so
# Origin file does not exist:/usr/lib64/libpcre.so.1.2.7
# Origin file does not exist:/usr/lib64/libpthread-2.21.so
# Origin file does not exist:/usr/lib64/libresolv-2.21.so
# Origin file does not exist:/usr/lib64/librt-2.21.so
# Origin file does not exist:/usr/lib64/libsystemd.so.0.6.0
# Origin file does not exist:/usr/lib64/libtinfo.so.5.9
# Origin file does not exist:/usr/lib64/libz.so.1.2.8

# Data packages:
RUN yum -y install filesystem # filesystem-3.2-40.fc26.x86_64
# Already installed glibc -> glibc-2.25-6.fc26.x86_64
RUN yum -y install glibc-all-langpacks # glibc-all-langpacks-2.25-6.fc26.x86_64
RUN yum -y install glibc-common # glibc-common-2.25-6.fc26.x86_64
RUN yum -y install setup # setup-2.10.5-2.fc26.noarch
RUN yum -y install tzdata # tzdata-2017b-1.fc26.noarch

# Data files:
# Origin file does not exist:/home/rchateau/rdfmon-code/Experimental/RetroBatch
# Origin file does not exist:/home/rchateau/rdfmon-code/Experimental/RetroBatch/TestProgs/sample_shell.sh

WORKDIR /home/rchateau/rdfmon-code/Experimental/RetroBatch
CMD [ "bash","TestProgs/sample_she..." ]
WORKDIR /home/rchateau/rdfmon-code/Experimental/RetroBatch


# Processes tree
# 2018-05-20 08:26:47.177594 -> 2018-05-20 08:26:47.553096 :      bash TestProgs/sample_she...
# 2018-05-20 08:26:47.185552 -> 2018-05-20 08:26:47.553096 :          ls
# 2018-05-20 08:26:47.198399 -> 2018-05-20 08:26:47.553096 :          ps -ef
# 2018-05-20 08:26:47.545561 -> 2018-05-20 08:26:47.553096 :          cat TestProgs/sample_she...
# 2018-05-20 08:26:47.185933 -> 2018-05-20 08:26:47.553096 :      *Unknown-command*
# 2018-05-20 08:26:47.199213 -> 2018-05-20 08:26:47.543412 :          wc

