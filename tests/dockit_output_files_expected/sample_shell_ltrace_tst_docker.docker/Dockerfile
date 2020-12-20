FROM docker.io/fedora

MAINTAINER contact@primhillcomputers.com

################################# Executables:
# Potential conflict with coreutils , coreutils-8.27-5.fc26.x86_64

################################# Dependencies by program type
# Dependencies: Binary programs
# Package installations:
RUN yum -y install bzip2-libs # bzip2-libs-1.0.6-22.fc26.x86_64
RUN yum -y install elfutils-libelf # elfutils-libelf-0.169-1.fc26.x86_64
RUN yum -y install elfutils-libs # elfutils-libs-0.169-1.fc26.x86_64
RUN yum -y install glibc # glibc-2.25-6.fc26.x86_64
RUN yum -y install libacl # libacl-2.2.52-15.fc26.x86_64
RUN yum -y install libattr # libattr-2.4.47-18.fc26.x86_64
RUN yum -y install libcap # libcap-2.25-5.fc26.x86_64
RUN yum -y install libgcc # libgcc-7.3.1-2.fc26.x86_64
RUN yum -y install libgcrypt # libgcrypt-1.7.7-1.fc26.x86_64
RUN yum -y install libgpg-error # libgpg-error-1.25-2.fc26.x86_64
RUN yum -y install libselinux # libselinux-2.6-6.fc26.x86_64
RUN yum -y install pcre # pcre-8.40-7.fc26.x86_64
RUN yum -y install procps-ng # procps-ng-3.3.10-13.fc26.x86_64
RUN yum -y install systemd-libs # systemd-libs-233-6.fc26.x86_64
RUN yum -y install xz-libs # xz-libs-5.2.3-2.fc26.x86_64
RUN yum -y install zlib # zlib-1.2.11-2.fc26.x86_64

# Non-packaged executable files copies:
# Origin file does not exist:/lib64/libtinfo.so.5

# Data packages:
RUN yum -y install filesystem # filesystem-3.2-40.fc26.x86_64
# Already installed glibc -> glibc-2.25-6.fc26.x86_64
RUN yum -y install glibc-all-langpacks # glibc-all-langpacks-2.25-6.fc26.x86_64
RUN yum -y install glibc-common # glibc-common-2.25-6.fc26.x86_64
RUN yum -y install setup # setup-2.10.5-2.fc26.noarch
RUN yum -y install systemd # systemd-233-6.fc26.x86_64

# Data files:
# Origin file does not exist:/home/rchateau/rdfmon-code/Experimental/RetroBatch/TestProgs/sample_shell.sh

WORKDIR /home/rchateau/rdfmon-code/Experimental/RetroBatch

ENV BLOCKSIZE ""
ENV BLOCK_SIZE ""
ENV CMD_ENV ""
ENV COLUMNS ""
ENV I_WANT_A_BROKEN_PS ""
ENV LINES ""
ENV LS_BLOCK_SIZE ""
ENV POSIX2 ""
ENV POSIXLY_CORRECT ""
ENV PS_PERSONALITY ""
ENV QUOTING_STYLE ""
ENV TABSIZE ""
ENV UNIX95 ""

# Processes tree
# 2018-05-20 09:00:22.529684 -> 2018-05-20 09:00:23.657686 :      *Unknown-command*
# 2018-05-20 09:00:22.557771 -> 2018-05-20 09:00:23.657686 :          /usr/bin/ls
# 2018-05-20 09:00:22.598022 -> 2018-05-20 09:00:23.657686 :          *Unknown-command*
# 2018-05-20 09:00:22.599853 -> 2018-05-20 09:00:23.631763 :          *Unknown-command*
# 2018-05-20 09:00:23.641969 -> 2018-05-20 09:00:23.657686 :          /usr/bin/cat

