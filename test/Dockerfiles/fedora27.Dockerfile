FROM fedora:27
SHELL ["/bin/bash", "-c"]

# dependencies
RUN dnf -y groups install 'Development tools'
RUN dnf -y install \
    autoconf libtool pkgconfig \
    python-devel python-pip python2-virtualenv

# needed for build time
# https://stackoverflow.com/questions/34624428/g-error-usr-lib-rpm-redhat-redhat-hardened-cc1-no-such-file-or-directory
RUN dnf -y install redhat-rpm-config

RUN useradd --home-dir /home/chaum --create-home --shell /bin/bash --skel /etc/skel/ chaum
ARG core_version
ARG core_dist
ARG repo_name
RUN mkdir -p /home/chaum/${repo_name}
COPY ${repo_name} /home/chaum/${repo_name}
RUN ls -la /home/chaum
RUN chown -R chaum:chaum /home/chaum/${repo_name}
USER chaum

# copy node software from the host and install
WORKDIR /home/chaum
RUN ls -la .
RUN ls -la ${repo_name}
RUN ls -la ${repo_name}/deps
RUN tar xaf ./${repo_name}/deps/${core_dist} -C /home/chaum
ENV PATH "/home/chaum/bitcoin-${core_version}/bin:${PATH}"
RUN bitcoind --version | head -1

# install script
WORKDIR ${repo_name}
RUN ./install.sh --no-gpg-validation
RUN source jmvenv/bin/activate && ./test/run_tests.sh
