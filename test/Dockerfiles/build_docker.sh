#!/bin/bash -x

travis_docker_env ()
{
    if [[ -n "${DOCKER_IMG_JM}" ]] && [[ "${HAS_JOSH_K_SEAL_OF_APPROVAL}" == true ]]; then
        return 0
    else
        return 1
    fi
}

build_docker ()
{
    if ! travis_docker_env; then
        return 0
    fi

    core_version='0.16.1'
    core_dist="bitcoin-${core_version}-x86_64-linux-gnu.tar.gz"
    core_url="https://bitcoin.org/bin/bitcoin-core-${core_version}/${core_dist}"
    jm_root="${TRAVIS_BUILD_DIR}"
    owner_name="${TRAVIS_REPO_SLUG%\/*}"
    repo_name="${TRAVIS_REPO_SLUG#*\/}"

    if [[ ! -f "${HOME}/downloads/${core_dist}" ]]; then
        wget "${core_url}" -O "$HOME/downloads/${core_dist}"
    fi

    mkdir -p "${jm_root}/deps"
    cp "${HOME}/downloads/${core_dist}" "${jm_root}/deps/"
    cd "${jm_root}/../"

    docker build \
        --shm-size=1G \
        --build-arg core_version="${core_version}" \
        --build-arg core_dist="${core_dist}" \
        --build-arg repo_name="${repo_name}" \
        -f "./${repo_name}/test/Dockerfiles/${DOCKER_IMG_JM}.Dockerfile" .
    return "$?"
}
build_docker
