#!groovy

@Library('SovrinHelpers') _

try {
    testing()
    publishing()
    if (acceptanceTesting()) {
        releasing()
    }
    notifyingSuccess()
} catch (err) {
    notifyingFailure()
    throw err
}

def testing() {
    stage('Testing') {
        isDebugTests = !(env.BRANCH_NAME in ['master', 'rc'])
        parallel([
                'ubuntu-test' : { ubuntuTesting(isDebugTests) },
                'windows-test': { windowsTesting(isDebugTests) }
        ])
    }
}

def publishing() {
    stage('Publishing') {
        if (!(env.BRANCH_NAME in ['master', 'rc'])) {
            echo "${env.BRANCH_NAME}: skip publishing"
            return
        }
        echo "${env.BRANCH_NAME}: start publishing"

        publishedVersions = parallel([
                'ubuntu-files' : { ubuntuPublishing() },
                'windows-files': { windowsPublishing() },
        ])

        version = publishedVersions['ubuntu-files']
        if (publishedVersions['windows-files'] != version) {
            error "platforms artifacts have different versions"
        }
    }
}

def acceptanceTesting() {
    stage('Acceptance testing') {
        if (env.BRANCH_NAME == 'rc') {
            echo "${env.BRANCH_NAME}: acceptance testing"
            if (approval.check("default")) {
                return true
            }
        } else {
            echo "${env.BRANCH_NAME}: skip acceptance testing"
        }
        return false
    }
}

def releasing() {
    stage('Releasing') {
        if (env.BRANCH_NAME == 'rc') {
            publishingRCtoStable()
        }
    }
}

def notifyingSuccess() {
    if (env.BRANCH_NAME == 'master') {
        currentBuild.result = "SUCCESS"
        node('ubuntu-master') {
            sendNotification.success('indy-crypto')
        }
    }
}

def notifyingFailure() {
    currentBuild.result = "FAILED"
    node('ubuntu-master') {
        sendNotification.fail([slack: env.BRANCH_NAME == 'master'])
    }
}

void getSrcVersion() {
    commit = sh(returnStdout: true, script: 'git rev-parse HEAD').trim()
    version = sh(returnStdout: true, script: "wget -q https://raw.githubusercontent.com/hyperledger/indy-crypto/$commit/libindy-crypto/Cargo.toml -O - | grep -E '^version =' | head -n1 | cut -f2 -d= | cut -f2 -d '\"'").trim()
    return version
}

def linuxTesting(file, env_name, isDebugTests) {
    try {
        echo "${env_name} Test: Checkout csm"
        checkout scm

        def testEnv

        dir('libindy-crypto') {
            echo "${env_name} Test: Build docker image"
            
            testEnv = dockerHelpers.build('libindy-crypto', file)
            testEnv.inside() {
                echo "${env_name} Test: Test"
                try {
                    def buildType = ''
                    if (!isDebugTests) {
                        buildType = '--release'
                    }

                    testParams = "$buildType".trim()

                    echo "${env_name} Test: Build"
                    sh "RUST_BACKTRACE=1 cargo test $testParams --no-run"

                    echo "${env_name} Test: Run tests"
                    sh "RUST_BACKTRACE=1 RUST_LOG=trace cargo test $testParams"
                }
                finally {
                    /* TODO FIXME restore after xunit will be fixed
                    junit 'test-results.xml'
                    */
                }
            }
        }

        def folder = isDebugTests ? "debug" : "release"

        sh "cp libindy-crypto/target/$folder/libindy_crypto.so wrappers/python"
        dir('wrappers/python') {
            testEnv.inside() {
                echo "${env_name} Test: Test python wrapper"

                sh '''
                    python3.5 -m pip install --user -e .
                    LD_LIBRARY_PATH=./ RUST_LOG=trace python3.5 -m pytest
                '''
            }
        }
    }
    finally {
        step([$class: 'WsCleanup'])
    }
}

def windowsTesting(isDebugTests) {
    node('win2016') {
        stage('Windows Test') {
            echo "Windows Test: Checkout scm"
            checkout scm

            try {
                dir('libindy-crypto') {
                    def buildType = ''
                    if (!isDebugTests) {
                        buildType = '--release'
                    }

                    echo "Windows Test: Build"
                    withEnv([
                            "RUST_BACKTRACE=1"
                    ]) {
                        bat "cargo test $buildType --no-run"

                        echo "Windows Test: Run tests"
                        withEnv([
                                "RUST_TEST_THREADS=1",
                                "RUST_LOG=trace",
                        ]) {
                            bat "cargo test $buildType"
                        }
                    }
                }

                //TODO wrappers testing

            } finally {
                step([$class: 'WsCleanup'])
            }
        }
    }
}

def ubuntuTesting(isDebugTests) {
    node('ubuntu') {
        stage('Ubuntu Test') {
            linuxTesting("ci/ubuntu.dockerfile ci", "Ubuntu", isDebugTests)
        }
    }
}

def ubuntuPublishing() {
    node('ubuntu') {
        stage('Publish Ubuntu Files') {
            try {
                echo 'Publish Ubuntu files: Checkout csm'
                checkout scm

                version = getSrcVersion()

                echo 'Publish Ubuntu files: Build docker image'
                testEnv = dockerHelpers.build('indy-crypto', 'libindy-crypto/ci/ubuntu.dockerfile libindy-crypto/ci')

                libindyCryptoDebPublishing(testEnv)
                libindyCryptoCargoPublishing(testEnv, false)
                pythonWrapperPublishing(testEnv, false)
            }
            finally {
                echo 'Publish Ubuntu files: Cleanup'
                step([$class: 'WsCleanup'])
            }
        }
    }

    return version
}

def windowsPublishing() {
    node('win2016') {
        stage('Publish Libindy Crypto Windows Files') {
            try {
                echo 'Publish Windows files: Checkout csm'
                checkout scm

                version = getSrcVersion()

                dir('libindy-crypto') {
                    echo "Publish Windows files: Build"
                    withEnv([
                            "RUST_BACKTRACE=1"
                    ]) {
                        bat "cargo build --release"
                    }

                    withCredentials([file(credentialsId: 'EvernymRepoSSHKey', variable: 'evernym_repo_key')]) {
                        sh "./ci/libindy_crypto-win-zip-and-upload.sh $version '${evernym_repo_key}' $env.BRANCH_NAME $env.BUILD_NUMBER"
                    }
                }
            }
            finally {
                echo 'Publish Windows files: Cleanup'
                step([$class: 'WsCleanup'])
            }
        }
    }
    return version
}

def libindyCryptoDebPublishing(testEnv) {
    dir('libindy-crypto') {
        testEnv.inside('-u 0:0') {
            sh 'chmod -R 755 ci/*.sh'

            withCredentials([file(credentialsId: 'EvernymRepoSSHKey', variable: 'evernym_repo_key')]) {
                sh "./ci/libindy_crypto-deb-build-and-upload.sh $version $evernym_repo_key $env.BRANCH_NAME $env.BUILD_NUMBER"
                sh "rm -rf debian"
            }
        }
    }
}

def getSuffix(isRelease, target) {
    def suffix
    if (env.BRANCH_NAME == 'master' && !isRelease) {
        suffix = "-dev-$env.BUILD_NUMBER"
    } else if (env.BRANCH_NAME == 'rc') {
        if (isRelease) {
            suffix = ""
        } else {
            suffix = "-rc-$env.BUILD_NUMBER"
        }
    } else {
        error "Publish To ${target}: invalid case: branch ${env.BRANCH_NAME}, isRelease ${isRelease}"
    }
    return suffix
}

def libindyCryptoCargoPublishing(testEnv, isRelease) {
    dir('libindy-crypto') {
        testEnv.inside {
            def suffix = getSuffix(isRelease, "Cargo")
            sh "sed -i -E -e 'H;1h;\$!d;x' -e \"s/version = \\\"([0-9,.]+)/version = \\\"\\1$suffix/\" Cargo.toml"

            withCredentials([string(credentialsId: 'cargoSecretKey', variable: 'LOGIN')]) {
                sh 'cargo login $LOGIN'
                sh 'cargo package --allow-dirty'
                sh 'cargo publish --allow-dirty'
            }
        }
    }
}

def pythonWrapperPublishing(testEnv, isRelease) {
    dir('wrappers/python') {
        def suffix = getSuffix(isRelease, "Pypi")

        testEnv.inside {
            withCredentials([file(credentialsId: 'pypi_credentials', variable: 'credentialsFile')]) {
                sh 'cp $credentialsFile ./'
                sh "sed -i -E \"s/version='([0-9,.]+).*/version='\\1$suffix',/\" setup.py"
                sh '''
                    python3.5 setup.py sdist
                    python3.5 -m twine upload dist/* --config-file .pypirc
                '''
            }
        }
    }
}

def publishingRCtoStable() {
    node('ubuntu') {
        stage('Moving RC artifacts to Stable') {
            try {
                echo 'Moving RC artifacts to Stable: Checkout csm'
                checkout scm

                version = getSrcVersion()

                echo 'Moving RC artifacts to Stable: libindy-crypto'
                publishLibindyCryptoRCtoStable(version)

                echo 'Moving RC artifacts to Stable: Build docker image for wrappers publishing'
                testEnv = dockerHelpers.build('indy-crypto', 'libindy-crypto/ci/ubuntu.dockerfile libindy-crypto/ci')
                echo 'Moving RC artifacts to Stable: python wrapper'
                libindyCryptoCargoPublishing(testEnv, true)
                pythonWrapperPublishing(testEnv, true)
            } finally {
                echo 'Moving RC artifacts to Stable: Cleanup'
                step([$class: 'WsCleanup'])
            }
        }
    }
}

def publishLibindyCryptoRCtoStable(version) {
    rcFullVersion = "${version}-${env.BUILD_NUMBER}"
    withCredentials([file(credentialsId: 'EvernymRepoSSHKey', variable: 'key')]) {
        for (os in ['ubuntu', 'windows']) { //FIXME add rhel IS-307
            src = "/var/repository/repos/libindy_crypto/$os/rc/$rcFullVersion/"
            target = "/var/repository/repos/libindy_vrypto/$os/stable/$version"
            //should not exists
            sh "ssh -v -oStrictHostKeyChecking=no -i '$key' repo@192.168.11.111 '! ls $target'"
            sh "ssh -v -oStrictHostKeyChecking=no -i '$key' repo@192.168.11.111 cp -r $src $target"
        }
    }
}
