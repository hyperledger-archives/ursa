#!groovy

try {
    testing()
} catch (err) {
    notifyingFailure()
    throw err
}

def testing() {
    stage('Testing') {
        parallel([
                'ubuntu-test' : { ubuntuTesting() },
                'windows-test': { windowsTesting() }
        ])
    }
}

def notifyingFailure() {
    currentBuild.result = "FAILED"
    node('ubuntu-master') {
        sendNotification.fail([email: true])
    }
}

def getUserUid() {
    return sh(returnStdout: true, script: 'id -u').trim()
}

def linuxTesting(file, env_name) {
    try {
        echo "${env_name} Test: Checkout csm"
        checkout scm

        def testEnv

        dir('libindy-crypto') {
            echo "${env_name} Test: Build docker image"

            testEnv = docker.build("libindy-crypto-test", "--build-arg uid=${getUserUid()} -f $file")
            testEnv.inside {
                echo "${env_name} Test: Test"

                echo "${env_name} Test: Build"
                sh "RUST_BACKTRACE=1 cargo test --no-run"

                echo "${env_name} Test: Run tests"
                sh "RUST_BACKTRACE=1 RUST_LOG=trace cargo test"
            }
        }

        sh "cp libindy-crypto/target/debug/libindy_crypto.so wrappers/python"
        dir('wrappers/python') {
            testEnv.inside {
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

def windowsTesting() {
    node('win2016') {
        stage('Windows Test') {
            echo "Windows Test: Checkout scm"
            checkout scm

            try {
                dir('libindy-crypto') {
                    echo "Windows Test: Build"
                    withEnv([
                            "RUST_BACKTRACE=1"
                    ]) {
                        bat "cargo test --no-run"

                        echo "Windows Test: Run tests"
                        withEnv([
                                "RUST_TEST_THREADS=1",
                                "RUST_LOG=trace",
                        ]) {
                            bat "cargo test"
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

def ubuntuTesting() {
    node('ubuntu') {
        stage('Ubuntu Test') {
            linuxTesting("ci/ubuntu.dockerfile ci", "Ubuntu")
        }
    }
}