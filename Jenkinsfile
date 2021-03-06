void setBuildStatus(String message, String state, String context) {
  step([
      $class: "GitHubCommitStatusSetter",
      reposSource: [$class: "ManuallyEnteredRepositorySource", url: "git@github.com:loomnetwork/transfer-gateway.git"],
      contextSource: [$class: "ManuallyEnteredCommitContextSource", context: context],
      errorHandlers: [[$class: "ChangingBuildStatusErrorHandler", result: "UNSTABLE"]],
      statusResultSource: [ $class: "ConditionalStatusResultSource", results: [[$class: "AnyBuildResult", message: message, state: state]] ]
  ]);
}

def builders = [:]

builders['linux'] = {
  node('linux-any') {
    timestamps {
      def thisBuild = null

      try {
        stage ('Checkout - Linux') {
          checkout changelog: true, poll: true, scm:
          [
            $class: 'GitSCM',
            branches: [[name: 'origin/pull/*/head']],
            doGenerateSubmoduleConfigurations: false,
            extensions: [
              [$class: 'PreBuildMerge',
              options: [
                fastForwardMode: 'FF',
                mergeRemote: 'origin',
                mergeTarget: 'master'
                ]],
              [$class: 'WipeWorkspace'],
              [$class: 'PruneStaleBranch'],
              [$class: 'RelativeTargetDirectory', relativeTargetDir: 'src/github.com/loomnetwork/transfer-gateway']
              ],
            submoduleCfg: [],
            userRemoteConfigs:
            [[
              url: 'git@github.com:loomnetwork/transfer-gateway.git',
              refspec: '+refs/heads/master:refs/remotes/origin/master +refs/pull/*/head:refs/remotes/origin/pull/*/head'
            ]]
          ]
        }

        setBuildStatus("Build ${env.BUILD_DISPLAY_NAME} is in progress", "PENDING", "Linux");

        stage ('Build - Linux') {
          sh '''
            ./src/github.com/loomnetwork/transfer-gateway/jenkins.sh
          '''
        }
      } catch (e) {
        thisBuild = 'FAILURE'
        throw e
      } finally {
        if (currentBuild.currentResult == 'FAILURE' || thisBuild == 'FAILURE') {
          setBuildStatus("Build ${env.BUILD_DISPLAY_NAME} failed", "FAILURE", "Linux");
        }
        else if (currentBuild.currentResult == 'SUCCESS') {
          setBuildStatus("Build ${env.BUILD_DISPLAY_NAME} succeeded in ${currentBuild.durationString.replace(' and counting', '')}", "SUCCESS", "Linux");
        }
      }
    }
  }
}

builders['osx'] = {
  node('osx-any') {
    timestamps {
      def thisBuild = null

      try {
        stage ('Checkout - OSX') {
          checkout changelog: true, poll: true, scm:
          [
            $class: 'GitSCM',
            branches: [[name: 'origin/pull/*/head']],
            doGenerateSubmoduleConfigurations: false,
            extensions: [
              [$class: 'PreBuildMerge',
              options: [
                fastForwardMode: 'FF',
                mergeRemote: 'origin',
                mergeTarget: 'master'
                ]],
              [$class: 'WipeWorkspace'],
              [$class: 'PruneStaleBranch'],
              [$class: 'RelativeTargetDirectory', relativeTargetDir: 'src/github.com/loomnetwork/transfer-gateway']
              ],
            submoduleCfg: [],
            userRemoteConfigs:
            [[
              url: 'git@github.com:loomnetwork/transfer-gateway.git',
              refspec: '+refs/heads/master:refs/remotes/origin/master +refs/pull/*/head:refs/remotes/origin/pull/*/head'
            ]]
          ]
        }

        setBuildStatus("Build ${env.BUILD_DISPLAY_NAME} is in progress", "PENDING", "OSX");

        stage ('Build - OSX') {
          sh '''
            ./src/github.com/loomnetwork/transfer-gateway/jenkins.sh
          '''
        }
      } catch (e) {
        thisBuild = 'FAILURE'
        throw e
      } finally {
        if (currentBuild.currentResult == 'FAILURE' || thisBuild == 'FAILURE') {
          setBuildStatus("Build ${env.BUILD_DISPLAY_NAME} failed", "FAILURE", "OSX");
        }
        else if (currentBuild.currentResult == 'SUCCESS') {
          setBuildStatus("Build ${env.BUILD_DISPLAY_NAME} succeeded in ${currentBuild.durationString.replace(' and counting', '')}", "SUCCESS", "OSX");
        }
      }
    }
  }
}

throttle(['loom-sdk']) {
  timeout(time: 60, unit: 'MINUTES'){
    parallel builders
  }
}
