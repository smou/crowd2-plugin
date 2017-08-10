crowd2-plugin for Jenkins
=========================

This plugin delegates the authentication to a remote Crowd server
(http://www.atlassian.com/software/crowd). With this setting, users can
login by entering their Crowd username and password.

This plugin supports single-sign-on and also allows you to use Crowd groups
for authorization. For example, you can say "everyone in the 'developers'
group will have the administrator access".

## Building
Check out the code by calling:
```
git clone https://github.com/di2e/crowd2-plugin.git
```

Once checked out, the plugin can be built by running the following command:
```
mvn clean install
```

The deployable file, ```crowd2.hpi```, will be located in the target folder after the build finishes.

## Deploying
Deploying directly to jenkins can be done by:
1. Log in to Jenkins with an administrative user
2. Go to 'Manage Jenkins'
3. On the Manage Jenkins screen click on 'Manage Plugins'
4. Select the 'Advanced' tab
5. Select the .hpi file in the 'Upload Plugin' section and click on the 'Upload' button.
6. Once uploaded you can either have Jenkins restart itself when safe or manually restart the jenkins service.