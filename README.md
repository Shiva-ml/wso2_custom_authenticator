## Custom Local Authenticator

### Build the Application
- Use the following command to make the custom provisioning connector artifact, `org.wso2.custom.local.authenticator`.
```bash
mvn clean install -DskipTests
```

### Configure the Application in WSO2 IS
- Copy the artifact and put it into `<IS_HOME>/repository/components/dropins` directory.
- Run the IS server with OSGi console using the following command.
```bash
./wso2server.sh -DosgiConsole
```
- After starting the WSO2 Management Console, check whether the artifact in `ACTIVE` state by typing,
```bash
ss org.wso2.custom.local.authenticator
```

### Test the Custom Local Authenticator
- Create an SP using the following DCR script.
```bash
curl -k -X POST -H "Authorization: Basic YWRtaW46YWRtaW4=" -H "Content-Type: application/json" -d '{"client_name": "playground_2","grant_types": ["authorization_code","password"], "redirect_uris": ["http://localhost:8080/playground2/oauth2client"],"ext_param_client_id":"provided_client_id0001","ext_param_client_secret":"provided_client_secret0001" }' "https://localhost:9443/api/identity/oauth2/dcr/v1.1/register"
```
- Go to `Local & Outbount Authentication Configuration` and select the local authenticator you have created from the `Local Authentication` list.