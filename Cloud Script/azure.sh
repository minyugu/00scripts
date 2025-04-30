# ps
Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force

# cli
az --version
az cloud set -n AzureChinaCloud
az cloud set -n AzureCloud
az login

#Sign in with a managed identity
az login --identity

# $1000
subscriptionId='07936935-5ab8-40b8-9c34-e097c4d462ea'
# 21v
subscriptionId='fc13c8a6-8596-4e22-80f7-966c93f1a457'
# MSDN
subscriptionId='67cd700e-3be0-4d8a-a7ef-6119f9c991c1'

# China 21v
subscriptionId='fc13c8a6-8596-4e22-80f7-966c93f1a457'

$location='chinaeast2'

#tenant
az account tenant list

# subscription
az account list \
   --refresh \
   --output table \
   --query "[?contains(name, 'Concierge Subscription')].id"

az account set --subscription $subscriptionId

# list quota
az quota list --scope "subscriptions/$($subscriptionId)/providers/Microsoft.Compute/locations/$($location)"
az quota list --scope "subscriptions/fc13c8a6-8596-4e22-80f7-966c93f1a457/providers/Microsoft.Network/locations/chinanorth2"

# region
az account subscription list-location --subscription-id ${subscriptionId} -o table

# service principal
az ad sp create-for-rbac --name [APP_NAME] --password [CLIENT_SECRET]

# resource group
$DefaultResourceGroup='learn-91c4be74-ed17-48a9-85c7-351863059152'
az group create --location $location -name $DefaultResourceGroup
az configure --defaults group=$DefaultResourceGroup

# key vault
keyVaultName='kv-mg-learning' # A unique name for the key vault.
login='myadmin' # The login that you used in the previous step.
password='Pass@word' # The password that you used in the previous step.

az group create --name 'dataOps-rg' --location 'eastasia'
az keyvault create --name $keyVaultName --location westus --enabled-for-template-deployment true
az keyvault secret set --vault-name $keyVaultName --name "sqlServerAdministratorLogin" --value $login
az keyvault secret set --vault-name $keyVaultName --name "sqlServerAdministratorPassword" --value $password
az keyvault show --name $keyVaultName --query id --output tsv

# create log analytics
az monitor log-analytics workspace create \
  --workspace-name ToyLogs \
  --location eastus

# create storageaccount
storageAccountName='sa2ea2mystorageaccount'
containerName='mgcontainer'
resourceGroupName='rg-storage'
accountKey='jeFEx+om5TcazhSe0a/gslcXNpyBEjLspPYS0z6Zk5rd2DJM4BkDFagZR67mrlpObnRpmxm5SQXyRUPCQvo/2Q=='

az storage account create \
  --name mgtoystorageaccount09 \
  --location eastus

# list storage key
storageAccountName='sa2ea2mystorageaccount'
resourceGroupName='rg-storage'
az storage account keys list -g $(resourceGroupName) -n $(storageAccountName)

# get Storage container
az storage container exists --account-name ${storageAccountName} --account-key ${accountKey} --name ${containerName}
az storage container exists --account-name ${storageAccountName} --name ${containerName}
# generate sas
end=`date -u -d "30 minutes" '+%Y-%m-%dT%H:%MZ'`
az storage container generate-sas --account-name ${storageAccountName} -n ${containerName} --https-only --permissions dlrw --expiry ${end} -o tsv

# az extension
az extension list -o table
az extension list-available -o table
az extension add --name application-insights
az extension add --name azure-devops

# Azure DevOps
az devops configure --defaults organization=https://dev.azure.com/mgMicrosoft/parking_sensors
az devops configure --defaults organization=https://dev.azure.com/mgMicrosoft project=parking_sensors
az devops project list --organization https://dev.azure.com/mgMicrosoft
az devops configure --list

######### ARM Template #########
# install bicep
az bicep install && az bicep upgrade

# ARM template
az deployment group create --template-file main.bicep

az deployment group create \
  --template-file main.bicep \
  --parameters main.parameters.dev.json

az deployment group create --template-file main.bicep --parameters environmentName=Production location=westeurope

az deployment group create \
  --template-file main.bicep \
  --parameters storageAccountName="mgtoystorageaccount09"

az deployment group what-if \
  --template-file main.bicep

az deployment group what-if \
  --what-if-exclude-change-types
  --template-file main.bicep
  --no-pretty-print

az deployment group create \
  --mode Complete \
  --confirm-with-what-if \
  --template-file main.bicep

# convert jason to bicep
az bicep decompile --file template.json
#=================================== tools ===================================
# mount file shell in cloud shell
clouddrive mount -s '67cd700e-3be0-4d8a-a7ef-6119f9c991c1' -g 'rg-sharedstorage' -n 'shared2storage2account' -f 'cloudshelldrive'

# Azcopy
&"C:\Program Files\azcopy_windows_amd64_10.14.1\azcopy.exe" copy `
  "C:\MyGu\OneDrive\WorkData\My Documents\0 MS\.DevOps\repository\Fundamentals of Bicep" `
  "https://cloudshellstorag0ea.file.core.windows.net/fs-cloudshell/Deployment?sv=2020-08-04&ss=f&srt=sco&sp=rwdlc&se=2024-04-06T15:59:59Z&st=2022-04-06T16:00:00Z&spr=https&sig=B13I82Cfdx%2Br1Op1qjB5UehZuNzf0cJk7ezHEScI7Fg%3D" `
  --recursive --preserve-smb-permissions=true --preserve-smb-info=true

# Windows Subsystem for Linux
wsl --install
wsl --install -d Ubuntu

#=================================== databricks az cli ===================================
adbWorkspaceName='dbks-n2-databricks'
resourceGroupName='rg-databricks'

# get databrics workspace
az databricks workspace show \
  --name $adbWorkspaceName \
  --resource-group $resourceGroupName

# update databrics workspace
az databricks workspace update \
  --name $adbWorkspaceName \
  --resource-group $resourceGroupName \
  --enable-no-public-ip

#=================================== databricks cli ===================================
pip install databricks-cli

#=================================== databricks api ===================================
export DATABRICKS_TOKEN=dapi5172ffeea0019f5a9624a8b960a493cc
# check ip access control
curl -X GET --header "Authorization: Bearer $DATABRICKS_TOKEN" \
  https://adb-5473740219084800.0.databricks.azure.cn/api/2.0/workspace-conf?keys=enableIpAccessLists

# enable ip access
curl -X PATCH --header "Authorization: Bearer $DATABRICKS_TOKEN" \
    https://adb-5473740219084800.0.databricks.azure.cn/api/2.0/workspace-conf \
    -d '{
      "enableIpAccessLists": "true"
      }'

# get ip access lists
curl -X GET --header "Authorization: Bearer $DATABRICKS_TOKEN" \
  https://adb-5473740219084800.0.databricks.azure.cn/api/2.0/ip-access-lists \
  | jq -s

# set allow ip access
curl -X POST --header "Authorization: Bearer $DATABRICKS_TOKEN" \
  https://adb-5473740219084800.0.databricks.azure.cn/api/2.0/ip-access-lists \
  -d '{
    "label": "office",
    "list_type": "ALLOW",
    "ip_addresses": [
        "52.184.28.75",
        "0.0.0.0/0"
      ]
    }'

# add block ip access 
curl -X POST --header "Authorization: Bearer $DATABRICKS_TOKEN" \
  https://adb-5473740219084800.0.databricks.azure.cn/api/2.0/ip-access-lists \
  -d '{
    "label": "kgfw",
    "list_type": "BLOCK",
    "ip_addresses": [
        "13.77.168.118"
      ]
    }'

# update ip access 
curl -X PATCH --header "Authorization: Bearer $DATABRICKS_TOKEN" \
  https://adb-5473740219084800.0.databricks.azure.cn/api/2.0/ip-access-lists/1363e3c3-186c-4bd5-9319-6ffe02393808 \
  -d '{     
    "ip_addresses": [
    "13.77.168.118"
    ]
  }'

curl -X PATCH --header "Authorization: Bearer $DATABRICKS_TOKEN" \
  https://adb-5473740219084800.0.databricks.azure.cn/api/2.0/ip-access-lists/cdf89097-2941-4fd6-8df4-d85f30a1210f \
  -d '{
    "enabled": false
  }'

# get cluster
curl -X GET --header "Authorization: Bearer $DATABRICKS_TOKEN" \
  https://adb-5473740219084800.0.databricks.azure.cn/api/2.0/clusters/list

# get notebook
curl -X GET --header "Authorization: Bearer $DATABRICKS_TOKEN" \
  https://adb-5473740219084800.0.databricks.azure.cn/api/2.0/workspace/get-status \
  --header 'Accept: application/json' \
  --data '{ "path": "/Users/mg@sh.omygu.com/03-Reading-and-writing-data-in-Azure-Databricks/5.Writing Data" }' \
  | jq -s

######## Create or update workspace with custom parameters
subscriptionId='fc13c8a6-8596-4e22-80f7-966c93f1a457'
resourceGroupName='rg-databricks'
adbWorkspaceName='dbks-n2-databricks'

curl -X GET --header "Authorization: Bearer $armAccessToken" \
  https://management.chinacloudapi.cn/subscriptions/${subscriptionId}/resourceGroups/${resourceGroupName}/providers/Microsoft.Databricks/workspaces/${adbWorkspaceName}?api-version=2018-04-01 \
  | jq -s

# update Databricks workspace
curl -X PATCH --header "Authorization: Bearer $armAccessToken" -H "Content-Type: application/json" \
  -d '{
    "tags": {
      "enableNoPublicIP": "false"
    }
  }' \
  https://management.chinacloudapi.cn/subscriptions/${subscriptionId}/resourceGroups/${resourceGroupName}/providers/Microsoft.Databricks/workspaces/${adbWorkspaceName}?api-version=2018-04-01 \
  | jq -s

<# unspport
  -d '{
    "properties": {
      "parameters": {
        "enableNoPublicIp": {
          "value": ture
        }
      }
    }
  }
#>

#=================================== Azure Resource Manager REST API ===================================
########## authorization Option 1 - Code grant
# parameter
tenantId='8c942a06-79ec-4931-b8aa-0c9b701a77d6'
scope='https%3A%2F%2Fmanagement.chinacloudapi.cn%2Fuser_impersonation'
redirectUri='http%3A%2F%2Flocalhost%2Fsp_ArmApi%2F'
decodeRedirectUri='http://localhost/sp_ArmApi/'
clientId='1697c3c7-e7b4-400f-84e5-97d608c4a125'
clientSecret='_.lIPaD2sKigRH.2DeaJ.VPQh8J1di.DGu'

# request an authorization code from Azure AD
authCodeUrl="https://login.partner.microsoftonline.cn/${tenantId}/oauth2/v2.0/authorize?scope=${scope}&client_id=${clientId}&response_type=code&redirect_uri=${redirectUri}&response_mode=query&state=12345"
echo ${authCodeUrl}
"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --new-window ${authCodeUrl}

# Request an access token with a client_secret
armAuthorizationCode='0.AAAABiqUjOx5MUm4qgybcBp31tiyqCdlMmVMhzyHSdpWhBYBALw.AQABAAIAAADF8uhbdqMKTqrrFtoyDhmY-1EYk6Xckott6HSZC7FrbJewJRiZsLqWd-8utWMZq4lNpvjgxAdHTmHEAtdrMIhZZJ0rmVIRVSxIM4zJOiMl8ErXd8YAF2IIK15O1hIItHHBec_7kZKBO7WBRevii8Mg8_XOC13vc3obn_zpZKeQdTVumgbYUfYpwsdho70nO5qsT0SmShvxWW1WAciielulB_erRNjIE79ln_HCK9tx_HU-00EPCIX9phDh-lgBfh5ORVUQpAXJ77rR-3TEJ_7ZJdgeMd1K6O6b66mUIopQv-ypZc4KP3SbHPXty9NH_qF-kq1SJw9o0pe3K7YOwcg2zmEuPB4OnEn4YH5Dp5YA-2iBO261We_Sh2-2zu3rJegCUDD_0fZhx5uRHF65u9RkN-JC7wUzNfLgKCPeCquEpnotS2pM8HvvB1T8gGhC-Tvj08vkEAnAXSNaZPwgia8tE7-GMngSxFhMFahi0vpvQF8mxE6c5GDRz_-5itmCeM7l0LqKK60AU4WRysjQBh1R7a0nb4tSXdrDqQ333gQ-9iyEWvloJV7LJ_IFIJIXN0ZVVLsYGobowbpqac7wW3CRIxw8mecIqUiPu8PTE5jIK90lfFkz3NS8sKhXEozx_f6pcogPmF49KUJFDD9AWzBWcsMQp8sSSMmDM6opKUidGSAA'

armAccessToken=$(curl -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${clientId}&scope=${scope}&code=${armAuthorizationCode}&redirect_uri=${redirectUri}&grant_type=authorization_code&client_secret=${clientSecret}" \
  https://login.partner.microsoftonline.cn/8c942a06-79ec-4931-b8aa-0c9b701a77d6/oauth2/v2.0/token \
  | jq -s -r '.[].access_token' \
  )
  
echo $armAccessToken

########## authorization Option 2 - client credentials
# parameter
tenantId='8c942a06-79ec-4931-b8aa-0c9b701a77d6'
scope='https%3A%2F%2Fmanagement.chinacloudapi.cn%2F.default'
redirectUri='http%3A%2F%2Flocalhost%2Fsp_ArmApi%2F'
decodeRedirectUri='http://localhost/sp_ArmApi/'
clientId='1697c3c7-e7b4-400f-84e5-97d608c4a125'
clientSecret='_.lIPaD2sKigRH.2DeaJ.VPQh8J1di.DGu'

# Request the permissions from a directory admin
echo "https://login.partner.microsoftonline.cn/${tenantId}/adminconsent?client_id=${clientId}&state=12345&redirect_uri=${redirectUri}permissions"

echo "${decodeRedirectUri}permissions?tenant=${tenantId}/&state=state=12345&admin_consent=True"

armAccessToken=$(curl -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${clientId}&scope=${scope}&client_secret=${clientSecret}&grant_type=client_credentials" \
  "https://login.partner.microsoftonline.cn/${tenantId}/oauth2/v2.0/token" \
  | jq -s -r '.[].access_token' \
  )

#=================================== Git ===================================
#=================================== Git ===================================
# https://dev.to/web/list-of-all-git-commands-4m83
ls -path ".\*.git" -Recurse -Force | Format-Table FullName

cd '/C/MyGu/OneDrive/WorkData/My Documents/0 MS/.DevOps/repository/terraform/terraform101/deploy'

# git var
$gitPAT = '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'
$gitAccountName = 'minyugu'
$gitRepoName = 'modern-data-warehouse-dataops'

git --version
git config --global user.name "My Gu"
git config --global user.email "mygu@outlook.com"
git config --list
code --reuse-window .
git init
git status
git branch -M main
git add .
git commit --message "Add first version of Bicep template."
git log --pretty=oneline

##### start branch #####
# switch/create add-database branch
git checkout -b add-database
# switch main branch
git checkout main

$gitRepoUrl = 'https://github.com/minyugu/toy-website-review.git'
$localPath = '2-4. Review Azure infrastructure changes by using Bicep and pull requests'
git clone $gitRepoUrl $localPath
code -r $localPath~

# merge branch to main
git merge add-database
# remove branch
git branch -d add-database

# push local branch to remote main branch
git push -u origin main

# pushed to a new branch, also named add-orders-queue
git push --set-upstream origin 'add-orders-queue'

# reset the state of the main branch to what it was before the last commit was merged in
git reset --hard HEAD~1
##### end branch #####

# add remote repo
git remote add origin 'https://github.com/minyugu/terraform101.git'
# clone git
git clone -c http.sslVerify=false -c http.extraHeader='Authorization: Bearer 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' https://github.com/minyugu/databricksPublic

#git clone https://minyugu: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@github.com/minyugu/databricksPublic.git

# change PAT
git remote set-url origin "https://$($gitPAT)@github.com/$($gitAccountName)/$($gitRepoName).git"

# check and remove remote repo with local repo
git remote -v
git remote rm origin

# remove local repo
git rm -r "C:\MyGu\OneDrive\WorkData\My Documents\0 MS\.DevOps\repository\tp\databricksPublic"

# remove a file from being tracked
git rm --cached 'terraform.lock.hcl'

#=================================== Git Bash ===================================
echo $VAR
export VAR="my value"

#=================================== chocolatey ===================================
choco upgrade chocolatey

#=================================== Terraform ===================================
#!/bin/sh
echo "Setting environment variables for Terraform"
export ARM_SUBSCRIPTION_ID=fc13c8a6-8596-4e22-80f7-966c93f1a457
#export ARM_CLIENT_ID=eb74b366-a193-4c25-bee7-90047ac0e600
export ARM_CLIENT_ID=f2203519-e46d-4b2e-98b7-8b0ac69fd988
export ARM_CLIENT_SECRET=KehnDk0s6rvgi_8u4M.~_8G5vKD.jsOzqS
export ARM_TENANT_ID=8c942a06-79ec-4931-b8aa-0c9b701a77d6
# Not needed for public, required for usgovernment, german, china
export ARM_ENVIRONMENT=china

terraform version

terraform init \
  -backend-config=environment=china \
  -backend-config=storage_account_name=terraform101cn3sa \
  -backend-config=container_name=terraform \
  -backend-config=key=prod.terraform101.tfstate \
  -backend-config=resource_group_name=terraform101-cn3-rg \
  -backend-config=subscription_id=fc13c8a6-8596-4e22-80f7-966c93f1a457 \
  -backend-config=tenant_id=8c942a06-79ec-4931-b8aa-0c9b701a77d6 \
  -backend-config=client_id=f2203519-e46d-4b2e-98b7-8b0ac69fd988 \
  -backend-config=client_secret=KehnDk0s6rvgi_8u4M.~_8G5vKD.jsOzqS

terraform init
terraform validate
terraform plan -var "terraformStateSaName=terraform101cn3sa"
terraform plan -var-file="variables.tf"

terraform apply -auto-approve -var "terraformStateSaName=terraform101cn3sa"
terraform apply -auto-approve -var-file="variables.tf"

# terraform destroy

#=================================== Kubernetes ===================================
# install kubectl
curl -LO "https://dl.k8s.io/release/v1.24.0/bin/windows/amd64/kubectl.exe"

# get credential for aks
resourceGroupName='myKubernetes-ea-rg'
aksClusterName='devops-agent-ea-aks'
az aks get-credentials --resource-group $resourceGroupName --name $aksClusterName

# list cluster
kubectl get nodes

# deploy application
kubectl apply -f azure-vote.yaml

# watch application
kubectl get service azure-vote-front --watch

#### ReplicaSet
replicaSetName='azdevops-deployment-6467886bcb'
# view the status of your ReplicaSet
kubectl get rs $replicaSetName

# https://docs.microsoft.com/en-us/azure-stack/aks-hci/create-replicasets
# edit controller's configuration
kubectl edit rs $replicaSetName

# replace Controller
kubectl replace -f ReplicationController.yaml

# directly increase or decrease the number
kubectl scale --replicas=10 rs $replicaSetName

# Verify ClusterRole & ClusterRoleBinding 
kubectl get clusterrole
kubectl get clusterrolebinding
kubectl get serviceaccount

# get aks info
az aks show --resource-group $resourceGroupName --name $aksClusterName

# Validate the ACR is accessible from the AKS cluster
az aks check-acr --name $aksClusterName --resource-group $resourceGroupName --acr "$containerRegistryName.azurecr.io"

#=================================== container-registry ===================================
# Log in to registry
containerRegistryName='mgimage'
az acr login --name $containerRegistryName

# pull image
docker pull mcr.microsoft.com/hello-world

# tag image
docker tag mcr.microsoft.com/hello-world "${containerRegistryName}.azurecr.io/hello-world:v1"

# push image
docker push "${containerRegistryName}.azurecr.io/hello-world:v1"

# remove image in local dock
docker rmi "${containerRegistryName}.azurecr.io/hello-world:v1"

# Run image from remote registry
docker run "${containerRegistryName}.azurecr.io/hello-world:v1"

#=================================== Using dock for DevOps Agent ===================================
## https://docs.microsoft.com/en-us/azure/devops/pipelines/agents/docker?view=azure-devops#create-and-build-the-dockerfile-1

# build the image
docker build -t dockeragent:latest .

# Start the dock image as ADO pool agent
azpUrl='https://dev.azure.com/omygu-com'
azpToken='r2s5l6gylupzsyktgba6d2s76jhnd3fvlha4rqvddz7l5fo2qtgq'
azpAgentName='dock agent 1'
azpPool='Dock Agents'
docker run -e AZP_URL=$azpUrl -e "AZP_TOKEN=$azpToken" -e "AZP_AGENT_NAME=$azpAgentName" -e "AZP_POOL=$azpPool" dockeragent:latest

#=================================== Using AKS for DevOps Agent ===================================
## https://docs.microsoft.com/en-us/azure/devops/pipelines/agents/docker?view=azure-devops#deploy-and-configure-azure-kubernetes-service

# Configure secrets and deploy a replica set
azpUrl='https://dev.azure.com/omygu-com'
azpToken='r2s5l6gylupzsyktgba6d2s76jhnd3fvlha4rqvddz7l5fo2qtgq'
azpAgentName='dock agent 1'
azpPool='Dock Agents'

containerRegistryName='mgimage'

kubectl create secret generic azdevops \
  --from-literal=AZP_URL="$azpUrl" \
  --from-literal=AZP_TOKEN="$azpToken" \
  --from-literal=AZP_POOL="$azpPool"

# tag image
docker tag dockeragent:latest "${containerRegistryName}.azurecr.io/dockeragent:latest"

# push dock image
docker push "${containerRegistryName}.azurecr.io/dockeragent:latest"

# deploy agent
kubectl apply -f ReplicationController.yaml
kubectl get service "azdevops-deployment" --watch

# replace Controller
kubectl replace -f ReplicationController.yaml

# Install controller
kubectl apply -f https://raw.githubusercontent.com/cloudoven/azdo-k8s-agents/main/src/kubernetes/install.yaml