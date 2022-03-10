#!/bin/bash

# Log levels
readonly LOG_LEVEL_ERROR="ERROR"
readonly LOG_LEVEL_INFO="INFO"
readonly LOG_LEVEL_DEBUG="DEBUG"
readonly SPOT_IDENTIFIER_URI="https://spot.io"
readonly POLICY_FILE_NAME="/tmp/spot_azure_policy.json"
readonly POLICY_FILE_NAME_TEMP="/tmp/spot_azure_policy_temp.json"
readonly APP_AVAILALBE_TO_OTHER_TENANTS="false"
readonly SECRETS_STORE="/tmp/spot_azure_secrets_store.json"
readonly ACCOUNTS_STORE="/tmp/spot_azure_accounts_store.json"
readonly TEMP_APP_DETAILS_LOCATION="/tmp/spot_app_azure_details.json"

function cleanup {
	rm $POLICY_FILE_NAME_TEMP $POLICY_FILE_NAME $ACCOUNTS_STORE $SECRETS_STORE $TEMP_APP_DETAILS_LOCATION
}

function format_timestamp {
  date +"%Y-%m-%d %H:%M:%S"
}

function log {
  local readonly timestamp="$1"
  shift
  local readonly log_level="$1"
  shift
  local readonly message="$@"
  echo -e "${timestamp} [${log_level}] ${message}"
}

function log_error {
  log "$(format_timestamp)" "$LOG_LEVEL_ERROR" "$@"
}

function log_info {
  log "$(format_timestamp)" "$LOG_LEVEL_INFO" "$@"
}

function log_info_sleep {
  log "$(format_timestamp)" "$LOG_LEVEL_INFO" "$@"
  sleep 2
}

function log_debug {
  log "$(format_timestamp)" "$LOG_LEVEL_DEBUG" "$@"
}

function getDate {
	local date_az=`[ "$(uname)" = Linux ] && date --date="+2 years" +"%Y"-"%m"-"%d" || date -v+02y +"%Y"-"%m"-"%d"`
	echo $date_az
}

KeyboardInterrupt() {
	kill $PID
	echo "Please make sure you continued from where you've stopped"
}

function azureCliNotSupported() { log_error "Azure CLI is not installed in your OS. In order to make this script work, please install it and then proceed"; exit 0; }

function jqNotSupported () {  log_error "jq command which is used in the script to parse azure data is not available in your OS, hence the script couldn't be executed.\n\tPlease download jq and then proceed."; exit 0; }

function searchAndReplace () {
	local search=$1
	local replace=$2
	local filename=$3

	echo "$1 $2 $3"
	sed -i "" "s/{$search}/$replace/g" $POLICY_FILE_NAME

}

function validate {
  log_info "Validating"

  if ! hash az 2>/dev/null; then 
  	azureCliNotSupported
  fi

  if ! hash jq 2>/dev/null; then
  	jqNotSupported
  fi

  log_info "All prerequisites are available, will proceed to connect application"

}

function parseAzureFile {
	local shouldRemoveFirstCharacter=`head -c 1 $1`

	if [[ "$shouldRemoveFirstCharacter" == "=" ]]; then
		echo "In cond"
		echo `cat $1 | cut -c2-500000` > $1
	fi
}

# function savedPatchedApplicationDetailsIfExists {
# 	echo `az ad app show --id 
# }

function createAppRegistration {
	local APP_CREATION_SIGNAL='appId'
	local APP_REGISTRATION_PATCH_ERROR="WARNING: Found an existing application instance of"

	while true; do
		read -p "Please pick a name for the application: " chosenApplicationName
		registeredApplicationDetails==`az ad app create --display-name $chosenApplicationName --reply-urls "$SPOT_IDENTIFIER_URI" --available-to-other-tenants $APP_AVAILALBE_TO_OTHER_TENANTS`

		case "$registeredApplicationDetails" in 
	  		*"$APP_CREATION_SIGNAL"*) echo "Application Created Successfully"; echo $registeredApplicationDetails > $TEMP_APP_DETAILS_LOCATION; parseAzureFile $TEMP_APP_DETAILS_LOCATION; break;;
	  		* ) echo "Invalid, please run again.";;
		esac
	done

	cat $TEMP_APP_DETAILS_LOCATION
}

function getAppId {
	local appId=`cat $TEMP_APP_DETAILS_LOCATION | jq -r ".appId"`
	echo $appId

}

function validateCreatedRole {
	local ROLE_CREATION_SIGNAL="notActions"
	local attempts=0

	while true; do
		spot_azure_created_role=`az role definition create --role-definition $POLICY_FILE_NAME --subscription "$account_to_connect"`

		case "$spot_azure_created_role" in 
	  		*"$APP_CREATION_SIGNAL"*) echo "Role Created Successfully"; break;;
	  		* ) echo "Invalid, please run again.";;
		esac
		if [[ $attempts == 5 ]]; then
			echo "Reached max attempts when trying to create role, exiting."
		fi
		((attempts=attempts+1))

	done

}

function connectSubscription {
	log_info "In Subscription"
	accountId=$1
	token=$2
	tenantId=`cat $ACCOUNTS_STORE | jq -r ".tenantId"`
	subscriptionId=`cat $ACCOUNTS_STORE | jq -r ".id"`
	clientId=`cat $SECRETS_STORE | jq -r ".appId"`
	clientSecret=`cat $SECRETS_STORE | jq -r ".password"`
	local MAX_ATTEMPTS=5
	local attempts=0
	local timeout=1


	log_info "Params: token: $token\nAccountId: $accountId\ntenantId: $tenantId\nsubscriptionId: $subscriptionId\nclientId: $clientId\nclientSecret: $clientSecret"
	read -p "Would you like to continue?: "

	while [[ $attempts < $MAX_ATTEMPTS ]]; do
		req=`curl --location --request POST "https://api.spotinst.io/azure/setup/credentials?spotinstAccountId=${accountId}" \
					--header "Authorization: Bearer ${token}" \
					--header "Content-Type: application/json" \
					--data-raw '{
					"clientId": "'"${clientId}"'",
					"clientSecret": "'"${clientSecret}"'",
					"tenantId": "'"${tenantId}"'",
					"subscriptionId": "'"${subscriptionId}"'"
					}'`
		statusCode=`echo $req | jq -r ".response.status.code"`
		echo $req
		if [[ $statusCode == 200 ]]; then
			log_info "Spot Azure subscription connected successfully" & sleep 1
			jq <<< $req
			break
		fi

		echo "Failure! Retrying in $timeout.." 1>&2
    	sleep $timeout
		((attempts=attempts+1))
		timeout=$(( timeout * 2 ))

	done

}

function connectAzureAccount {
	# Get valid account id
	while true; do 
		read -p "Please enter valid accountId that matches the regex of ^\s*(act-[^\W_]{8})\s*$:    " spotinstAccountId
		if [[ "$spotinstAccountId" =~ ^\s*(act-[^\W_]{8})\s*$ ]]; then
			break
		fi
	done

	read -p "Please enter your account token: " accountToken
	log_info_sleep "Start creating subscription for accountId: $spotinstAccountId"
	connectSubscription $spotinstAccountId $accountToken

}

function assignRole {
	local REQUEST_SUCCESS_CRITERIA="principalId"
	local CREATION_SUCCEEDED=0
	for i in {1..20}; do
		application_id=$1
		role_name=$2
		request=`az role assignment create --assignee $application_id --role $role_name`
		case "$request" in 
	  		*"$REQUEST_SUCCESS_CRITERIA"*) log_info "Successfully assigned IAM Role to Spot Azure Application"; CREATION_SUCCEEDED=1; break;;
	  		* ) log_error "Failed at $i attempt, retrying to assign role to application";;
		esac
	done

	if [[ $CREATION_SUCCEEDED -eq 0 ]]; then
		log_error "Couldn't assign role.. exiting the process"
		exit 1
	fi

}

function handle {
	azure_list_accounts=`az account list -o json`
	log_info "These are the following available Azure accounts linked to your user, please choose one to connect to spot"
	echo $azure_list_accounts | jq ".[].name" | tr -d '"'
	echo -e "Which account (name) would you like to connect to Spot platform?"
	read -r account_to_connect
	echo -e "The command requires new registration creation in Azure Active Directory/App registration."

	read -p "Continue (y/n)? or submit your application_id if already exists.. Choice: " choice

	application_id=""

	case "$choice" in 
	  y|Y ) echo "yes"; createAppRegistration; application_id=$(getAppId);;
	  n|N ) echo "no";;
	  *"-"*) echo "Continuing with given application_id: $choice"; application_id="$choice";;
	  * ) echo "Invalid, please run again."; exit 0;;
	esac

	log_info "appId : $application_id"

    newApplicationExpirationDate=$(getDate)

    log_info "Resetting application to allow traffic from spot"
	secret_details=`az ad app credential reset --id $application_id --end-date $newApplicationExpirationDate`
	echo $secret_details > $SECRETS_STORE

	log_info "Application $appId has a token endDate set for $newApplicationExpirationDate"
	log_info "Start creating custom role..." && sleep 2

	read -p "Please pick a name for the Spot for Azure IAM Role: " iam_role_name

	curl -X GET https://spotinst-public.s3.amazonaws.com/assets/azure/custom_role_file.json > $POLICY_FILE_NAME
	# echo $spotAzureCustomRolePermissions | jq '. + {"Name": "$chosenIamRoleName"}'

	subscriptionId=`echo $azure_list_accounts | jq -r --arg account "$account_to_connect" '.[] | select(.name==$account).id' | tr -d '"'`
	# sed -e "s/\${roleName}/$chosenIamRoleName/" -e "s/\${subscriptionId}/$subscriptionId/"` $spotAzureCustomRolePermissions
	# echo $spotAzureCustomRolePermissions

	policyData=`cat $POLICY_FILE_NAME | jq '.properties'`
	echo $policyData > $POLICY_FILE_NAME

	# fix file according to Azure limits
	searchAndReplace "subscriptionId" $subscriptionId $POLICY_FILE_NAME
	searchAndReplace "customRoleName" $iam_role_name $POLICY_FILE_NAME
	cat $POLICY_FILE_NAME | jq --arg roleName "$iam_role_name" '. + {Name: $roleName}' > $POLICY_FILE_NAME_TEMP
	cp $POLICY_FILE_NAME_TEMP $POLICY_FILE_NAME

	log_info "Start creating IAM Role..."

	spot_azure_created_role=`az role definition create --role-definition $POLICY_FILE_NAME`

	log_info "Assigning role to service principals" & sleep 10
		
	# create SP for app
	service_principal_details=`az ad sp create --id $application_id`
	service_principal_dp=`echo $service_principal_details | jq -r '.displayName'`

	assignRole $application_id $iam_role_name

	echo $azure_list_accounts | jq -r --arg account "$account_to_connect" '.[] | select(.name==$account)' > $ACCOUNTS_STORE

	connectAzureAccount

	log_info "Finished"

}

function main {
  validate
  handle
  cleanup
}

main
