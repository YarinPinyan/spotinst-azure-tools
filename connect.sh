#!/bin/bash

# Log levels, enums and constants
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
readonly RESOURCE_FILE="/tmp/spot_azure_created_resources.json"
readonly RESOURCE_FILE_TEMP="/tmp/spot_azure_created_resources_temp.json"
readonly NO_SIGNAL_SUCCESS="NO_SIGNAL_SUCCESS"
readonly EXISTING_ROLE_ASSIGNMENT_REFERENCE_ON_DELETION="There are existing role assignments referencing"
readonly SIGNAL_APP_REGISTRATION_CREATION_ENUM="SIGNAL_APP_REGISTRATION_CREATION"
readonly SIGNAL_IAM_ROLE_CREATION_ENUM="SIGNAL_IAM_ROLE_CREATION"
readonly SIGNAL_ROLE_ASSIGNMENT_SUCCESS_ENUM="SIGNAL_ROLE_ASSIGNMENT_SUCCESS"
readonly SIGNAL_SPOT_AZURE_SUBSCRIPTION_CONNECTED_SUCCESS_ENUM="SIGNAL_SPOT_AZURE_SUBSCRIPTION_CONNECTED_SUCCESS"
readonly SIGNAL_SERVICE_PRINCIPAL_CREATION_ENUM="SIGNAL_SERVICE_PRINCIPAL_CREATION"
readonly SIGNAL_APPLICATION_SECRET_RESET_ENUM="SIGNAL_APPLICATION_SECRET_RESET"
export SIGNAL_APP_REGISTRATION_CREATION=0
export SIGNAL_APPLICATION_SECRET_RESET=0
export SIGNAL_IAM_ROLE_CREATION=0
export SIGNAL_ROLE_ASSIGNMENT_SUCCESS=0
export SIGNAL_SPOT_AZURE_SUBSCRIPTION_CONNECTED_SUCCESS=0
export SIGNAL_SERVICE_PRINCIPAL_CREATION=0

function init {
	echo "{}" > $RESOURCE_FILE
	echo "{}" > $RESOURCE_FILE_TEMP
}

function cleanup {
	log_debug "Cleaning up resources that have been used under /tmp dir..."
	rm $POLICY_FILE_NAME_TEMP $POLICY_FILE_NAME $ACCOUNTS_STORE $SECRETS_STORE $TEMP_APP_DETAILS_LOCATION $RESOURCE_FILE_TEMP $RESOURCE_FILE
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

function deleteAppRegistration {
	# receives application id as $1
	app_id=`echo $i | jq -r '.resourceId'`
	execute_with_backoff "$NO_SIGNAL_SUCCESS" "az" "ad" "app" "delete" "--id" "$app_id"
}

function deleteIamRole {
	# receives iam role id as $1
	iam_role=`echo $1 | jq -r '.resourceId'`
	execute_with_backoff "$NO_SIGNAL_SUCCESS" "az" "ad" "app" "delete" "--id" "$app_id"
}

function deleteRoleAssignment {
	# receives role assignment id as $1
	iam_role=`echo $1 | jq -r '.resourceId'`
	execute_with_backoff "$NO_SIGNAL_SUCCESS" "az" "role" "assignment" "delete" "--role" "$iam_role"
}

function deleteServicePrincipals {
	# receives service principal id as $1
	service_principals=`echo $1 | jq -r '.resourceId'`
	execute_with_backoff "$NO_SIGNAL_SUCCESS" "az" "ad" "sp" "credential" "delete" "--id" "$service_principals"
}

function cleanupCreatedResources {

	read -p "Start deleting resources..."
	jq -c '.[]' $RESOURCE_FILE | while read i; do
		read -p "Waitttttt"
		case "$i" in
			*"appRegistration"* ) deleteAppRegistration $i ;;
			*"iamRole"* ) deleteIamRole $i ;;
			*"servicePrincipals"* ) deleteServicePrincipals $i ;;
			*"roleAssignment"* ) deleteRoleAssignment $i ;;
			*"spotAccount"* ) ;;
		esac
	done
}

KeyboardInterrupt() {
	while true; do
		read -p "Would you like to cleann the created resources before the failure?" choice
		case "$choice" in 
		  y|Y ) echo "yes"; cleanupCreatedResources; break;;
		  n|N ) echo "no"; break;;
		  * ) echo "Invalid, please run again.";;
		esac
	done

	kill $PID
	echo "Please make sure you continued from where you've stopped"
	exit
}

trap KeyboardInterrupt SIGINT

function azureCliNotSupported() { log_error "Azure CLI is not installed in your OS. In order to make this script work, please install it and then proceed"; exit 0; }

function jqNotSupported () {  log_error "jq command which is used in the script to parse azure data is not available in your OS, hence the script couldn't be executed.\n\tPlease download jq and then proceed."; exit 0; }

function searchAndReplace () {
	local search=$1
	local replace=$2
	local filename=$3

	echo "$1 $2 $3"
	[ "$(uname)" = Linux ] && sed -i "s/{$search}/$replace/g" $POLICY_FILE_NAME || sed -i "" "s/{$search}/$replace/g" $POLICY_FILE_NAME
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
	  		*"$APP_CREATION_SIGNAL"*) echo "Application Created Successfully"; SIGNAL_APP_REGISTRATION_CREATION=1; echo $registeredApplicationDetails > $TEMP_APP_DETAILS_LOCATION; parseAzureFile $TEMP_APP_DETAILS_LOCATION; saveCreatedResourceToJsonObject "appRegistration" $(getAppId); break;;
	  		* ) echo "Invalid, please run again.";;
		esac
	done
}

function getAppId {
	local appId=`cat $TEMP_APP_DETAILS_LOCATION | jq -r ".appId"`
	echo $appId

}

function saveCreatedResourceToJsonObject {
	local resource_type=$1
	local resource_id=$2

	local TEMP_VAR="TEMP_SPOT_AZURE_APP_RESOURCE_LOCATION"
	local file_data=`cat $RESOURCE_FILE`
	echo $file_data | jq --arg resourceType $resource_type --arg resourceId $resource_id '. + {TEMP_SPOT_AZURE_APP_RESOURCE_LOCATION: {resourceId: $resourceId , resourceType: $resourceType }}' | sed "s/$TEMP_VAR/$resource_type/g" > $RESOURCE_FILE_TEMP && cp $RESOURCE_FILE_TEMP $RESOURCE_FILE && echo "" > $RESOURCE_FILE_TEMP
}

function validateCreatedRole {
	local ROLE_CREATION_SIGNAL="notActions"
	local attempts=0

	while true; do
		spot_azure_created_role=`az role definition create --role-definition $POLICY_FILE_NAME --subscription "$account_to_connect"`

		case "$spot_azure_created_role" in 
	  		*"$APP_CREATION_SIGNAL"*) echo "Role Created Successfully"; SIGNAL_IAM_ROLE_CREATION=1; break;;
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
			SIGNAL_SPOT_AZURE_SUBSCRIPTION_CONNECTED_SUCCESS=1
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
	  		*"$REQUEST_SUCCESS_CRITERIA"*) log_info "Successfully assigned IAM Role to Spot Azure Application"; SIGNAL_ROLE_ASSIGNMENT_SUCCESS=1; saveCreatedResourceToJsonObject "roleAssignment" "$role_name"; break;;
	  		* ) log_error "Failed at $i attempt, retrying to assign role to application";;
		esac
	done

}

function execute_with_backoff {
	local MAX_ATTEMPTS=5
	local attempts=0
	local timeout=1
	local IS_REQUEST_SUCCEEDED=0
	local SIGNAL_CRITERIA_SUCCESS_OUTPUT=$1
	shift
	local cmds="$@"

	log_info "Command to execute: $cmds"

	while [[ $attempts < $MAX_ATTEMPTS ]]; do
		{ req="$( { special_execute $cmds; } 2>&1 1>&3 3>&- )"; } 3>&1;

		if [[ $(echo $req | tr '[:upper:]' '[:lower:]') != *"error"* ]]; then
			log_info "Successfully executed command. request output: $req"
			IS_REQUEST_SUCCEEDED=1
			if [[ "$SIGNAL_CRITERIA_SUCCESS_OUTPUT" != "$NO_SIGNAL_SUCCESS" ]]; then
				echo "in cond"
				 eval $SIGNAL_CRITERIA_SUCCESS_OUTPUT=1
			fi
			break
		fi

    	sleep $timeout
		((attempts=attempts+1))
		timeout=$(( timeout * 2 ))
	done

	if [[ $IS_REQUEST_SUCCEEDED -eq 0 ]]; then
		log_error "Failed to execute command: $cmds"
	fi


}
function special_execute() { set -x; "$@"; set +x; }

function createIamRole {
	local iam_role_name=$1
	local account_to_connect=$2

	curl -X GET https://spotinst-public.s3.amazonaws.com/assets/azure/custom_role_file.json > $POLICY_FILE_NAME

	subscriptionId=`cat $ACCOUNTS_STORE | jq -r --arg account "$account_to_connect" '.[] | select(.name==$account).id' | tr -d '"'`

	policyData=`cat $POLICY_FILE_NAME | jq '.properties'`
	echo $policyData > $POLICY_FILE_NAME

	# fix file according to Azure limits
	searchAndReplace "subscriptionId" $subscriptionId $POLICY_FILE_NAME
	searchAndReplace "customRoleName" $iam_role_name $POLICY_FILE_NAME
	cat $POLICY_FILE_NAME | jq --arg roleName "$iam_role_name" '. + {Name: $roleName}' > $POLICY_FILE_NAME_TEMP
	cp $POLICY_FILE_NAME_TEMP $POLICY_FILE_NAME
	echo "" > $ACCOUNTS_STORE

	log_info "Start creating IAM Role..."

	execute_with_backoff "$SIGNAL_IAM_ROLE_CREATION_ENUM" "az" "role" "definition" "create" "--role-definition" "$POLICY_FILE_NAME"
}

function createServicePrincipals {
	local application_id=$1
	log_info "Assigning role to service principals" & sleep 10
	execute_with_backoff "$SIGNAL_SERVICE_PRINCIPAL_CREATION_ENUM" "az" "ad" "sp" "create" "--id" "$application_id"
}

function validateCreatedResource {
	if [[ ! -z $1 ]]; then
		echo "yes"
	fi
}

function resetSecrets {
	local application_id=$1
    newApplicationExpirationDate=$(getDate)
    log_info "Resetting application to allow traffic from spot"
	secret_details=`az ad app credential reset --id $application_id --end-date $newApplicationExpirationDate`
	echo $secret_details > $SECRETS_STORE
	if [[ ! -z $(cat $SECRETS_STORE)  ]]; then
		SIGNAL_APPLICATION_SECRET_RESET=1
	fi

	# execute_with_backoff "$SIGNAL_APPLICATION_SECRET_RESET_ENUM" "az" "ad" "app" "credential" "reset" "--id" "$application_id" "--end-date" "$newApplicationExpirationDate > $SECRETS_STORE && sed -i '' '/^{/,/^}/!d' $SECRETS_STORE && sleep 2 && cat $SECRETS_STORE"
}

function handle {
	azure_list_accounts=`az account list -o json`
	log_info "These are the following available Azure accounts linked to your user, please choose one to connect to spot"
	echo $azure_list_accounts | jq ".[].name" | tr -d '"'
	echo -e "Which account (name) would you like to connect to Spot platform?"
	read -r account_to_connect
	echo -e "The command requires new registration creation in Azure Active Directory/App registration.\n"

	read -p "Continue (y/n)? or submit your application_id if already exists.. Choice: " choice

	application_id=""

	case "$choice" in 
	  y|Y ) echo "yes"; createAppRegistration; application_id=$(getAppId);;
	  n|N ) echo "no";;
	  *"-"*) echo "Continuing with given application_id: $choice"; application_id="$choice";;
	  * ) echo "Invalid, please run again."; exit 0;;
	esac

	log_info "appId : $application_id"

	if [[ $SIGNAL_APP_REGISTRATION_CREATION -eq 1 ]]; then
		log_info "Application $application_id created successfully"
		resetSecrets $application_id
		if [[ $SIGNAL_APPLICATION_SECRET_RESET -eq 1 ]]; then
			read -p "Please pick a name for the Spot for Azure IAM Role: " iam_role_name
			echo $azure_list_accounts > $ACCOUNTS_STORE
			createIamRole "$iam_role_name" "$account_to_connect"
			echo $SIGNAL_IAM_ROLE_CREATION
			if [[ $SIGNAL_IAM_ROLE_CREATION -eq 1 ]]; then
				saveCreatedResourceToJsonObject "iamRole" "$iam_role_name" 
				log_info "Start creating service_principals\n"
				service_principal_details=`az ad sp create --id $application_id`
				service_principal_dp=`echo $service_principal_details | jq -r '.displayName'`
				if [[ ! -z $(validateCreatedResource $service_principal_dp) ]]; then
					eval $SIGNAL_SERVICE_PRINCIPAL_CREATION_ENUM=1
					if [[ $SIGNAL_SERVICE_PRINCIPAL_CREATION -eq 1 ]]; then
						saveCreatedResourceToJsonObject "servicePrincipals" "$service_principal_dp"
						assignRole $application_id $iam_role_name
						if [[ $SIGNAL_ROLE_ASSIGNMENT_SUCCESS -eq 1 ]]; then
							# store account details to connect spot account
							echo $azure_list_accounts | jq -r --arg account "$account_to_connect" '.[] | select(.name==$account)' > $ACCOUNTS_STORE
							connectAzureAccount
							if [[ $SIGNAL_SPOT_AZURE_SUBSCRIPTION_CONNECTED_SUCCESS -eq 1 ]]; then
								log_info "Successfully connected subscription to spot account."
							fi
						fi
					fi
				fi
			fi
		fi
	fi


}

function main {
  init
  validate
  handle
  cleanup
}

main
