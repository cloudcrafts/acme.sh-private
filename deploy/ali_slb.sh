#!/usr/bin/bash
#!/usr/bin/env sh
# Script to create certificate to Alibaba Cloud SLB
# 
# This deployment required following variables
# export Ali_Region="cn-hangzhou"
# export Ali_Key=""
# export Ali_Secret=""
# export DEPLOY_ALI_SLB_ID="lb-xxxxx"
# export DEPLOY_ALI_SLB_PORT="443"

ali_slb_deploy() {
    _cdomain="$1"
    _ckey="$2"
    _ccert="$3"
    _cca="$4"
    _cfullchain="$5"
    _getdeployconf Ali_Region
    if [ -z "$Ali_Region" ]; then
        Ali_Region="cn-hangzhou"
    fi
    _savedeployconf Ali_Region "$Ali_Region"

    if [[ $Ali_Region == "cn-hangzhou" ]]; then
        Ali_API="slb.aliyuncs.com"
    else
        Ali_API="slb.${Ali_Region}.aliyuncs.com"
    fi
    echo "Ali_Region: $Ali_Region"
    echo "Ali_API: $Ali_API"
    _random_name=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)

    _debug _cdomain "$_cdomain"
    _debug _ckey "$_ckey"
    _debug _ccert "$_ccert"
    _debug _cca "$_cca"
    _debug _cfullchain "$_cfullchain"

    _ret=$(_api_rpc "$Ali_API" "2014-05-15" "UploadServerCertificate" --RegionId "$Ali_Region" --ServerCertificateName "$_cdomain-$_random_name" --PrivateKey "get_key()" --ServerCertificate "get_cert()")
    if [ "$?" != "0" ]; then
        _err "Failed to upload certificate to Alibaba Cloud SLB"
        _err "$_ret"
        return 1
    fi
    _debug "$_ret"
    _cert_id=$(echo "$_ret" | _egrep_o "\"ServerCertificateId\":\"[^\"]*\"" | cut -d':' -f2 | tr -d '"')
    _debug "Certificate ID: $_cert_id"
    if [ -z "$_cert_id" ]; then
        _err "Failed to upload certificate to Alibaba Cloud SLB"
        return 1
    fi

    _getdeployconf DEPLOY_ALI_SLB_ID
    if [ -z "$DEPLOY_ALI_SLB_ID" ]; then
        _err "You don't specify a load balance id yet."
        return 1
    fi
    _savedeployconf DEPLOY_ALI_SLB_ID "$DEPLOY_ALI_SLB_ID"

   _getdeployconf DEPLOY_ALI_SLB_PORT
    if [ -z "$DEPLOY_ALI_SLB_PORT" ]; then
        DEPLOY_ALI_SLB_PORT="443"
    fi
    _savedeployconf DEPLOY_ALI_SLB_PORT "$DEPLOY_ALI_SLB_PORT"

    # query old certificate id

    _ret=$(_api_rpc "$Ali_API" "2014-05-15" "DescribeLoadBalancerHTTPSListenerAttribute" --RegionId "$Ali_Region" --LoadBalancerId "$DEPLOY_ALI_SLB_ID" --ListenerPort "$DEPLOY_ALI_SLB_PORT")

    if [ "$?" != "0" ]; then
        _err "Failed to query certificate from Alibaba Cloud SLB"
        return 1
    fi

    _old_cert_id=$(echo "$_ret" | _egrep_o "\"ServerCertificateId\":\"[^\"]*\"" | cut -d':' -f2 | tr -d '"')

    # _loadbance_ids example: "lb-xxxxx lb-xxx"

    _api_rpc "$Ali_API" "2014-05-15" "SetLoadBalancerHTTPSListenerAttribute" --RegionId "$Ali_Region" --LoadBalancerId "$DEPLOY_ALI_SLB_ID" --ListenerPort "$DEPLOY_ALI_SLB_PORT" --ServerCertificateId "$_cert_id"

    if [ "$?" != "0" ]; then
        _err "Failed to deploy certificate to Alibaba Cloud SLB"
        return 1
    fi

    # delete old certificate
    if [ -n "$_old_cert_id" ]; then
        _api_rpc "$Ali_API" "2014-05-15" "DeleteServerCertificate" --RegionId "$Ali_Region" --ServerCertificateId "$_old_cert_id"
        if [ "$?" != "0" ]; then
            _err "Failed to delete old certificate from Alibaba Cloud SLB"
            return 1
        fi
    fi
    _info "Certificate has been deployed to Alibaba Cloud SLB"
    _ali_cert_manage "$_cdomain" "$_cfullchain" "$_ckey"
}

_api_rpc() {

    # get key and secret
    Ali_Key="${Ali_Key:-$(_readaccountconf_mutable Ali_Key)}"
    Ali_Secret="${Ali_Secret:-$(_readaccountconf_mutable Ali_Secret)}"
    if [ -z "$Ali_Key" ] || [ -z "$Ali_Secret" ]; then
        Ali_Key=""
        Ali_Secret=""
        _err "You don't specify aliyun api key and secret yet."
        return 1
    fi

    _saveaccountconf_mutable Ali_Key "$Ali_Key"
    _saveaccountconf_mutable Ali_Secret "$Ali_Secret"

    local -r _AliAccessKeyId=$Ali_Key _AliAccessKeySecret=$Ali_Secret

    local _http_host=$1
    local _api_version=$2
    local _api_action=$3
    shift 3

    local _query_str _signature_nonce _timestamp
    _signature_nonce=$(_urlencode "$(_signature_nonce)")
    _timestamp=$(_urlencode "$(_timestamp_rpc)")
    _query_str="AccessKeyId=$_AliAccessKeyId&Action=$_api_action&Format=JSON&SignatureMethod=HMAC-SHA1&SignatureVersion=1.0&SignatureNonce=$_signature_nonce&Timestamp=$_timestamp&Version=$_api_version&"
    # 解析其余参数
    local _key _value
    while [[ $# -ne 0 ]]
    do
        case $1 in
            --*)
                if [[ $# -le 1 ]]; then
                    echo "_api_rpc: '$1' has no value" >&2
                    return 2
                fi
                _key=${1:2}
                _value=$2
                [[ $_value =~ .+\(\)$ && $(type -t "${_value:0:-2}") == "function" ]] && _value=$(${_value:0:-2})
                _value=$(_urlencode "$_value")
                _query_str+="$_key=$_value&"
                shift 2
                ;;
            *)
                echo "_api_rpc: '$1' is unknown parameter" >&2
                return 2
                ;;
        esac
    done

    local _signature
    _signature=$(_signature_rpc "GET" "${_query_str:0:-1}")
    _query_str+="Signature=$(_urlencode "$_signature")"
    local _http_url="https://$_http_host/?$_query_str"
    _get "$_http_url"
}


get_cert() {
    sed -e "/^$/d" "$_cfullchain"
}
get_key() {
    cat "$_ckey"
}

_timestamp_rpc() {
    # ISO8601 UTC
    date -u -Iseconds
}

_signature_nonce() {
    local nonce=""
    if [[ -f /proc/sys/kernel/random/uuid ]]; then
        nonce=$(</proc/sys/kernel/random/uuid)
    else
        nonce=$(date +%s%N)
    fi
    echo "$RANDOM${nonce//-/}$RANDOM"
}

_signature_rpc() {
    if [[ ${LC_ALL:-X} != C ]]; then
        LC_ALL=C _signature_rpc "$@"
        return $?
    fi

    local -u _http_method=$1
    local _str=$2 _query_str _sign_str
    local _newline="
"
    _str=$(sort <<< "${_str//"&"/"$_newline"}")
    _query_str=${_str//"$_newline"/"&"}
    _sign_str="$_http_method&$(_urlencode "/")&$(_urlencode "$_query_str")"
    printf "%s" "$_sign_str" | openssl dgst -sha1 -hmac "$_AliAccessKeySecret&" -binary | openssl base64 -e
}


_urlencode() {
    if [[ ${LC_ALL:-X} != C ]]; then
        LC_ALL=C _urlencode "$@"
        return $?
    fi
    local char hex string=$1
    while [[ -n $string ]]; do
        char=${string:0:1}
        string=${string:1}
        case $char in
            [-._~0-9A-Za-z]) printf %c "$char";;
            *)
                if [[ ALIYUN_SDK_RUN_ON_MUSL_LIBC -eq 0 ]]; then
                    printf %%%02X "'$char"
                else
                    # Hack musl libc for not ASCII chars (incomplete test)
                    hex=$(printf %02X "'$char")
                    printf %%%s "${hex:${#hex}-2}"
                fi
            ;;
        esac
    done
    echo
}
