_ali_v3_rpc_invoke() {
    # Script to call Alibaba Cloud API v3
    #
    # Required environment variables:
    #   Ali_Key     - Your Alibaba Cloud Access Key ID
    #   Ali_Secret  - Your Alibaba Cloud Access Key Secret
    #
    # Example usage:
    #   export Ali_Key="your_access_key_id"
    #   export Ali_Secret="your_access_key_secret"
    #   _ali_v3_rpc_invoke "POST" "cas.aliyuncs.com" "UploadUserCertificate" "2020-04-07" --body '{"Name":"cert-upload-test","Cert":"'"$(get_cert)"'","Key":"'"$(get_key)"'"}'
    #
    # Notice:
    #   need jq、uuidgen command installed

    # URL encode
    _url_encode() {
        local string="${1}"
        local strlen=${#string}
        local encoded=""
        local pos c o

        for (( pos=0 ; pos<strlen ; pos++ )); do
            c=${string:$pos:1}
            case "$c" in
                [-_.~a-zA-Z0-9] ) o="${c}" ;;
                * )               printf -v o '%%%02X' "'$c"
            esac
            encoded+="${o}"
        done
        echo "${encoded}"
    }

    local httpMethod="$(echo "$1" | tr '[:lower:]' '[:upper:]')"
    local host="$2"
    local action="$3"
    local version="$4"
    shift 4

    # load AccessKey/Secret
    Ali_Key="${Ali_Key:-$(_readaccountconf_mutable Ali_Key 2>/dev/null)}"
    Ali_Secret="${Ali_Secret:-$(_readaccountconf_mutable Ali_Secret 2>/dev/null)}"
    if [ -z "$Ali_Key" ] || [ -z "$Ali_Secret" ]; then
        _err "You don't specify aliyun api key or secret yet."
        return 1
    fi

    _saveaccountconf_mutable Ali_Key "$Ali_Key"
    _saveaccountconf_mutable Ali_Secret "$Ali_Secret"

    local canonicalURI="/"
    local content_type="application/json; charset=utf-8"

    if [ "$httpMethod" = "GET" ]; then
        # parse GET-style --key [value] or --flag
        while [ $# -gt 0 ]; do
            case "$1" in
                --*)
                    local key="${1#--}"; shift
                    local val=""
                    if [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; then
                        val="$1"; shift
                    fi
                    if [ -n "$val" ]; then
                        params_list+=("${key}=$(_url_encode "$val")")
                    else
                        # flag param (no value)
                        params_list+=("$(_url_encode "$key")")
                    fi
                    ;;
                *)
                    _err "_ali_v3_rpc_invoke: unknown parameter '$1'"
                    return 2
                    ;;
            esac
        done
        if [ ${#params_list[@]} -gt 0 ]; then
            # sort and join with &
            canonicalQueryString=$(printf "%s\n" "${params_list[@]}" | LC_ALL=C sort | paste -sd'&' -)
        fi
    else
        # POST/PUT with JSON body
        local body=""
        local body_json="{}"
        while [ $# -gt 0 ]; do
            case "$1" in
                --*)
                    local key="${1:2}"
                    local val="$2"
                    shift 2
                    body_json=$(printf "%s" "$body_json" | jq --arg k "$key" --arg v "$val" '. + {($k): $v}')
                    ;;
                *)
                    _err "_ali_v3_rpc_invoke: unknown parameter '$1'"
                    return 2
                    ;;
            esac
        done
        body="$body_json"
    fi

    _info "_ali_v3_rpc_invoke function request payload prepared"

    # UTC time & nonce
    local utc_date nonce
    utc_date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    nonce=$(uuidgen | sed 's/-//g')

    # hash payload (empty string if GET)
    local hashedRequestPayload
    hashedRequestPayload=$(printf "%s" "$body" | openssl dgst -sha256 | awk '{print $2}')

    # Headers
    local headers_arr=(
        "host:${host}"
        "x-acs-action:${action}"
        "x-acs-version:${version}"
        "x-acs-date:${utc_date}"
        "x-acs-signature-nonce:${nonce}"
        "content-type:${content_type}"
        "x-acs-content-sha256:${hashedRequestPayload}"
    )

    # Canonical request
    local canonicalHeaders signedHeaders canonicalRequest
    canonicalHeaders=$(printf "%s\n" "${headers_arr[@]}" | awk -F: '{print tolower($1) ":" $2}' | sort)
    signedHeaders=$(printf "%s\n" "${headers_arr[@]}" | awk -F: '{print tolower($1)}' | sort | paste -sd';' -)
    canonicalRequest="${httpMethod}\n${canonicalURI}\n${canonicalQueryString}\n${canonicalHeaders}\n\n${signedHeaders}\n${hashedRequestPayload}"
    local hashedCanonicalRequest
    hashedCanonicalRequest=$(printf "%s" "$canonicalRequest" | openssl sha256 -hex | awk '{print $2}')

    # signature
    local algorithm="ACS3-HMAC-SHA256"
    local stringToSign="${algorithm}\n${hashedCanonicalRequest}"
    local signature
    signature=$(printf "%s" "$stringToSign" | openssl dgst -sha256 -hmac "${Ali_Secret}" | awk '{print $2}')

    local authorization="${algorithm} Credential=${Ali_Key},SignedHeaders=${signedHeaders},Signature=${signature}"

    # build curl command
    local url="https://${host}${canonicalURI}"
    [ -n "$canonicalQueryString" ] && url="${url}?${canonicalQueryString}"

    local curl_headers=()
    for h in "${headers_arr[@]}"; do curl_headers+=("-H" "$h"); done
    curl_headers+=("-H" "Authorization: $authorization")

    if [ "$httpMethod" = "GET" ]; then
        curl -sS -X "$httpMethod" "${curl_headers[@]}" "$url"
    else
        curl -sS -X "$httpMethod" "${curl_headers[@]}" -d "$body" "$url"
    fi
}