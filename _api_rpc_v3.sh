. acme.sh
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
    #   _ali_v3_rpc_invoke "POST" "cas.aliyuncs.com" "UploadUserCertificate" "2020-04-07" --Name cert-upload-test --Cert "$cert" --Key "$key"
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
            canonicalQueryString=$(printf "%s\n" "${params_list[@]}" | LC_ALL=C sort -t= -k1,1 | paste -sd'&' -)
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
    canonicalHeaders=$(for h in "${headers_arr[@]}"; do
        key="${h%%:*}"
        val="${h#*:}"
        echo "${key,,}:${val}"
    done | sort)

    signedHeaders=$(for h in "${headers_arr[@]}"; do
        key="${h%%:*}"
        echo "${key,,}"
    done | sort | paste -sd';' -)
    canonicalRequest="${httpMethod}\n${canonicalURI}\n${canonicalQueryString}\n${canonicalHeaders}\n\n${signedHeaders}\n${hashedRequestPayload}"
    local hashedCanonicalRequest
    str=$(echo "$canonicalRequest" | sed 's/%/%%/g')
    hashedCanonicalRequest=$(printf "$str" | openssl sha256 -hex | awk '{print $2}')

    # signature
    local algorithm="ACS3-HMAC-SHA256"
    local stringToSign="${algorithm}\n${hashedCanonicalRequest}"
    local signature
    signature=$(printf "$stringToSign" | openssl dgst -sha256 -hmac "${Ali_Secret}" | awk '{print $2}')

    local authorization="${algorithm} Credential=${Ali_Key},SignedHeaders=${signedHeaders},Signature=${signature}"

    # build curl command
    local url="https://${host}${canonicalURI}"
    [ -n "$canonicalQueryString" ] && url="${url}?${canonicalQueryString}"

    local curl_headers=()
    for h in "${headers_arr[@]}"; do curl_headers+=("-H" "$h"); done
    curl_headers+=("-H" "Authorization: $authorization")

    if [ "$httpMethod" = "GET" ]; then
        curl -sS -X "$httpMethod"  "$url" "${curl_headers[@]}"
    else
        curl -sS -X "$httpMethod"  "$url" "${curl_headers[@]}" -d "$body"
    fi
}
cert="-----BEGIN CERTIFICATE-----
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
UirkwA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIG1TCCBL2gAwIBAgIQbFWr29AHksedBwzYEZ7WvzANBgkqhkiG9w0BAQwFADCB
iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl
cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV
BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjAw
MTMwMDAwMDAwWhcNMzAwMTI5MjM1OTU5WjBLMQswCQYDVQQGEwJBVDEQMA4GA1UE
ChMHWmVyb1NTTDEqMCgGA1UEAxMhWmVyb1NTTCBSU0EgRG9tYWluIFNlY3VyZSBT
aXRlIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAhmlzfqO1Mdgj
4W3dpBPTVBX1AuvcAyG1fl0dUnw/MeueCWzRWTheZ35LVo91kLI3DDVaZKW+TBAs
JBjEbYmMwcWSTWYCg5334SF0+ctDAsFxsX+rTDh9kSrG/4mp6OShubLaEIUJiZo4
t873TuSd0Wj5DWt3DtpAG8T35l/v+xrN8ub8PSSoX5Vkgw+jWf4KQtNvUFLDq8mF
WhUnPL6jHAADXpvs4lTNYwOtx9yQtbpxwSt7QJY1+ICrmRJB6BuKRt/jfDJF9Jsc
RQVlHIxQdKAJl7oaVnXgDkqtk2qddd3kCDXd74gv813G91z7CjsGyJ93oJIlNS3U
gFbD6V54JMgZ3rSmotYbz98oZxX7MKbtCm1aJ/q+hTv2YK1yMxrnfcieKmOYBbFD
hnW5O6RMA703dBK92j6XRN2EttLkQuujZgy+jXRKtaWMIlkNkWJmOiHmErQngHvt
iNkIcjJumq1ddFX4iaTI40a6zgvIBtxFeDs2RfcaH73er7ctNUUqgQT5rFgJhMmF
x76rQgB5OZUkodb5k2ex7P+Gu4J86bS15094UuYcV09hVeknmTh5Ex9CBKipLS2W
2wKBakf+aVYnNCU6S0nASqt2xrZpGC1v7v6DhuepyyJtn3qSV2PoBiU5Sql+aARp
wUibQMGm44gjyNDqDlVp+ShLQlUH9x8CAwEAAaOCAXUwggFxMB8GA1UdIwQYMBaA
FFN5v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBTI2XhootkZaNU9ct5fCj7c
tYaGpjAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHSUE
FjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwIgYDVR0gBBswGTANBgsrBgEEAbIxAQIC
TjAIBgZngQwBAgEwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51c2VydHJ1
c3QuY29tL1VTRVJUcnVzdFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMHYG
CCsGAQUFBwEBBGowaDA/BggrBgEFBQcwAoYzaHR0cDovL2NydC51c2VydHJ1c3Qu
Y29tL1VTRVJUcnVzdFJTQUFkZFRydXN0Q0EuY3J0MCUGCCsGAQUFBzABhhlodHRw
Oi8vb2NzcC51c2VydHJ1c3QuY29tMA0GCSqGSIb3DQEBDAUAA4ICAQAVDwoIzQDV
ercT0eYqZjBNJ8VNWwVFlQOtZERqn5iWnEVaLZZdzxlbvz2Fx0ExUNuUEgYkIVM4
YocKkCQ7hO5noicoq/DrEYH5IuNcuW1I8JJZ9DLuB1fYvIHlZ2JG46iNbVKA3ygA
Ez86RvDQlt2C494qqPVItRjrz9YlJEGT0DrttyApq0YLFDzf+Z1pkMhh7c+7fXeJ
qmIhfJpduKc8HEQkYQQShen426S3H0JrIAbKcBCiyYFuOhfyvuwVCFDfFvrjADjd
4jX1uQXd161IyFRbm89s2Oj5oU1wDYz5sx+hoCuh6lSs+/uPuWomIq3y1GDFNafW
+LsHBU16lQo5Q2yh25laQsKRgyPmMpHJ98edm6y2sHUabASmRHxvGiuwwE25aDU0
2SAeepyImJ2CzB80YG7WxlynHqNhpE7xfC7PzQlLgmfEHdU+tHFeQazRQnrFkW2W
kqRGIq7cKRnyypvjPMkjeiV9lRdAM9fSJvsB3svUuu1coIG1xxI1yegoGM4r5QP4
RGIVvYaiI76C0djoSbQ/dkIUUXQuB8AL5jyH34g3BZaaXyvpmnV4ilppMXVAnAYG
ON51WhJ6W0xNdNJwzYASZYH+tmCWI+N60Gv2NNMGHwMZ7e9bXgzUCZH5FaBFDGR5
S9VWqHB73Q+OyIVvIbKYcSc2w/aSuFKGSA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFgTCCBGmgAwIBAgIQOXJEOvkit1HX02wQ3TE1lTANBgkqhkiG9w0BAQwFADB7
MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
VQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UE
AwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTE5MDMxMjAwMDAwMFoXDTI4
MTIzMTIzNTk1OVowgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5
MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBO
ZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0
aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgBJlFzYOw9sI
s9CsVw127c0n00ytUINh4qogTQktZAnczomfzD2p7PbPwdzx07HWezcoEStH2jnG
vDoZtF+mvX2do2NCtnbyqTsrkfjib9DsFiCQCT7i6HTJGLSR1GJk23+jBvGIGGqQ
Ijy8/hPwhxR79uQfjtTkUcYRZ0YIUcuGFFQ/vDP+fmyc/xadGL1RjjWmp2bIcmfb
IWax1Jt4A8BQOujM8Ny8nkz+rwWWNR9XWrf/zvk9tyy29lTdyOcSOk2uTIq3XJq0
tyA9yn8iNK5+O2hmAUTnAU5GU5szYPeUvlM3kHND8zLDU+/bqv50TmnHa4xgk97E
xwzf4TKuzJM7UXiVZ4vuPVb+DNBpDxsP8yUmazNt925H+nND5X4OpWaxKXwyhGNV
icQNwZNUMBkTrNN9N6frXTpsNVzbQdcS2qlJC9/YgIoJk2KOtWbPJYjNhLixP6Q5
D9kCnusSTJV882sFqV4Wg8y4Z+LoE53MW4LTTLPtW//e5XOsIzstAL81VXQJSdhJ
WBp/kjbmUZIO8yZ9HE0XvMnsQybQv0FfQKlERPSZ51eHnlAfV1SoPv10Yy+xUGUJ
5lhCLkMaTLTwJUdZ+gQek9QmRkpQgbLevni3/GcV4clXhB4PY9bpYrrWX1Uu6lzG
KAgEJTm4Diup8kyXHAc/DVL17e8vgg8CAwEAAaOB8jCB7zAfBgNVHSMEGDAWgBSg
EQojPpbxB+zirynvgqV/0DCktDAdBgNVHQ4EFgQUU3m/WqorSs9UgOHYm8Cd8rID
ZsswDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wEQYDVR0gBAowCDAG
BgRVHSAAMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29t
L0FBQUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggr
BgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUA
A4IBAQAYh1HcdCE9nIrgJ7cz0C7M7PDmy14R3iJvm3WOnnL+5Nb+qh+cli3vA0p+
rvSNb3I8QzvAP+u431yqqcau8vzY7qN7Q/aGNnwU4M309z/+3ri0ivCRlv79Q2R+
/czSAaF9ffgZGclCKxO/WIu6pKJmBHaIkU4MiRTOok3JMrO66BQavHHxW/BBC5gA
CiIDEOUMsfnNkjcZ7Tvx5Dq2+UUTJnWvu6rvP3t3O9LEApE9GQDTF1w52z97GA1F
zZOFli9d31kWTz9RvdVFGD/tSo7oBmF0Ixa1DVBzJ0RHfxBdiSprhTEUxOipakyA
vGp4z7h/jnZymQyd/teRCBaho1+V
-----END CERTIFICATE-----"
key="-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAqvZYHSotoZNzr6NgAB26nHs8MViBhAatzPoG6Y6aqQBnkhk9
QUY8LBBUfj4a+HMfG+yMlujsSvBZMjx+2jmO9tWQLuTIE0/9ndTjQLcB9cNrQwDk
o2oX4mBU+zIyzarRUojHRbrlIbOd5aRytYHpEUWjFalFgSScEbRY5MgQ1NQwXmnP
qWgQXn6FXLOBqUwBLNLHSEoNYuX2WB2wij2ylgu1W9qVa4c87sFzy1SzSelbNZm2
4/JvYM4KFOi6Lzn4T3L9M6bSgQFAcY4ywjG6ozMhCY69Yk36HTWiRG+7PsKliBtd
BYQkF8yELyNUsFM6wO3Zjo/e7ivUnbrZIO5TjQIDAQABAoIBAACsLxo6RWtaevze
Ey1yRdQsxfFZwZ9ahAoyPPRj8RF+JL+AkEBL/ZucxYBTpTkvVsLTh5VmaDDpSNM3
mrYoE3sUHwOYNyigSsVOsPAwaCEROkBNZhjgfM88BXQ8NSf1ppTWYJZSeb6hXXB/
A6Eu2ChkZ5OuZ/gYmUaWjjekM9tqfU+Ji/JbapW1cMFV4N1VXSw7+7lvmdknhUq0
uWrA5l9qQjpIQCMQRz0ElGI+ZViB9nWnAjlVk/wiMQ7p5CCkIB/xoVOtCCVd+I6N
Qv6Ins+DtQU6fu8WWbF8ioV2b6C5MUN0nSX0bRfi7hZaZC0STpVELhQ/2PH49aCI
KGGszYECgYEA3NZMZm9ENmbehIXel/d/0QX43Q23HCl08f4j6MWILKHiTlm6/9jQ
nK8jNMsy81bG9a5dQt9gQ+sARmOALrhGgyMi4ciVOMll1O4xNZJYOZsWOt5FNBYn
iKoIv/pHqpBdDu2bcD6QAjdilSy893sv+A9zYRgKINcVJyg/lnuyQE0CgYEAxi8P
24FEgk2mfipuxxBkQmwy0dFV7alFjHu3y+1vEXkUFDoT6lGZCTNjRE5K3aqtmWAM
a7v0pTXAqpnLdkBBocjFVIlTo5S9a1M5CKSQ2MS+ijmrAljw4SV/STcrHpa+9hre
pI8cywT2Sb4+H4UVCoWyD3PIPQchqn0kTZFcAEECgYBBhd/zQK43ifwZy/KImmm1
JhV52RjsZSyKpIIZDYri20FfR+ZhBP6Yjqpefq/mXWf4+zw2nDpezHovaFRfCFP7
ktBFt5L232K0c9vr7jj5FpfY7ZwQ4UXnmbOw6lybMew6gqts+VMXJUG9yyFiOI26
BzOPqmdO6SIglSOQzbDMvQKBgAl68NhAO8W77y3z2668Ev+2a0vsJp8izMfmlykz
J2//ib1Z9d/snVR6V9JJqH0oD/vZQ17X8+D/TEMc7kWu1zTlBMOBejXGBLWgmobW
UHN+HdtA3PRUytkKUSdwcyiYb3QYXvQiQG9ZwmpOpmwdkp8ZPCZPFJIOyEZ+jAEF
5g/BAoGAITbKksh69iGgyC4E1afAo8nEO1tMDul1TdzcORMgZfZjWutBNmsmBP29
4tfuo95uVcptb9yJBGy+enxdkZwqFDds+o890Jtpd4zu72sI8XWeu8S4kcNmdC9r
JEz3QLpaB9QP5oTSk5+rLKbYj25e/PLFivW5szT+JljuLfiS9r4=
-----END RSA PRIVATE KEY-----"

set -x
#_ali_v3_rpc_invoke "POST" "cas.aliyuncs.com" "UploadUserCertificate" "2020-04-07" --Name cert-upload-test --Cert "$cert" --Key "$key" --ResourceGroupId "rg-aekzpjhvnv3x5pi"
_ali_v3_rpc_invoke "GET" "slb.aliyuncs.com" "DescribeLoadBalancerTCPListenerAttribute" "2014-05-15" --RegionId cn-hangzhou --LoadBalancerId lb-bp1nrcrdmv2w3gqudbs2b --ListenerPort 5002