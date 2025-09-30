# 获取已上传证书 ID，无则忽略，从域名本地配置中，变量名为 SAVED_ALI_SSL_CERT_ID，通过 acme 内置函数获取

# 证书上传 api 示例
resourcegroupid=rg-aekzpjhvnv3x5pi
_ret=$(_ali_v3_rpc_invoke "POST" "cas.aliyuncs.com" "UploadUserCertificate" "2020-04-07" --Name "autoup-cert-$_host-$(date -d now +%s%3N)" --Cert "$_cert" --Key "$_key" --ResourceGroupId "$resourcegroupid")

# 查询返回结果，有无  _certid=$(echo $ret | jq -r '.CertId') 结果，没有则上传失败，发送钉钉，格式如下：
dingtalk_send "Action: UploadUserCertificate" "$_host Failed" 1 "+86-13679965356"

# 有则保存证书 ID 到本地域名配置，保存失败则发送钉钉，格式如上。通知时需要加上 ID 号。

# 上传，保存 ID 完毕后，通过第一步获取的证书删除老的证书 ID，删除证书，证书删除 api 示例：
_ali_v3_rpc_invoke "POST" "cas.aliyuncs.com" "DeleteUserCertificate" "2020-04-07" --CertId "$_cert_id"

# 通过文本判断，命令是否调用失败，删除失败则发动钉钉，加上 ID 号：
# 这是删除成功返回值，{"RequestId":"A37E9039-143B-566E-A0DF-351C253127F4"}
# 删除失败返回值，{"RequestId":"DC7CBB70-4661-50B2-97B6-055B0CB4F75F","HostId":"cas.aliyuncs.com","Code":"NotFound","Message":"没有找到必要内容，请检查参数输入。","Recommend":"https://api.aliyun.com/troubleshoot?q=NotFound&product=cas&requestId=DC7CBB70-4661-50B2-97B6-055B0CB4F75F"}
# 判断命令返回的 json 中， Code 是否有 NotFound 即可

#-----------------------------------------------------------------
# Aliyun SSL Certificate Management Hook for acme.sh
#-----------------------------------------------------------------
# Dependencies:
#   - _ali_v3_rpc_invoke (acme.sh builtin)
#   - _getdeployconf, _savedeployconf (acme.sh builtin)
#   - dingtalk_send (custom notification)
#   - jq (for JSON parsing)
#
# Usage:
#   acme.sh --deploy -d example.com --deploy-hook ali-cert
#
# Parameters:
#   $1  domain name
#   $2  key file path
#   $3  cert file path
#   $4  ca file path
#   $5  fullchain file path
#
# Workflow:
#   1. Get old CertId from deploy conf (if exists)
#   2. Upload new cert & key to Aliyun CAS
#   3. Save new CertId into deploy conf
#   4. Delete old CertId (if exists)
#   5. Notify via dingtalk_send
#-----------------------------------------------------------------

_ali_cert_manage() {
  . "/root/.acme.sh/notify/dingtalk.sh"
  _cdomain="$1"
  _cfullchain="$2"
  _ckey="$3"

  _debug "_ali_cert_manage domain" "$_cdomain"

  # Step 1: Load previous CertId from deploy conf
  _getdeployconf "ALI_SSL_CERT_ID"
  _debug "old CertId: " "$ALI_SSL_CERT_ID"

  # Step 2: Upload new certificate
  _cert="$(cat "$_cfullchain")" 
  _key="$(cat "$_ckey")"
  _resourceGroupId="${ALI_SSL_RGID:-rg-aekzpjhvnv3x5pi}"

  _ret=$(_ali_v3_rpc_invoke "POST" "cas.aliyuncs.com" "UploadUserCertificate" "2020-04-07" \
    --Name "autoup-cert-$_cdomain-$(date -d now +%s%3N)" \
    --Cert "$_cert" \
    --Key "$_key" \
    --ResourceGroupId "$_resourceGroupId")

  _debug "Upload result" "$_ret"

  certid=$(echo "$_ret" | jq -r '.CertId')

  if [ -z "$certid" ]; then
    _err "UploadUserCertificate failed for $_cdomain"
    dingtalk_send "Action: UploadUserCertificate" "$_cdomain Failed\n\n$_ret" 1 "+86-13679965356"
    return 1
  fi

  _info "Upload success, new CertId=$certid"

  # Step 3: Save new CertId into deploy conf
  if ! _savedeployconf "ALI_SSL_CERT_ID" "$certid"; then
    dingtalk_send "Action: SaveCertId" "$_cdomain Failed to save, CertId=$certid" 1 "+86-13679965356"
    return 1
  fi

  # Step 4: Delete old certificate if exists
  if [ -n "$ALI_SSL_CERT_ID" ]; then
    _del_ret=$(_ali_v3_rpc_invoke "POST" "cas.aliyuncs.com" "DeleteUserCertificate" "2020-04-07" \
      --CertId "$ALI_SSL_CERT_ID")

    _debug "Delete result" "$_del_ret"

    if echo "$_del_ret" | grep -q '"Code":"NotFound"'; then
      _err "DeleteUserCertificate failed, NotFound, CertId=$ALI_SSL_CERT_ID"
      dingtalk_send "Action: DeleteUserCertificate" "$_cdomain Delete Failed, CertId=$ALI_SSL_CERT_ID\n\n$_del_ret" 1 "+86-13679965356"
    fi
  fi

  return 0
}