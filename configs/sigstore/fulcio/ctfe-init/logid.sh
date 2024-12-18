#!/bin/bash
#
# Copyright 2021 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


function get_log_id() {
	curl -s --retry-connrefused --retry 10 http://ct-trillian-log-server:8091/metrics |grep "^quota_acquired_tokens{spec=\"trees"|head -1|awk ' { print $1 } '|sed -e 's/[^0-9]*//g' > /tmp/logid
}

function create_log () {
	/go/bin/createtree -admin_server ct-trillian-log-server:8090 > /tmp/logid
	echo -n "Created log ID " && cat /tmp/logid
}

function update_config() {
	cat /root/ctfe/ct_server.cfg | sed -e "s/%LOGID%/"`cat /tmp/logid`"/g" > /etc/config/ct_server.cfg
	cp /root/ctfe/*.pem /etc/config/
}

# check to see if log id exists; if so, use that
echo -n "Checking for existing configuration..."
if ! [[ -s /etc/config/ct_server.cfg ]]; then
	echo " none found."
	echo "Checking for preexisting logs..."
	get_log_id
	# else create one
	if ! [[ -s /tmp/logid ]]; then
		echo "No log found; let's create one..."
		create_log
		# update config file accordingly
		update_config
	else
		echo "Log ID known but config not found"
		update_config
	fi
else
	echo " found."
	configid=`cat /etc/config/ct_server.cfg|grep log_id|awk ' { print $2 } '`
	echo "Existing configuration uses log ID $configid"
fi
curl -s --retry-connrefused --retry 10 http://fulcio:5555/api/v1/rootCert -o tmpchain.pem
csplit -s -f tmpcert- tmpchain.pem '/-----BEGIN CERTIFICATE-----/' '{*}'
mv $(ls tmpcert-* | tail -1) /etc/config/root.pem
rm tmpcert-* tmpchain.pem
cat /etc/config/root.pem
echo "Fetched valid root certificate from Fulcio to limit entries in CTFE instance"
