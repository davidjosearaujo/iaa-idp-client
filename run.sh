# Copyright 2024 David Araújo & Diogo Matos
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# These three emails MUST be different from each other!!
export CLIENT_EMAIL=${CLIENT_EMAIL:-"client-email@xpto.com"}
export OFFICER_EMAIL=${OFFICER_EMAIL:-"officer-email@xpto.com"}
export MANAGER_EMAIL=${MANAGER_EMAIL:-"manager-email@xpto.com"}

sed -i "s/client-email@xpto.com/$CLIENT_EMAIL/g" ./idp/environment_variables
sed -i "s/officer-email@xpto.com/$OFFICER_EMAIL/g" ./idp/environment_variables
sed -i "s/manager-email@xpto.com/$MANAGER_EMAIL/g" ./idp/environment_variables

sed -i "s/client-email@xpto.com/$CLIENT_EMAIL/g" ./resource_servers/environment_variables

echo "[+] Creating network..."
docker network create iaa_network >> /dev/null
echo -e "[!] Network 'iaa_network' created!\n"

rm -r logs
mkdir logs

cd ./resource_servers
echo "[+] Resource servers are launching..."
docker compose up -d >> ../logs/resources-launch.log
echo "[!] Resource servers launched!"
echo -e " => Logs at ./log/resources-launch.log\n"

cd ./cc_middleware
echo "[+] Launcing CC middleware..."
python3 -m venv .venv
source .venv/bin/activate >> ../../logs/cc-middleware.log 2>&1
pip install -r requirements.txt >> ../../logs/cc-middleware.log 2>&1
python3 -u -m flask run --host=127.0.0.1 --port 6004 >> ../../logs/cc-middleware.log 2>&1 &
echo "[!] CC Middleware launched!"
echo -e " => Logs at ./log/cc-middleware.log\n"

cd ../../idp
xhost +
echo "[+] IDP is launching..."
docker compose up -d >> ../logs/idp-launch.log
echo "[!] IDP launched! Follow the steps in the browser and pay attention to your email."
echo -e " => Logs at ./log/idp-launch.log\n"

cd ../services
echo "[+] Services are launching..."
docker compose up -d >> ../logs/services-launch.log
echo "[!] Services launched! Take note of the following URLs to access services AFTER having registered with the IDP."
echo " => => Home Banking service runing at: http://127.0.0.1:5005"
echo " => => Officer Management service runing at: http://127.0.0.1:5006"
echo " => => Manager Management service runing at: http://127.0.0.1:5007"
echo " => Logs at ./log/services-launch.log"