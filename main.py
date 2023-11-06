import json
import os
from os.path import exists
import logging
import http
import http.client
import urllib.parse
import aiohttp
import asyncio
import aiofiles

OK = http.HTTPStatus.OK
BAD_REQUEST = http.HTTPStatus.BAD_REQUEST
NOT_FOUND = http.HTTPStatus.NOT_FOUND
UNAUTHORIZED = http.HTTPStatus.UNAUTHORIZED
CREATED = http.HTTPStatus.CREATED
FORBIDDEN = http.HTTPStatus.FORBIDDEN
NO_CONTENT = http.HTTPStatus.NO_CONTENT
ACCEPTED = http.HTTPStatus.ACCEPTED
CONFLICT = http.HTTPStatus.CONFLICT

# create logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


def get_command_line_arguments():
    """

    Returns:
        Namespace
    """
    logger.info("Begin parsing command line argument")
    import argparse
    description = 'A simple command-line interface for CxSAST in Python.'
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--sca_tenant', required=True, help="CxSCA tenant")
    parser.add_argument('--sca_username', required=True, help="CxSCA username")
    parser.add_argument('--sca_password', required=True, help="CxSCA password")
    parser.add_argument('--report_csv', default="./cx_sca_licenses.csv", help="csv report file path")
    logger.info("Finish parsing command line argument")
    return parser.parse_known_args()


def get_new_header(username, password, account):
    """

    Args:
        username (str):
        password (str):
        account (str):

    Returns:

    """
    logger.info("begin to get SCA token")
    result = None
    params = urllib.parse.urlencode(
        {
            "username": username,
            "password": password,
            "acr_values": "Tenant:" + str(account),
            "grant_type": "password",
            "scope": "sca_api",
            "client_id": "sca_resource_owner",
        }
    )
    headers = {"Content-type": "application/x-www-form-urlencoded",
               "Accept": "text/plain"}
    conn = http.client.HTTPSConnection("platform.checkmarx.net")
    conn.request("POST", "/identity/connect/token", params, headers)
    response = conn.getresponse()
    if response.status == OK:
        data = response.read()
        data = json.loads(data)
        result = {
            "Authorization": data.get("token_type") + " " + data.get("access_token"),
            "Accept": "application/json;v=1.0",
            "Content-Type": "application/json;v=1.0",
            "user-agent":
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/106.0.0.0 Safari/537.36",
        }
    else:
        logger.error(f"Fail to get SCA token, "
                     f"response status: {response.status}, "
                     f"response reason: {response.reason}")
    conn.close()
    logger.info("Finish to get SCA token")
    return result


def get_projects(headers):
    """

    :param headers:
    :return:
    """
    logger.info("Begin to get all SCA projects info")
    result = None
    conn = http.client.HTTPSConnection("api-sca.checkmarx.net")
    conn.request("GET", "/risk-management/projects", headers=headers)
    response = conn.getresponse()
    if response.status == OK:
        data = response.read()
        result = [
            {
                "projectName": item.get("name"),
                "projectId": item.get("id"),
                "scanId": item.get("lastSuccessfulScanId")
            }
            for item in json.loads(data)
        ]

    conn.close()
    logger.info("Finish to get all SCA projects info")
    return result


async def create_csv_file(file_path, scan_id_info, content):
    logger.info("Begin to write CSV content")
    project_name = scan_id_info.get("projectName")
    project_id = scan_id_info.get("projectId")
    scan_id = scan_id_info.get("scanId")
    logger.info(f"project name: {project_name}")
    logger.info(f"project id: {project_id}")
    logger.info(f"scan id: {scan_id}")

    file_content = ""
    for item in content:
        line = ",".join([
            project_name,
            project_id,
            scan_id,
            item.get("id"),
            item.get("referenceType"),
            item.get("reference"),
            item.get("royaltyFree"),
            str(item.get("copyrightRiskScore")),
            item.get("riskLevel"),
            item.get("linking"),
            item.get("copyLeft"),
            str(item.get("patentRiskScore")),
            item.get("name"),
            item.get("url"),
        ]) + "\n"
        file_content += line

    if not exists(file_path):
        async with aiofiles.open(file_path, "w") as f:
            await f.write("projectName,projectId,scanId,packageId,referenceType,reference,royaltyFree,"
                          "copyrightRiskScore,riskLevel,linking,copyLeft,patentRiskScore,name,url\n")
            await f.write(file_content)
    else:
        async with aiofiles.open(file_path, "a") as f:
            await f.write(file_content)


async def fetch(s, scan_id_info, file_path):
    scan_id = scan_id_info.get("scanId")
    if not scan_id:
        return
    async with s.get(f'https://api-sca.checkmarx.net/risk-management/risk-reports/{scan_id}/licenses') as response:
        if response.status != 200:
            logger.error(f"Fail to scan with {scan_id} has no license info, {response.status}, {response.reason}")
            return
        await create_csv_file(file_path, scan_id_info, await response.json())


async def fetch_all(s, scan_ids, file_path):
    tasks = []
    for scan_id in scan_ids:
        task = asyncio.create_task(fetch(s, scan_id, file_path))
        tasks.append(task)
    await asyncio.gather(*tasks)


async def main():
    file_path = "./cx_sca_licenses.csv"
    if exists(file_path):
        os.remove(file_path)

    cli_args = get_command_line_arguments()
    args = cli_args[0]
    sca_tenant = args.sca_tenant
    sca_username = args.sca_username
    sca_password = args.sca_password
    report_csv = args.report_csv
    headers = get_new_header(sca_username, sca_password, sca_tenant)
    scan_id_info_list = get_projects(headers)
    async with aiohttp.ClientSession(headers=headers) as session:
        await fetch_all(session, scan_id_info_list, report_csv)


if __name__ == "__main__":
    asyncio.run(main())
