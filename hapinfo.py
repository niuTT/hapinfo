# -*- coding: utf-8 -*-

try:
    import sys
    import os
    import hashlib
    import binascii
    from androguard.core.bytecodes.apk import APK
    from androguard.core.bytecodes.dvm import *
    from colorama import Fore, Back, Style
    import OpenSSL
    import zipfile
    import re
    import plistlib
    from dateutil import parser
    import json
    from PIL import Image
    import io
    from binascii import hexlify, unhexlify
except ImportError as e:
    print("[*] 模块未安装,请确认androguard、openssl是否安装,安装命令:\n\tpip install androguard\n\tpip install pyopenssl\n")
    print("[*] 报错信息:", e)
    sys.exit()


# 定义打印格式
def stdio(info, content):
    if False:  # 控制台乱码修改此处为False
        print(info + " " + Fore.LIGHTCYAN_EX + Style.BRIGHT + str(content) + Style.RESET_ALL)
    else:
        print(info + " " + str(content))

def get_entry_to_json(zip_file, entry_name):
    with zip_file.open(entry_name) as entry:
        content = entry.read()
        return json.loads(content.decode('utf-8', errors='replace'))

def get_entry_to_image(zip_file, entry_name):
    with zip_file.open(entry_name) as entry:
        return Image.open(io.BytesIO(entry.read()))

def get_entry_to_bytes(zip_file, entry_name):
    with zip_file.open(entry_name) as entry:
        return entry.read()

class _Hap:

    def analyzeHap(self, hapPath):
        print(hapPath)
        hap_info = {}

        with zipfile.ZipFile(hapPath, 'r') as zip_file:
            # 读取module.json
            module = get_entry_to_json(zip_file, 'module.json')

            # app.
            hap_info["versionName"] = module.get("app", {}).get("versionName")
            hap_info["bundleName"] = module.get("app", {}).get("bundleName")
            hap_info["apiReleaseType"] = module.get("app", {}).get("apiReleaseType")
            hap_info["compileSdkType"] = module.get("app", {}).get("compileSdkType")
            hap_info["compileSdkVersion"] = module.get("app", {}).get("compileSdkVersion")
            hap_info["debug"] = module.get("app", {}).get("debug")
            hap_info["distributedNotificationEnabled"] = module.get("app", {}).get("distributedNotificationEnabled")
            hap_info["iconId"] = module.get("app", {}).get("iconId")

            hap_info["label"] = module.get("app", {}).get("label")
            hap_info["labelId"] = module.get("app", {}).get("labelId")
            hap_info["minAPIVersion"] = module.get("app", {}).get("minAPIVersion")
            hap_info["targetAPIVersion"] = module.get("app", {}).get("targetAPIVersion")
            hap_info["vendor"] = module.get("app", {}).get("vendor")
            hap_info["versionCode"] = module.get("app", {}).get("versionCode")

            # module.

            hap_info["compileMode"] = module.get("module", {}).get("compileMode")
            hap_info["deliveryWithInstall"] = module.get("module", {}).get("deliveryWithInstall")
            hap_info["dependencies"] = module.get("module", {}).get("dependencies")
            hap_info["deviceTypes"] = module.get("module", {}).get("deviceTypes")
            hap_info["mainElement"] = module.get("module", {}).get("mainElement")
            hap_info["installationFree"] = module.get("module", {}).get("installationFree")
            hap_info["type"] = module.get("module", {}).get("type")
            hap_info["virtualMachine"] = module.get("module", {}).get("virtualMachine")


            # 解析权限
            hap_info["requestPermissions"] = module.get("module", {}).get("requestPermissions", [])
            if hap_info["requestPermissions"]:
                hap_info["requestPermissionNames"] = [perm.get("name") for perm in hap_info["requestPermissions"]]

            # 解析图标
            module_abilities = module.get("module", {}).get("abilities") or module.get("module", {}).get(
                "extensionAbilities")
            target_ability = None
            try:
                target_ability = module_abilities[0]
            except (IndexError, TypeError):
                pass

            for ability in module_abilities:
                if hap_info["mainElement"] == ability.get("name"):
                    target_ability = ability
                    break

            if target_ability:
                icon_name = target_ability.get("icon").split(":")[1]
                icon_path = f"resources/base/media/{icon_name}.png"
                hap_info["iconPath"] = icon_path
                hap_info["iconBytes"] = get_entry_to_bytes(zip_file, icon_path)
                hap_info["icon"] = get_entry_to_image(zip_file, icon_path)
                hap_info["labelName"] = target_ability.get("label").split(":")[1]

            # 解析名称
            app_name = "解析失败"
            try:
                resources_index_bytes = get_entry_to_bytes(zip_file, 'resources.index')
                resources_index_hex = resources_index_bytes.hex().upper()
                label_name_hex = hap_info["labelName"].encode().hex().upper()

                reg = rf"00..000000..000000..0000....00(.*?)00..00{label_name_hex}"
                match = re.search(reg, resources_index_hex)
                if match:
                    app_name_hex = match.group(1)
                    app_name_parts = re.split(r"00..000000..000000..0000....00", app_name_hex)
                    app_name_hex = app_name_parts[-1]
                    app_name = unhexlify(app_name_hex).decode('utf-8', errors='replace')
            except Exception as e:
                print(e)
            hap_info["appName"] = app_name

            # 技术探测
            tech_list = set()
            for zip_entry in zip_file.infolist():
                name = zip_entry.filename
                if re.search(r"libs/arm.*/libcocos.so", name) or re.search(r"ets/workers/CocosWorker.abc", name):
                    tech_list.add("Cocos")
                elif re.search(r"libs/arm.*/libflutter.so", name):
                    tech_list.add("Flutter")
                elif re.search(r"libs/arm.*/libQt5Core.so", name):
                    tech_list.add("Qt")
                elif re.search(r"libs/arm.*/libil2cpp.so", name) or re.search(r"libs/arm.*/libtuanjie.so", name):
                    tech_list.add("Unity(团结引擎)")

            hap_info["techList"] = tech_list
        print(f"\t应用名称: {hap_info['appName']}")
        print(f"\t包名: {hap_info['bundleName']}")
        print(f"\t版本名称: {hap_info['versionName']}")
        print(f"\t版本代码: {hap_info['versionCode']}")
        stdio("\t文件大小:", os.path.getsize(hapPath))
        print(f"\t供应商: {hap_info['vendor']}")
        print(f"\t最小API版本: {hap_info['minAPIVersion']}")
        print(f"\t目标API版本: {hap_info['targetAPIVersion']}")
        print(f"\tAPI发布类型: {hap_info['apiReleaseType']}")
        print(f"\t主元素: {hap_info['mainElement']}")
        print(f"\t请求权限: {hap_info.get('requestPermissionNames')}")
        print(f"\t图标 ID: {hap_info['iconId']}")
        print(f"\t图标路径: {hap_info['iconPath']}")
        print(f"\t标签名称: {hap_info['labelName']}")
        print(f"\t标签 ID: {hap_info['labelId']}")
        print(f"\t技术列表: {hap_info['techList']}")
        print(f"\t编译 SDK 类型: {hap_info['compileSdkType']}")
        print(f"\t编译 SDK 版本: {hap_info['compileSdkVersion']}")
        print(f"\t调试模式: {hap_info['debug']}")
        print(f"\t分布式通知启用: {hap_info['distributedNotificationEnabled']}")

        # module.
        print(f"\t编译模式: {hap_info['compileMode']}")
        print(f"\t带安装交付: {hap_info['deliveryWithInstall']}")
        print(f"\t依赖项: {hap_info['dependencies']}")
        print(f"\t设备类型: {hap_info['deviceTypes']}")
        print(f"\t自由安装: {hap_info['installationFree']}")
        print(f"\t类型: {hap_info['type']}")
        print(f"\t虚拟机: {hap_info['virtualMachine']}")

        apkByte = open(hapPath, "rb").read()
        m = hashlib.md5()
        m.update(apkByte)
        apkMd5 = m.hexdigest()
        stdio("\thap文件MD5:", apkMd5)
        m = hashlib.sha1()
        m.update(apkByte)
        apkSha1 = m.hexdigest()
        stdio("\thap文件SHA1:", apkSha1)
        m = hashlib.sha256()
        m.update(apkByte)
        apkSha256 = m.hexdigest()
        stdio("\thap文件SHA256:", apkSha256)




if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 2:
        stdio("ERROR:", "参数输入错误")
        stdio("Example:", "python hapinfo.py  xxx.hap")
        sys.exit()

    if not os.path.isfile(sys.argv[1]):
        stdio("ERROR:", "文件不存在")
        sys.exit()

    if not zipfile.is_zipfile(sys.argv[1]):
        stdio("ERROR:", "不是有效的hap文件")
        sys.exit()


    if sys.argv[1][-4:] == ".hap":
        _Hap().analyzeHap(sys.argv[1])
    else:
        stdio("ERROR:", "文件后缀非hap")

    # pip install androguard
    # pip install pyopenssl
