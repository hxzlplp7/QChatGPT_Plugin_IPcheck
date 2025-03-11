from pkg.plugin.context import register, handler, llm_func, BasePlugin, APIHost, EventContext
from pkg.plugin.events import *  # 导入事件类
import re
import httpx
import json
from mirai import Plain

@register(name="IP查询扩展", description="集成查询IP信息和风险查询功能", version="0.2", author="zzseki")
class GetIPExtendedPlugin(BasePlugin):

    def __init__(self, host: APIHost):
        pass

    @handler(PersonNormalMessageReceived)
    async def person_normal_message_received(self, ctx: EventContext):
        receive_text = ctx.event.text_message

        # 定义正则匹配模式：
        # 匹配“查询IP信息”或“查询指定IP信息”，后面跟着IP地址
        pattern_ip_info = re.compile(r"(?i)(?:查询(?:指定)?IP信息)[:：\s]*([\d]{1,3}(?:\.[\d]{1,3}){3})")
        # 匹配“查询IP风险”或“查询指定IP风险”，后面跟着IP地址
        pattern_ip_risk = re.compile(r"(?i)(?:查询(?:指定)?IP风险)[:：\s]*([\d]{1,3}(?:\.[\d]{1,3}){3})")
        # 匹配“查询当前IP风险”或“当前IP风险”（无IP参数）
        pattern_current_ip_risk = re.compile(r"(?i)(?:查询当前IP风险|当前IP风险)")

        if match := pattern_ip_info.search(receive_text):
            ip = match.group(1)
            ip_info = await self.get_ip_info(ip)
            if ip_info:
                ctx.add_return("reply", [Plain(ip_info)])
                self.ap.logger.info(ip_info)
                ctx.prevent_default()
        elif match := pattern_ip_risk.search(receive_text):
            ip = match.group(1)
            ip_risk = await self.get_ip_risk(ip)
            if ip_risk:
                ctx.add_return("reply", [Plain(ip_risk)])
                self.ap.logger.info(ip_risk)
                ctx.prevent_default()
        elif pattern_current_ip_risk.search(receive_text):
            current_risk = await self.get_current_ip_risk()
            if current_risk:
                ctx.add_return("reply", [Plain(current_risk)])
                self.ap.logger.info(current_risk)
                ctx.prevent_default()

    @handler(GroupNormalMessageReceived)
    async def group_normal_message_received(self, ctx: EventContext):
        receive_text = ctx.event.text_message

        pattern_ip_info = re.compile(r"(?i)(?:查询(?:指定)?IP信息)[:：\s]*([\d]{1,3}(?:\.[\d]{1,3}){3})")
        pattern_ip_risk = re.compile(r"(?i)(?:查询(?:指定)?IP风险)[:：\s]*([\d]{1,3}(?:\.[\d]{1,3}){3})")
        pattern_current_ip_risk = re.compile(r"(?i)(?:查询当前IP风险|当前IP风险)")

        if match := pattern_ip_info.search(receive_text):
            ip = match.group(1)
            ip_info = await self.get_ip_info(ip)
            if ip_info:
                ctx.add_return("reply", [Plain(ip_info)])
                self.ap.logger.info(ip_info)
                ctx.prevent_default()
        elif match := pattern_ip_risk.search(receive_text):
            ip = match.group(1)
            ip_risk = await self.get_ip_risk(ip)
            if ip_risk:
                ctx.add_return("reply", [Plain(ip_risk)])
                self.ap.logger.info(ip_risk)
                ctx.prevent_default()
        elif pattern_current_ip_risk.search(receive_text):
            current_risk = await self.get_current_ip_risk()
            if current_risk:
                ctx.add_return("reply", [Plain(current_risk)])
                self.ap.logger.info(current_risk)
                ctx.prevent_default()

    async def get_ip_info(self, ip: str):
        """
        查询指定IP信息，调用接口：http://ip234.in/search_ip?ip=xxx
        """
        url = f"http://ip234.in/search_ip?ip={ip}"
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            json_data = response.json()
        # 从返回数据中提取关键信息（若字段不存在，则显示“未知”）
        ip_address = json_data.get("ip", "未知")
        city = json_data.get("city", "未知")
        organization = json_data.get("organization", "未知")
        asn = json_data.get("asn", "未知")
        network = json_data.get("network", "未知")
        country = json_data.get("country", "未知")
        country_code = json_data.get("country_code", "未知")
        continent = json_data.get("continent", "未知")
        continent_code = json_data.get("continent_code", "未知")
        postal = json_data.get("postal", "未知")
        latitude = json_data.get("latitude", "未知")
        longitude = json_data.get("longitude", "未知")
        timezone = json_data.get("timezone", "未知")
        region = json_data.get("region", "未知")
        region_cn = json_data.get("region_cn", "未知")
        region_code = json_data.get("region_code", "未知")
        result_text = (
            f"【指定IP信息】\n"
            f"IP地址: {ip_address}\n"
            f"城市: {city}\n"
            f"组织: {organization}\n"
            f"ASN: {asn}\n"
            f"网络: {network}\n"
            f"国家: {country} ({country_code})\n"
            f"洲: {continent} ({continent_code})\n"
            f"邮政编码: {postal}\n"
            f"纬度: {latitude}\n"
            f"经度: {longitude}\n"
            f"时区: {timezone}\n"
            f"地区代码: {region_code}\n"
            f"地区: {region}\n"
            f"中文地区: {region_cn}"
        )
        return result_text

    async def get_current_ip_risk(self):
        """
        查询当前IP风险，调用接口：http://ip234.in/f.json
        """
        url = "http://ip234.in/f.json"
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            json_data = response.json()
        # 将返回的 JSON 数据格式化为易读文本
        result_text = "【当前IP风险信息】\n" + json.dumps(json_data, ensure_ascii=False, indent=2)
        return result_text

    async def get_ip_risk(self, ip: str):
        """
        查询指定IP风险，调用接口：http://ip234.in/fraud_check?ip=xxx
        """
        url = f"http://ip234.in/fraud_check?ip={ip}"
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            json_data = response.json()
        result_text = f"【指定IP风险信息】\nIP {ip} 风险信息:\n" + json.dumps(json_data, ensure_ascii=False, indent=2)
        return result_text

    def __del__(self):
        pass
