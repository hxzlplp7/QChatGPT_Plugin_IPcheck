from pkg.plugin.context import register, handler, llm_func, BasePlugin, APIHost, EventContext
from pkg.plugin.events import *  # 导入事件类
import re
import httpx
from mirai import Plain

@register(name="IP查询", description="查询IP地址", version="0.1", author="zzseki")
class GetIPPlugin(BasePlugin):

    def __init__(self, host: APIHost):
        pass

    @handler(PersonNormalMessageReceived)
    async def person_normal_message_received(self, ctx: EventContext):
        receive_text = ctx.event.text_message
        # 检测消息中是否包含 "ip"（不区分大小写）
        ip_pattern = re.compile(r"(?i)ip")
        if ip_pattern.search(receive_text):
            ip_info = await self.get_ip()
            if ip_info:
                ctx.add_return("reply", [Plain(ip_info)])
                self.ap.logger.info(ip_info)
                ctx.prevent_default()

    @handler(GroupNormalMessageReceived)
    async def group_normal_message_received(self, ctx: EventContext):
        receive_text = ctx.event.text_message
        ip_pattern = re.compile(r"(?i)ip")
        if ip_pattern.search(receive_text):
            ip_info = await self.get_ip()
            if ip_info:
                ctx.add_return("reply", [Plain(ip_info)])
                self.ap.logger.info(ip_info)
                ctx.prevent_default()

    async def get_ip(self):
        url = "http://ip234.in/ip.json"
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            json_data = response.json()  # 解析 JSON 数据
            # 从返回的数据中提取各项信息
            ip = json_data.get("ip", "未知")
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
            # 格式化文本消息
            result_text = (
                f"IP地址: {ip}\n"
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

    def __del__(self):
        pass
