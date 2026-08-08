#  This file is part of lceta modules
#  Copyright (c) 2026 lceta
#  This software is released under the MIT License.
#  https://opensource.org/licenses/MIT

# meta developer: @lceta
# meta banner: https://raw.githubusercontent.com/lcetaa/VirusTotal-hikka-bot/refs/heads/main/logo.png
# meta pic: https://raw.githubusercontent.com/lcetaa/VirusTotal-hikka-bot/refs/heads/main/icon.png

__version__ = (2, 0, 8) #show api spend toast and comments added

# ░█░░░█▀▀░█▀▀░▀█▀░█▀█
# ░█░░░█░░░█▀▀░░█░░█▀█
# ░▀▀▀░▀▀▀░▀▀▀░░▀░░▀░▀


import asyncio,re,base64,hashlib,time,ipaddress,logging,html
from datetime import datetime,timezone
from urllib.parse import urlparse
from typing import Optional,Dict,Tuple
from dataclasses import dataclass,field
import aiohttp
from .. import loader,utils

MAX_FILE_SIZE=32*1024*1024
HISTORY_PER_PAGE=5
COMMENTS_PER_PAGE=10
MAX_JUMP_PAGES=7
logger=logging.getLogger(__name__)

class VirusTotalError(Exception):pass
class QuotaExceededError(VirusTotalError):pass
class InvalidKeyError(VirusTotalError):pass
class RateLimitError(VirusTotalError):pass
class NotFoundError(VirusTotalError):pass

@dataclass
class ScanStats:
    malicious:int=0
    suspicious:int=0
    harmless:int=0
    undetected:int=0
    @property
    def total(self)->int:
        return self.malicious+self.suspicious+self.harmless+self.undetected

@dataclass
class HistoryEntry:
    item_id:str
    timestamp:datetime
    scan_type:str
    name:Optional[str]=None
    url:Optional[str]=None
    as_owner:Optional[str]=None
    country_code:Optional[str]=None
    stats:ScanStats=field(default_factory=ScanStats)
    raw_result:dict=field(default_factory=dict)

@loader.tds
class VirusTotalMod(loader.Module):
    strings={
        "name":"VirusTotal",
        "_cls_doc":"Scan files, URLs, IPs and hashes (MD5/SHA1/SHA256) via VirusTotal API.",
        "no_url":"Specify URL, IP, domain, file or hash (MD5/SHA1/SHA256)",
        "checking_domain":"Checking domain...",
        "reputation":"Reputation",
        "categories":"Categories",
        "invalid_url":"Invalid URL format",
        "downloading":"Downloading file...",
        "uploading":"Uploading to VirusTotal...",
        "scanning_url":"Scanning URL...",
        "waiting":"Waiting for analysis",
        "no_key":"Set API key(s) in config",
        "error":"Error: {}",
        "size_limit":"File is larger than 32MB",
        "timeout":"Scan timeout",
        "view_report":"Full report",
        "checking_cache":"Checking cache...",
        "upload_error":"Upload error",
        "scan_error":"Scan error",
        "results_title":"VirusTotal Scan Results",
        "history_title":"VirusTotal Scan History",
        "history_empty":"Scan history is empty",
        "history_cleared":"History cleared",
        "history_entries":"Total entries",
        "clear_history":"Clear",
        "cancel":"Cancel",
        "confirm_clear":"Confirm clear",
        "clear_history_confirm":"⚠️ Are you sure you want to clear all history?\nThis action cannot be undone.",
        "prev_page":"Back",
        "next_page":"Forward",
        "refresh":"Refresh",
        "back_to_results":"Back",
        "file":"File",
        "url":"URL",
        "hash":"Hash",
        "domain":"Domain",
        "scans":"scans",
        "engines":"engines",
        "clean":"clean",
        "dangerous":"dangerous",
        "very_dangerous":"very dangerous",
        "suspicious":"suspicious",
        "likely_safe":"likely safe",
        "threats":"Threats",
        "detected":"detected",
        "status":"Status",
        "safe":"safe",
        "results":"Results",
        "malicious":"Malicious",
        "harmless":"Harmless",
        "undetected":"Undetected",
        "checking_hash":"Checking hash...",
        "searching_report":"Searching report by {} hash...",
        "not_found":"Not found",
        "unknown":"Unknown",
        "country":"Country",
        "asn":"ASN",
        "ip_address":"IP-address",
        "checking":"Checking",
        "of":"of",
        "history":"History",
        "yes_clear":"Yes, clear",
        "deleted_entries":"Deleted entries",
        "bytes":"B",
        "kb":"KB",
        "mb":"MB",
        "gb":"GB",
        "sec":"sec",
        "min":"min",
        "entries":"Entries",
        "quota_error":"{} VirusTotal daily quota exceeded. Try again tomorrow or add more API keys",
        "invalid_key_error":"{} Invalid API key. Check your key(s) in config: <code>.cfg VirusTotal api_keys</code>",
        "rate_limit_error":"{} Too many requests. Please wait {} seconds",
        "not_found_error":"{} Resource not found in VirusTotal database",
        "server_error":"{} VirusTotal server error ({}). Try again later",
        "network_error":"{} Network error: {}",
        "all_keys_exhausted":"{} <b>All API keys have exhausted their quotas. Add new keys to config</b>",
        "comments":"Comments",
        "comments_title":"Community comments",
        "comments_total":"Total: {} comments",
        "no_comments":"No comments for this item yet",
        "comment_votes":"👍 {} 👎 {}",
        "quota_short":"⚠️ API quota used up",
        "quota_title":"API Keys",
        "quota_active_keys":"Keys",
        "quota_requests_today":"Today",
        "quota_used":"Quota",
        "quota_key_type":"Type",
        "loading":"Loading…",
        "quota_free":"Free",
        "quota_paid":"Paid",
        "quota_unavailable":"VT quota data unavailable",
        "quota_no_keys":"No API keys configured",
        "please_wait":"⏳ Already loading, please wait",
        "spent_requests":"API keys spent: {}",
        "to_start":"To start",
        "to_end":"To end",
        "jump_limit_hit":"⚠️ Limit reached API keys: {}",
        "write_review":"Write review",
        "review_prompt":"Enter your review text",
        "review_posted":"Review posted: {}",
        "review_failed":"Review error: {}",
        "review_empty":"Review text cannot be empty",
        "delete_short":"delete",
        "you":"you",
        "comment_deleted":"Comment deleted",
        "checking_update":"Checking for update...",
        "update_load_error":"Download error: HTTP {}",
        "already_latest":"You already have the latest version",
        "version_unknown":"unknown",
        "installing_update":"Installing update {}...",
        "update_success":"Module updated to {}",
        "update_fallback":"Use <code>.dlm {}</code> if auto-install failed, remove old: <code>.unloadmod VirusTotal</code>",
        "update_timeout":"Timeout while downloading update",
        "update_error":"Update error: {}",
        "file_default":"file",
        "file_too_large":"File is too large to upload to VT",
        "size_label":"Size",
        "try_hash_search":"You can try to find this file in the VirusTotal database by hash — if someone has already scanned it before, the result will appear instantly.",
        "downloading_for_hash":"Downloading to calculate hash...",
        "not_in_vt_db":"File not found in VirusTotal database",
        "search_in_vt":"🔍 Search in VirusTotal",
        "no_search_results":"No results found for: {}",
        "size_limit_hint":"limit 32 MB",
    }
    
    strings_ru={
        "name":"VirusTotal",
        "_cls_doc":"Проверка файлов, ссылок, IP и хешей (MD5/SHA1/SHA256) через VirusTotal API.",
        "no_url":"Укажите ссылку, айпи, домен, файл или хеш (MD5/SHA1/SHA256)",
        "checking_domain":"Проверяю домен...",
        "reputation":"Репутация",
        "categories":"Категории",
        "invalid_url":"Неверный формат ссылки",
        "downloading":"Скачиваю файл...",
        "uploading":"Загружаю на VirusTotal...",
        "scanning_url":"Сканирую ссылку...",
        "waiting":"Жду анализа...",
        "no_key":"Укажите API ключ(и) в конфиге",
        "error":"Ошибка: {}",
        "size_limit":"Файл больше 32МБ",
        "timeout":"Таймаут сканирования",
        "view_report":"Полный отчёт",
        "checking_cache":"Проверка кэша...",
        "upload_error":"Ошибка загрузки",
        "scan_error":"Ошибка сканирования",
        "results_title":"Результаты сканирования VirusTotal",
        "history_title":"История сканирований VirusTotal",
        "history_empty":"История сканирований пуста",
        "history_cleared":"История очищена",
        "history_entries":"Всего записей",
        "clear_history":"Очистить",
        "cancel":"Отмена",
        "confirm_clear":"Подтвердить очистку",
        "clear_history_confirm":"⚠️ Вы уверены, что хотите очистить всю историю?\nЭто действие нельзя отменить.",
        "prev_page":"Назад",
        "next_page":"Вперед",
        "refresh":"Обновить",
        "back_to_results":"Обратно",
        "file":"Файл",
        "url":"Ссылка",
        "hash":"Хеш",
        "domain":"Домен",
        "scans":"сканирований",
        "engines":"движков",
        "clean":"чистый",
        "dangerous":"опасный",
        "very_dangerous":"очень опасный",
        "suspicious":"подозрительный",
        "likely_safe":"вероятно безопасный",
        "threats":"Угроз",
        "detected":"обнаружено",
        "status":"Статус",
        "safe":"безопасно",
        "results":"Результаты",
        "malicious":"Вредоносные",
        "harmless":"Безвредные",
        "undetected":"Не обнаружено",
        "checking_hash":"Проверка хеша...",
        "searching_report":"Поиск отчета по {} хешу...",
        "not_found":"Не найден",
        "unknown":"Неизвестно",
        "country":"Страна",
        "asn":"ASN",
        "ip_address":"IP-адрес",
        "checking":"Проверяю",
        "of":"из",
        "history":"История",
        "yes_clear":"Да, очистить",
        "deleted_entries":"Удалено записей",
        "bytes":"Б",
        "kb":"КБ",
        "mb":"МБ",
        "gb":"ГБ",
        "sec":"сек",
        "min":"мин",
        "entries":"Записи",
        "quota_error":"{} Превышен дневной лимит запросов VirusTotal. Попробуйте завтра или добавьте ещё API ключей",
        "invalid_key_error":"{} Неверный API ключ. Проверьте ключ(и) в конфиге: <code>.cfg VirusTotal api_keys</code>",
        "rate_limit_error":"{} Слишком много запросов. Подождите {} секунд",
        "not_found_error":"{} Ресурс не найден в базе VirusTotal",
        "server_error":"{} Ошибка сервера VirusTotal ({}). Попробуйте позже",
        "network_error":"{} Сетевая ошибка: {}",
        "all_keys_exhausted":"{} <b>Все API ключи исчерпали лимиты. Добавьте новые ключи в конфиг</b>",
        "comments":"Комментарии",
        "comments_title":"Комментарии сообщества",
        "comments_total":"Всего: {} коммент.",
        "no_comments":"Комментарии отсутствуют",
        "comment_votes":"👍 {} 👎 {}",
        "quota_short":"⚠️ Лимит API исчерпан",
        "quota_title":"API ключи",
        "quota_active_keys":"Ключи",
        "quota_requests_today":"Сегодня",
        "quota_used":"Квота",
        "quota_key_type":"Тип",
        "loading":"Загрузка…",
        "quota_free":"Бесплатный",
        "quota_paid":"Платный",
        "quota_unavailable":"Данные квоты VT недоступны",
        "quota_no_keys":"API ключи не настроены",
        "please_wait":"⏳ Уже загружается, подождите",
        "spent_requests":"Потрачено API ключей: {}",
        "to_start":"В начало",
        "to_end":"В конец",
        "jump_limit_hit":"⚠️ Лимит достигнут API ключей: {}",
        "write_review":"Отзыв",
        "review_prompt":"Введите текст отзыва",
        "review_posted":"Отзыв опубликован: {}",
        "review_failed":"Ошибка отзыва: {}",
        "review_empty":"Текст отзыва не может быть пустым",
        "delete_short":"удалить",
        "you":"вы",
        "comment_deleted":"Комментарий удалён",
        "checking_update":"Проверяю обновление...",
        "update_load_error":"Ошибка загрузки: HTTP {}",
        "already_latest":"У вас уже последняя версия",
        "version_unknown":"неизвестна",
        "installing_update":"Устанавливаю обновление {}...",
        "update_success":"Модуль обновлён до {}",
        "update_fallback":"Используйте <code>.dlm {}</code> если не сработало автоматически, удалите старый: <code>.unloadmod VirusTotal</code>",
        "update_timeout":"Таймаут при загрузке обновления",
        "update_error":"Ошибка обновления: {}",
        "file_default":"файл",
        "file_too_large":"Файл слишком большой для загрузки на VT",
        "size_label":"Размер",
        "try_hash_search":"Можно попробовать найти этот файл в базе VirusTotal по хешу — если кто-то уже сканировал его раньше, результат появится мгновенно.",
        "downloading_for_hash":"Скачиваю для вычисления хеша...",
        "not_in_vt_db":"Файл не найден в базе VirusTotal",
        "search_in_vt":"🔍 Искать в базе VirusTotal",
        "no_search_results":"Ничего не найдено по запросу: {}",
        "size_limit_hint":"лимит 32 МБ",
    }

    def __init__(self):
        self.config=loader.ModuleConfig(
            loader.ConfigValue('api_keys','','VirusTotal API keys (comma-separated)',validator=loader.validators.Hidden()),
            loader.ConfigValue('max_wait_time',300,'Maximum wait time',validator=loader.validators.Integer(minimum=60,maximum=600)),
            loader.ConfigValue('poll_interval',10,'Polling interval',validator=loader.validators.Integer(minimum=5,maximum=10)),
            loader.ConfigValue('save_history',True,'Save scan history',validator=loader.validators.Boolean()),
            loader.ConfigValue('max_history_items',10,'Max history entries',validator=loader.validators.Integer(minimum=1,maximum=10)),
            loader.ConfigValue('cleanup_interval',3600,'Cleanup interval',validator=loader.validators.Integer(minimum=300,maximum=86400))
        )
        self.history=[]
        self._session=None
        self._cleanup_task=None
        self._result_cache={}
        self._cache_ttl=300
        self._comments_cache={}
        self._comments_cache_ttl=300
        self._comments_cache_max=200
        self._report_cache={}
        self._report_cache_ttl=300
        self._report_cache_max=300
        self._comments_inflight=set()
        self.api_keys=[]
        self.key_status={}
        self.current_key_index=0
        self._request_count=0
        self._request_count_day=None
        self.key_lock=asyncio.Lock()
        self._timeout=aiohttp.ClientTimeout(total=30)
        self._connector=aiohttp.TCPConnector(limit=20)

    def _emoji(self,name:str,premium:bool=True)->str:
        emojis={
            'file':('<emoji document_id=5915834902074364776>☁️</emoji>','☁️'),
            'url':('<emoji document_id=5271604874419647061>🔗</emoji>','🔗'),
            'size':('<emoji document_id=5784891605601225888>📦</emoji>','📦'),
            'time':('<emoji document_id=5382194935057372936>⏱️</emoji>','⏱️'),
            'engines':('<emoji document_id=5195033767969839232>🚀</emoji>','🚀'),
            'scans':('<emoji document_id=5444965061749644170>👥</emoji>','👥'),
            'progress':('<emoji document_id=5386367538735104399>⏳</emoji>','⏳'),
            'refresh':('<emoji document_id=5818740758257077530>🔄</emoji>','🔄'),
            'stats':('<emoji document_id=5231200819986047254>📊</emoji>','📊'),
            'shield':('<emoji document_id=5251203410396458957>🛡</emoji>','🛡'),
            'check':('<emoji document_id=5231012545799666522>🔍</emoji>','🔍'),
            'success':('<emoji document_id=5206607081334906820>✅️</emoji>','✅'),
            'error':('<emoji document_id=5210952531676504517>❌️</emoji>','❌'),
            'warning':('<emoji document_id=5447644880824181073>⚠️</emoji>','⚠️'),
            'danger':('<emoji document_id=5260293700088511294>⛔️</emoji>','⛔'),
            'skull':('<emoji document_id=5370842086658546991>☠️</emoji>','☠️'),
            'history':('<emoji document_id=5197269100878907942>📋</emoji>','📋'),
            'pages':('<emoji document_id=5253742260054409879>📄</emoji>','📄'),
            'hash':('<emoji document_id=5343824560523322473>🔢</emoji>','🔢'),
            'upload':('<emoji document_id=5406745015365943482>⬇️</emoji>','⬇️'),
            'globe':('<emoji document_id=5447410659077661506>🌐</emoji>','🌐'),
            'chart':('<emoji document_id=5244837092042750681>📈</emoji>','📈'),
            'forbidden':('<emoji document_id=5240241223632954241>🚫</emoji>','🚫'),
            'trash':('<emoji document_id=5445267414562389170>🗑</emoji>','🗑'),
            'history_empty':('<emoji document_id=5253742260054409879>✉️</emoji>','✉️'),
            'downloading':('<emoji document_id=5433653135799228968>📥</emoji>','📥'),
            'waiting':('<emoji document_id=5386367538735104399>⏳</emoji>','⏳'),
            'timeout':('<emoji document_id=5382194935057372936>⏰</emoji>','⏰'),
            'not_found':('<emoji document_id=5235750010691271995>❓</emoji>','❓'),
            'left_arrow':('⬅️','⬅️'),
            'right_arrow':('➡️','➡️'),
            'back_arrow':('↩️','↩️'),
            'link':('🔗','🔗'),
            'cancel':('🚫','🚫'),
            'server':('<emoji document_id=5341715473882955310>⚙️</emoji>','⚙️'),
            'quota':('<emoji document_id=5206492775075295242>💔</emoji>','💔'),
            'exhausted':('<emoji document_id=5274099962655816924>❗️</emoji>','❗️'),
            'comment':('<emoji document_id=5443038326535759644>💬</emoji>','💬'),
        }
        return emojis[name][0] if premium else emojis[name][1]

    def _country_flag(self,country_code:str)->str:
        if not country_code or len(country_code)!=2:return '🏳️'
        base=127462
        return chr(base+(ord(country_code[0].upper())-ord('A')))+chr(base+(ord(country_code[1].upper())-ord('A')))

    def _format_size(self,size:int)->str:
        units=[self.strings('bytes'),self.strings('kb'),self.strings('mb'),self.strings('gb')]
        idx=0
        while size>=1024 and idx<len(units)-1:
            size/=1024
            idx+=1
        return f"{size:.1f} {units[idx]}" if idx>0 else f"{size:.0f} {units[0]}"

    def _format_time(self,seconds:int)->str:
        if seconds<60:return f"{seconds} {self.strings('sec')}"
        m,s=divmod(seconds,60)
        return f"{m} {self.strings('min')} {s} {self.strings('sec')}" if s else f"{m} {self.strings('min')}"

    def _get_status(self,stats:ScanStats)->Tuple[str,str]:
        if stats.malicious==0 and stats.suspicious==0:
            return self._emoji('success'),'clean'
        ratio=stats.malicious/stats.total if stats.total>0 else 0
        thresholds=[(0.02,'likely_safe','success'),(0.05,'suspicious','warning'),(0.15,'dangerous','danger')]
        for limit,key,emoji in thresholds:
            if ratio<limit:return self._emoji(emoji),key
        return self._emoji('skull'),'very_dangerous'

    def _get_lang(self)->str:
        try:return self._db.get("hikka.inline","lang","en")
        except Exception:return "en"

    def _refresh_api_keys(self):
        raw_keys=str(self.config['api_keys'] or '')
        new_keys=[k.strip() for k in raw_keys.split(',') if k.strip()]
        if new_keys!=self.api_keys:
            self.api_keys=new_keys
            self.key_status.clear()
            self.current_key_index=0
        return self.api_keys

    async def _get_next_key(self)->Optional[str]:
        async with self.key_lock:
            self._refresh_api_keys()
            if not self.api_keys:return None
            start=self.current_key_index
            for i in range(len(self.api_keys)):
                idx=(start+i)%len(self.api_keys)
                key=self.api_keys[idx]
                if self.key_status.get(key,True):
                    self.current_key_index=(idx+1)%len(self.api_keys)
                    return key
            self.key_status.clear()
            self.current_key_index=0
            return self.api_keys[0] if self.api_keys else None

    async def _mark_key_bad(self,key:str):
        async with self.key_lock:
            self.key_status[key]=False
            logger.warning(f"Key {key[:8]}... marked as bad")

    _error_map={
        InvalidKeyError:('shield','invalid_key_error'),
        QuotaExceededError:('quota','quota_error'),
        RateLimitError:('progress','rate_limit_error'),
        NotFoundError:('check','not_found_error'),
    }

    _key_pattern=re.compile(r'\b[a-fA-F0-9]{32,}\b')

    def _redact(self,text:str)->str:
        try:
            return self._key_pattern.sub(lambda m:m.group(0)[:6]+'…redacted…',text)
        except Exception:
            return text

    def _log_err(self,msg:str,e:Optional[Exception]=None,level:str='error')->None:
        """Log a message, always redacting API keys from the exception text."""
        text=f"{msg}: {self._redact(str(e))}" if e is not None else msg
        getattr(logger,level,logger.error)(text)

    async def _handle_error(self,e:Exception,context:str="",plain:bool=False)->str:
        logger.exception(f"VirusTotal error in {context}: {self._redact(str(e))}")
        em=lambda name:self._emoji(name,not plain)
        if isinstance(e,asyncio.TimeoutError):return self.strings("timeout")
        if isinstance(e,aiohttp.ClientResponseError):
            if e.status==403:return self.strings('invalid_key_error').format(em('shield'))
            if e.status==429:return self.strings('rate_limit_error').format(em('progress'),e.headers.get('Retry-After','60'))
            if e.status==404:return self.strings('not_found_error').format(em('check'))
            if e.status>=500:return self.strings('server_error').format(em('server'),e.status)
        if isinstance(e,aiohttp.ClientError):return self.strings('network_error').format(em('globe'),str(e))
        for err,(emoji,key) in self._error_map.items():
            if isinstance(e,err):return self.strings(key).format(em(emoji))
        if isinstance(e,VirusTotalError):
            if str(e)=="No API keys available":return f"{em('forbidden')} {self.strings('quota_no_keys')}"
            return self.strings('all_keys_exhausted').format(em('exhausted'))
        return self.strings("error").format(str(e))

    async def _check_api_response(self,data:dict)->Optional[Exception]:
        if not data or 'error' not in data:return None
        m=data['error'].get('message','').lower()
        if 'quota' in m or 'exceeded' in m:return QuotaExceededError(m)
        if 'key' in m:return InvalidKeyError(m)
        if 'rate' in m or 'too many' in m:return RateLimitError(m)
        if 'not found' in m:return NotFoundError(m)
        return VirusTotalError(m)

    async def _request(self,method:str,url:str,**kwargs)->Optional[Dict]:
        today=datetime.now(timezone.utc).date()
        if self._request_count_day!=today:
            self._request_count_day=today
            self._request_count=0
        if not self._session or self._session.closed:
            if self._connector is None or self._connector.closed:
                self._connector=aiohttp.TCPConnector(limit=20)
            self._session=aiohttp.ClientSession(timeout=self._timeout,connector=self._connector)
        max_attempts,base_delay,max_delay=3,2,60
        last_error=None
        for attempt in range(max_attempts):
            api_key=await self._get_next_key()
            if not api_key:raise VirusTotalError("No API keys available")
            req_kwargs={**kwargs,"headers":{**kwargs.get("headers",{}),"x-apikey":api_key}}
            try:
                async with self._session.request(method,url,**req_kwargs) as resp:
                    if resp.status==429:
                        await self._mark_key_bad(api_key)
                        has_other_key=any(self.key_status.get(k,True) for k in self.api_keys if k!=api_key)
                        if not has_other_key:
                            delay=int(resp.headers.get('Retry-After',min(base_delay*2**attempt,max_delay)))
                            await asyncio.sleep(delay)
                        continue
                    if resp.status==403:
                        await self._mark_key_bad(api_key)
                        raise InvalidKeyError("Invalid API key (masked)")
                    try:data=await resp.json()
                    except Exception:
                        logger.debug('Failed to parse JSON response')
                        data=None
                    if data:
                        error=await self._check_api_response(data)
                        if error:
                            if isinstance(error,(InvalidKeyError,QuotaExceededError)):await self._mark_key_bad(api_key)
                            raise error
                    if resp.status!=200:
                        if resp.status>=500 and attempt<max_attempts-1:
                            await asyncio.sleep(min(base_delay*2**attempt,max_delay))
                            continue
                        return None
                    self._request_count+=1
                    return data
            except (aiohttp.ClientError,asyncio.TimeoutError) as e:
                last_error=e
                if attempt==max_attempts-1:break
                await asyncio.sleep(min(base_delay*2**attempt,max_delay))
            except (InvalidKeyError,QuotaExceededError) as e:
                last_error=e
                continue
            except Exception as e:
                last_error=e
                break
        if isinstance(last_error, (InvalidKeyError, QuotaExceededError)):
            raise VirusTotalError("All API keys exhausted") from last_error
        elif last_error:
            raise last_error
        raise VirusTotalError("All API keys exhausted")

    async def upload_file(self,filename:str,file_bytes:bytes)->Optional[str]:
        data=aiohttp.FormData()
        data.add_field('file',file_bytes,filename=filename)
        try:
            r=await self._request('POST','https://www.virustotal.com/api/v3/files',data=data)
            return r.get('data',{}).get('id') if r else None
        except Exception as e:self._log_err("Upload failed",e);return None

    async def get_overall_quotas(self,api_key:str)->Optional[Dict]:
        if not self._session or self._session.closed:
            if self._connector is None or self._connector.closed:
                self._connector=aiohttp.TCPConnector(limit=20)
            self._session=aiohttp.ClientSession(timeout=self._timeout,connector=self._connector)
        url=f'https://www.virustotal.com/api/v3/users/{api_key}/overall_quotas'
        max_attempts,base_delay,max_delay=3,2,20
        for attempt in range(max_attempts):
            try:
                async with self._session.request('GET',url,headers={'x-apikey':api_key},timeout=self._timeout) as resp:
                    if resp.status==429:
                        delay=int(resp.headers.get('Retry-After',min(base_delay*2**attempt,max_delay)))
                        if attempt<max_attempts-1:
                            await asyncio.sleep(delay)
                            continue
                        return None
                    if resp.status>=500 and attempt<max_attempts-1:
                        await asyncio.sleep(min(base_delay*2**attempt,max_delay))
                        continue
                    if resp.status!=200:return None
                    return await resp.json()
            except (aiohttp.ClientError,asyncio.TimeoutError) as e:
                if attempt<max_attempts-1:
                    await asyncio.sleep(min(base_delay*2**attempt,max_delay))
                    continue
                logger.debug(f"Quota fetch failed: {self._redact(str(e))}")
                return None
        return None

    async def get_analysis(self,analysis_id:str)->Optional[Dict]:
        try:return await self._request('GET',f'https://www.virustotal.com/api/v3/analyses/{analysis_id}')
        except Exception as e:self._log_err("Get analysis failed",e);return None

    async def _cached_report(self,cache_key:tuple,fetch,force:bool=False)->Optional[Dict]:
        if not force:
            cached=self._report_cache.get(cache_key)
            if cached:
                resp,ts=cached
                if time.time()-ts<self._report_cache_ttl:
                    return resp
                self._report_cache.pop(cache_key,None)
        resp=await fetch()
        if resp is not None:
            if len(self._report_cache)>=self._report_cache_max:
                oldest_key=min(self._report_cache,key=lambda k:self._report_cache[k][1])
                self._report_cache.pop(oldest_key,None)
            self._report_cache[cache_key]=(resp,time.time())
        return resp

    async def get_file_report(self,file_hash:str,force:bool=False)->Optional[Dict]:
        async def fetch():
            try:return await self._request('GET',f'https://www.virustotal.com/api/v3/files/{file_hash}')
            except NotFoundError:logger.debug(f"File hash not found in VT: {file_hash[:16]}...");return None
            except Exception as e:self._log_err("Get file report failed",e);return None
        return await self._cached_report(('file',file_hash),fetch,force)

    async def get_url_report(self,url_id:str,force:bool=False)->Optional[Dict]:
        async def fetch():
            try:return await self._request('GET',f'https://www.virustotal.com/api/v3/urls/{url_id}')
            except Exception as e:self._log_err("Get URL report failed",e);return None
        return await self._cached_report(('url',url_id),fetch,force)

    async def scan_url(self,url:str)->Optional[Dict]:
        data=aiohttp.FormData()
        data.add_field('url',url)
        try:return await self._request('POST','https://www.virustotal.com/api/v3/urls',data=data)
        except Exception as e:self._log_err("Scan URL failed",e);return None

    async def get_ip_report(self,ip:str,force:bool=False)->Optional[Dict]:
        async def fetch():
            try:return await self._request('GET',f'https://www.virustotal.com/api/v3/ip_addresses/{ip}')
            except Exception as e:self._log_err("Get IP report failed",e);return None
        return await self._cached_report(('ip',ip),fetch,force)

    async def get_domain_report(self,domain:str,force:bool=False)->Optional[Dict]:
        async def fetch():
            try:return await self._request('GET',f'https://www.virustotal.com/api/v3/domains/{domain}')
            except Exception as e:self._log_err("Get domain report failed",e);return None
        return await self._cached_report(('domain',domain),fetch,force)

    _comment_paths={'file':'files','url':'urls','domain':'domains','ip':'ip_addresses'}

    def _comments_endpoint(self,scan_type:str,item_id:str)->Optional[str]:
        p=self._comment_paths.get(scan_type)
        return f'https://www.virustotal.com/api/v3/{p}/{item_id}/comments' if p else None

    async def post_comment(self,scan_type:str,item_id:str,text:str)->Optional[Dict]:
        endpoint=self._comments_endpoint(scan_type,item_id)
        if not endpoint:return None
        payload={"data":{"type":"comment","attributes":{"text":text}}}
        return await self._request('POST',endpoint,json=payload)

    async def delete_comment(self,comment_id:str)->None:
        await self._request('DELETE',f'https://www.virustotal.com/api/v3/comments/{comment_id}')

    async def get_comments(self,scan_type:str,item_id:str,cursor:Optional[str]=None)->Optional[Dict]:
        endpoint=self._comments_endpoint(scan_type,item_id)
        if not endpoint:return None
        params={'limit':COMMENTS_PER_PAGE,'relationships':'author'}
        if cursor:params['cursor']=cursor
        try:return await self._request('GET',endpoint,params=params)
        except NotFoundError:return None

    async def get_comments_cached(self,scan_type:str,item_id:str,cursor:Optional[str]=None)->Tuple[Optional[Dict],bool]:
        key=(scan_type,item_id,cursor)
        cached=self._comments_cache.get(key)
        if cached:
            resp,ts=cached
            if time.time()-ts<self._comments_cache_ttl:
                return resp,False
            self._comments_cache.pop(key,None)
        resp=await self.get_comments(scan_type,item_id,cursor)
        if resp is not None:
            if len(self._comments_cache)>=self._comments_cache_max:
                oldest_key=min(self._comments_cache,key=lambda k:self._comments_cache[k][1])
                self._comments_cache.pop(oldest_key,None)
            self._comments_cache[key]=(resp,time.time())
        return resp,True

    def _is_domain(self,s:str)->bool:
        if '/' in s or ':' in s or '@' in s:return False
        try:
            encoded=s.encode('idna').decode('ascii')
        except Exception:
            encoded=s
        pattern=r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern,encoded))

    def _is_valid_ip(self,s:str)->bool:
        try:ipaddress.ip_address(s);return True
        except ValueError:return False

    def _validate_url(self,url:str)->Optional[str]:
        if re.match(r'^[a-z][a-z0-9+\-.]*://',url,re.IGNORECASE):
            if not url.startswith(('http://','https://')):
                return None
        else:
            url='https://'+url
        try:
            r=urlparse(url)
            if r.scheme in ('http','https') and r.netloc:
                return url
        except Exception:
            logger.debug('URL parse failed: %s', url)
        return None

    def _extract_stats(self,data:Dict,scan_type:str)->ScanStats:
        stats=ScanStats()
        attrs=data.get('data',{}).get('attributes',{})
        last_stats=attrs.get('last_analysis_stats',{})
        if last_stats:
            stats.malicious=last_stats.get('malicious',0)
            stats.suspicious=last_stats.get('suspicious',0)
            stats.harmless=last_stats.get('harmless',0)
            stats.undetected=last_stats.get('undetected',0)
        else:
            for r in attrs.get('last_analysis_results',{}).values():
                cat=r.get('category','')
                if cat=='malicious':stats.malicious+=1
                elif cat=='suspicious':stats.suspicious+=1
                elif cat=='harmless':stats.harmless+=1
                else:stats.undetected+=1
        return stats

    async def _poll_analysis(self,analysis_id:str)->Optional[Dict]:
        try:return await asyncio.wait_for(self._poll_loop(analysis_id),timeout=self.config['max_wait_time'])
        except asyncio.TimeoutError:return None

    async def _poll_loop(self,analysis_id:str)->Optional[Dict]:
        for d in[2,3,5,8,13,21]:
            r=await self.get_analysis(analysis_id)
            if r and r.get('data',{}).get('attributes',{}).get('status')=='completed':return r
            await asyncio.sleep(d)
        attempts=0
        while attempts<30:
            r=await self.get_analysis(analysis_id)
            if not r:return None
            if r.get('data',{}).get('attributes',{}).get('status')=='completed':return r
            await asyncio.sleep(self.config['poll_interval'])
            attempts+=1
        return None

    def _format_result_info(self,scan_type:str,item_id:str,data:dict,**kwargs)->Tuple[str,str,ScanStats]:
        stats=self._extract_stats(data,'url' if scan_type in['url','ip'] else scan_type)
        t=stats.total
        attrs_top=data.get('data',{}).get('attributes',{})
        if scan_type in('ip','domain'):
            votes=attrs_top.get('total_votes',{})
            pop=votes.get('harmless',0)+votes.get('malicious',0)
        else:
            pop=attrs_top.get('times_submitted',0)
        st=kwargs.get('scan_time',0)
        url=kwargs.get('url','')
        if scan_type=='file':
            is_hash=kwargs.get('is_hash',False)
            name=kwargs.get('name') or f"{self.strings('hash')}: {item_id[:16]}..."
            sz=kwargs.get('file_size',0)
            lbl=self.strings('hash') if is_hash else self.strings('file')
            info=[f"• {self._emoji('file')} <b>{lbl}:</b> <code>{name}</code>"]
            if sz:info.append(f"• {self._emoji('size')} <code>{self._format_size(sz)}</code>")
            info+=[f"• {self._emoji('time')} <code>{self._format_time(st)}</code>",f"• {self._emoji('engines')} <code>{t} {self.strings('engines')}</code>",f"• {self._emoji('scans')} <code>{pop} {self.strings('scans')}</code>"]
            vt_url=f"https://www.virustotal.com/gui/file/{item_id}"
        elif scan_type=='ip':
            a=data.get('data',{}).get('attributes',{})
            cc=a.get('country','')
            ao=a.get('as_owner','')
            asn=a.get('asn','')
            info=[f"• {self._emoji('globe')} <b>{self.strings('ip_address')}:</b> <code>{url}</code>",f"• {self._country_flag(cc)} <b>{self.strings('country')}:</b> <code>{cc or self.strings('unknown')}</code>"]
            if ao:info.append(f"• {self._emoji('stats')} <b>{self.strings('asn')}:</b> <code>{asn} ({ao})</code>")
            else:info.append(f"• {self._emoji('stats')} <b>{self.strings('asn')}:</b> <code>{asn or self.strings('unknown')}</code>")
            info+=[f"• {self._emoji('time')} <code>{self._format_time(st)}</code>",f"• {self._emoji('engines')} <code>{t} {self.strings('engines')}</code>",f"• {self._emoji('scans')} <code>{pop} {self.strings('scans')}</code>"]
            vt_url=f"https://www.virustotal.com/gui/ip-address/{item_id}"
        elif scan_type=='domain':
            a=data.get('data',{}).get('attributes',{})
            rep=a.get('reputation',0)
            cats=a.get('categories',{})
            cat_str=', '.join(set(cats.values()))[:50] if cats else self.strings('unknown')
            rep_icon='✅' if rep>=0 else '⚠️' if rep>=-10 else '🚫'
            info=[
                f"• {self._emoji('globe')} <b>{self.strings('domain')}:</b> <code>{item_id}</code>",
                *([ f"• {rep_icon} <b>{self.strings('reputation')}:</b> <code>{rep}</code>" ] if rep != 0 else []),
                f"• {self._emoji('stats')} <b>{self.strings('categories')}:</b> <code>{cat_str}</code>",
                f"• {self._emoji('time')} <code>{self._format_time(st)}</code>",
                f"• {self._emoji('engines')} <code>{t} {self.strings('engines')}</code>",
                f"• {self._emoji('scans')} <code>{pop} {self.strings('scans')}</code>",
            ]
            vt_url=f"https://www.virustotal.com/gui/domain/{item_id}"
        else:
            d=urlparse(url).netloc
            info=[f"• {self._emoji('url')} <b>{self.strings('url')}:</b> <code>{url[:40]+'...' if len(url)>40 else url}</code>",f"• {self._emoji('globe')} <b>{self.strings('domain')}:</b> <code>{d}</code>",f"• {self._emoji('time')} <code>{self._format_time(st)}</code>",f"• {self._emoji('engines')} <code>{t} {self.strings('engines')}</code>",f"• {self._emoji('scans')} <code>{pop} {self.strings('scans')}</code>"]
            vt_url=f"https://www.virustotal.com/gui/url/{item_id}"
        return "\n".join(info),vt_url,stats

    def _result_buttons(self,vt_url:str,msg_id:int,scan_type:str=''):
        row1=[{"text":f"{self._emoji('link',False)} {self.strings('view_report')}","url":vt_url},{"text":f"{self._emoji('check',False)} {self.strings('comments')}","callback":self._comments_cb,"args":(msg_id,)}]
        row2=[]
        row2.append({"text":f"{self._emoji('check',False)} {self.strings('write_review')}","input":self.strings('review_prompt'),"handler":self._write_review_input,"args":(msg_id,)})
        row2.append({"text":f"{self._emoji('history',False)} {self.strings('history')}","callback":self._history_cb,"args":(1,msg_id)})
        return[row1,row2]

    def _save_to_history(self,entry:HistoryEntry):
        if not self.config['save_history']:return
        self.history.insert(0,entry)
        if len(self.history)>self.config['max_history_items']:self.history=self.history[:self.config['max_history_items']]
        self._db.set(__name__,'history',[{'item_id':e.item_id,'timestamp':e.timestamp.isoformat(),'scan_type':e.scan_type,'name':e.name,'url':e.url,'as_owner':e.as_owner,'country_code':e.country_code,'stats':{'malicious':e.stats.malicious,'suspicious':e.stats.suspicious,'harmless':e.stats.harmless,'undetected':e.stats.undetected},'raw_result':e.raw_result} for e in self.history])

    def _load_history(self):
        self.history=[]
        for i in self._db.get(__name__,'history',[]):
            try:self.history.append(HistoryEntry(item_id=i['item_id'],timestamp=datetime.fromisoformat(i['timestamp']),scan_type=i['scan_type'],name=i.get('name'),url=i.get('url'),as_owner=i.get('as_owner'),country_code=i.get('country_code'),stats=ScanStats(**i.get('stats',{})),raw_result=i.get('raw_result',{})))
            except Exception as e:self._log_err("Failed to load history entry",e,level='warning')

    async def client_ready(self,client,db):
        self._client=client
        self._db=db
        self._refresh_api_keys()
        if self.api_keys:logger.info(f"Loaded {len(self.api_keys)} API key(s)")
        else:logger.warning("No API keys loaded from config!")
        self.key_status.clear()
        self._load_history()
        self._cleanup_task=asyncio.create_task(self._cleanup_loop())
        self._comments_cleanup_task=asyncio.create_task(self._comments_cleanup_loop())

    async def on_unload(self):
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        if getattr(self,'_comments_cleanup_task',None):
            self._comments_cleanup_task.cancel()
            try:
                await self._comments_cleanup_task
            except asyncio.CancelledError:
                pass
        if self._session and not self._session.closed:await self._session.close()
        self._result_cache.clear()
        self._comments_cache.clear()

    async def _comments_cleanup_loop(self):
        while True:
            await asyncio.sleep(self._comments_cache_ttl)
            t=time.time()
            expired_c=[k for k,(_,ts) in self._comments_cache.items() if t-ts>self._comments_cache_ttl]
            for k in expired_c:
                self._comments_cache.pop(k,None)

    async def _cleanup_loop(self):
        while True:
            await asyncio.sleep(self.config['cleanup_interval'])
            t=time.time()
            expired=[k for k,(_,_,ts) in self._result_cache.items() if t-ts>self._cache_ttl]
            for k in expired:
                self._result_cache.pop(k,None)
            for k in list((self._db.get(__name__) or {}).keys()):
                if k.startswith('result_'):
                    data=self._db.get(__name__,k)
                    if data and isinstance(data,dict) and 'timestamp' in data:
                        if t-data['timestamp']>self._cache_ttl:
                            self._db.set(__name__,k,None)
                    else:
                        self._db.set(__name__,k,None)
            
            if self.history:
                now_utc = datetime.now(timezone.utc)
                valid_entries = []
                history_changed = False
                for en in self.history:
                    try:
                        ts = en.timestamp.replace(tzinfo=timezone.utc) if hasattr(en.timestamp, 'replace') else en.timestamp
                        if (now_utc - ts).total_seconds() < 30 * 86400:
                            valid_entries.append(en)
                        else:
                            history_changed = True
                    except Exception:
                        valid_entries.append(en)
                if history_changed:
                    self.history = valid_entries
                    self._db.set(__name__, 'history', [
                        {
                            'item_id': e.item_id,
                            'timestamp': e.timestamp.isoformat() if hasattr(e.timestamp, 'isoformat') else e.timestamp,
                            'scan_type': e.scan_type,
                            'name': e.name,
                            'url': e.url,
                            'as_owner': getattr(e, 'as_owner', None),
                            'country_code': getattr(e, 'country_code', None),
                            'stats': {
                                'malicious': e.stats.malicious,
                                'suspicious': e.stats.suspicious,
                                'harmless': e.stats.harmless,
                                'undetected': e.stats.undetected,
                                'total': e.stats.total
                            },
                            'raw_result': getattr(e, 'raw_result', None)
                        } for e in self.history
                    ])

    async def _show_results(self,msg,item_id:str,data:dict,scan_type:str,orig_msg=None,**kwargs):
        try:
            info,vt_url,stats=self._format_result_info(scan_type,item_id,data,**kwargs)
            se,sk=self._get_status(stats)
            total=stats.total or 1
            safe=round((stats.harmless+stats.undetected)/total*100,1)
            if self.config['save_history']:
                if scan_type=='ip':
                    e=HistoryEntry(item_id=item_id,timestamp=datetime.now(timezone.utc),scan_type=scan_type,name=kwargs.get('url'),url=kwargs.get('url'),as_owner=data.get('data',{}).get('attributes',{}).get('as_owner'),country_code=data.get('data',{}).get('attributes',{}).get('country'),stats=stats,raw_result=data)
                else:
                    hn=kwargs.get('history_name') or kwargs.get('name') or f"{self.strings('hash')}: {item_id[:16]}..."
                    e=HistoryEntry(item_id=item_id,timestamp=datetime.now(timezone.utc),scan_type=scan_type,name=hn,url=kwargs.get('url'),stats=stats,raw_result=data)
                self._save_to_history(e)
            t=(f"<b>{self._emoji('shield')} {self.strings('results_title')}</b>\n━━━━━━━━━━━━━━━━━━━\n<blockquote expandable>{info}</blockquote>\n"
               f"<blockquote expandable>{se} <b>{self.strings('status')}:</b> <code>{self.strings(sk)} ({safe}% {self.strings('safe')})</code>\n"
               f"{se} <b>{self.strings('threats')}:</b> <code>{stats.malicious} {self.strings('detected')}</code></blockquote>\n"
               f"<blockquote expandable><b>{self._emoji('chart')} {self.strings('results')}:</b>\n"
               f"🚫<code>{stats.malicious}/{stats.total} ({round(stats.malicious/total*100,1)}%)│{self.strings('malicious')}</code>\n"
               f"⚠️<code>{stats.suspicious}/{stats.total} ({round(stats.suspicious/total*100,1)}%)│{self.strings('suspicious')}</code>\n"
               f"{self._emoji('success')}<code>{stats.harmless}/{stats.total} ({round(stats.harmless/total*100,1)}%)│{self.strings('harmless')}</code>\n"
               f"👁️<code>{stats.undetected}/{stats.total} ({round(stats.undetected/total*100,1)}%)│{self.strings('undetected')}</code></blockquote>")
            mid=msg.id if hasattr(msg,'id') else id(msg)
            self._result_cache[mid]=(t,vt_url,time.time())
            chat_id=getattr(orig_msg,'chat_id',None) if orig_msg is not None else None
            if chat_id is None:chat_id=getattr(msg,'chat_id',None)
            disp_name=kwargs.get('history_name') or kwargs.get('name') or kwargs.get('url') or item_id
            disp_name=str(disp_name)
            if len(disp_name)>40:disp_name=disp_name[:40]+'...'
            self._db.set(__name__,f"result_{mid}",{'text':t,'vt_url':vt_url,'timestamp':time.time(),'raw_result':data,'scan_type':scan_type,'chat_id':chat_id,'name':disp_name})
            form_target=orig_msg if orig_msg is not None else msg
            if hasattr(form_target,'inline_message_id') or (hasattr(form_target,'__class__') and 'InlineCall' in type(form_target).__name__):
                await form_target.edit(text=t,reply_markup=self._result_buttons(vt_url,mid,scan_type))
            else:
                await self.inline.form(text=t,message=form_target,reply_markup=self._result_buttons(vt_url,mid,scan_type),ttl=300)
        except Exception as e:
            await utils.answer(msg,await self._handle_error(e,"show_results"))

    def _relative_time(self,seconds:int)->str:
        is_ru = self.strings('clear_history') == "Очистить"
        if seconds < 45:
            return "только что" if is_ru else "just now"
        elif seconds < 3600:
            minutes = seconds // 60
            if is_ru:
                return f"{minutes} мин. назад"
            else:
                return f"{minutes} min. ago" if minutes > 1 else "1 min. ago"
        elif seconds < 86400:
            hours = seconds // 3600
            if is_ru:
                if hours == 1: return "1 час назад"
                elif 2 <= hours <= 4: return f"{hours} часа назад"
                else: return f"{hours} ч. назад"
            else:
                return f"{hours} hours ago" if hours > 1 else "1 hour ago"
        elif seconds < 172800:
            return "вчера" if is_ru else "yesterday"
        else:
            days = seconds // 86400
            if is_ru:
                if days == 2: return "2 дня назад"
                elif 3 <= days <= 4: return f"{days} дня назад"
                else: return f"{days} дней назад"
            else:
                return f"{days} days ago"

    async def _history_cb(self,call,page:int=1,return_id:Optional[int]=None,query:Optional[str]=None):
        if not self.history:
            t=f"{self._emoji('history_empty')} <b>{self.strings('history_empty')}</b>"
            if hasattr(call,'inline_message_id'):await call.edit(text=t,reply_markup=None)
            else:await call.edit(text=t)
            return
            
        items = self.history
        if query:
            q = query.lower()
            items = [
                en for en in self.history 
                if (en.name and q in en.name.lower()) or (en.url and q in en.url.lower()) or (en.item_id and q in en.item_id.lower())
            ]
            if not items:
                t=f"<b>{self._emoji('check')} {self.strings('no_search_results').format(query)}</b>"
                if hasattr(call,'inline_message_id'):await call.edit(text=t,reply_markup=None)
                else:await utils.answer(call, t)
                return

        t=len(items)
        p=(t+HISTORY_PER_PAGE-1)//HISTORY_PER_PAGE
        page=max(1,min(page,p))
        s=(page-1)*HISTORY_PER_PAGE
        e=items[s:s+HISTORY_PER_PAGE]
        l=[f"<b>{self._emoji('history')} {self.strings('history_title')}</b>","━━━━━━━━━━━━━━━━━━━",f"<b>{self._emoji('pages')} {self.strings('entries')} {s+1}-{min(s+HISTORY_PER_PAGE,t)} {self.strings('of')} {t}</b>"]
        for i,en in enumerate(e,1):
            try:
                if hasattr(en.timestamp, 'timestamp'):
                    seconds = int((datetime.now(timezone.utc) - en.timestamp.replace(tzinfo=timezone.utc)).total_seconds())
                else:
                    seconds = int(time.time() - float(en.timestamp))
            except Exception:
                seconds = 0

            dt = self._relative_time(seconds)

            se,_=self._get_status(en.stats)
            if en.scan_type=='file':
                n=(en.name or self.strings('unknown'))[:25]+('...' if en.name and len(en.name)>25 else '')
                b=f"<b>{i}.</b> {self._emoji('file')} <b>{n}</b>\n   {self._emoji('hash')} <code>{en.item_id}</code>\n   {self._emoji('time')} <code>{dt}</code>\n   {se} <code>{en.stats.malicious}/{en.stats.total}</code>"
            elif en.scan_type=='ip':
                fg=self._country_flag(en.country_code) if en.country_code else '🏳️'
                n=en.as_owner or en.name or self.strings('unknown')
                b=f"<b>{i}.</b> {fg} <b>{n}</b>\n   {self._emoji('url')} <code>{en.url or en.name}</code>\n   {self._emoji('time')} <code>{dt}</code>\n   {se} <code>{en.stats.malicious}/{en.stats.total}</code>"
            elif en.scan_type=='domain':
                b=f"<b>{i}.</b> {self._emoji('globe')} <b>{en.name or en.item_id}</b>\n   {self._emoji('url')} <code>{en.item_id}</code>\n   {self._emoji('time')} <code>{dt}</code>\n   {se} <code>{en.stats.malicious}/{en.stats.total}</code>"
            else:
                b=f"<b>{i}.</b> {self._emoji('globe')} <b>{d}</b>\n   {self._emoji('url')} <code>{en.url or self.strings('unknown')}</code>\n   {self._emoji('time')} <code>{dt}</code>\n   {se} <code>{en.stats.malicious}/{en.stats.total}</code>"
            l.append(f"<blockquote expandable>{b}</blockquote>")
        l.append(f"\n<b>{self.strings('history_entries')}: {t}/{self.config['max_history_items']}</b>")
        txt='\n'.join(l)
        btns=[]
        nav=[]
        if page>1:nav.append({"text":f"{self._emoji('left_arrow',False)} {self.strings('prev_page')}","callback":self._history_cb,"args":(page-1,return_id,query)})
        if page<p:nav.append({"text":f"{self.strings('next_page')} {self._emoji('right_arrow',False)}","callback":self._history_cb,"args":(page+1,return_id,query)})
        if nav:btns.append(nav)
        a=[{"text":f"{self._emoji('trash',False)} {self.strings('clear_history')}","callback":self._clear_confirm_cb},{"text":f"{self._emoji('refresh',False)} {self.strings('refresh')}","callback":self._history_cb,"args":(page,return_id,query)}]
        if return_id:a.append({"text":f"{self._emoji('back_arrow',False)} {self.strings('back_to_results')}","callback":self._return_cb,"args":(return_id,)})
        btns.append(a)
        if hasattr(call,'inline_message_id'):await call.edit(text=txt,reply_markup=btns)
        else:await self.inline.form(text=txt,message=call,reply_markup=btns,ttl=300)

    async def _clear_confirm_cb(self,call):
        if not self.history:return await call.answer(self.strings('history_empty'),show_alert=True)
        t=f"<b>{self._emoji('warning')} {self.strings('confirm_clear')}</b>\n━━━━━━━━━━━━━━━━━━━\n\n<blockquote expandable>{self.strings('clear_history_confirm')}\n<b>{self.strings('entries')}: {len(self.history)}</b></blockquote>"
        await call.edit(text=t,reply_markup=[[{"text":f"{self._emoji('success',False)} {self.strings('yes_clear')}","callback":self._clear_cb},{"text":self.strings('cancel'),"callback":self._cancel_cb}]])

    async def _clear_cb(self,call):
        c=len(self.history)
        self.history.clear()
        self._db.set(__name__,'history',[])
        await call.edit(text=f"<b>{self._emoji('success')} {self.strings('history_cleared')}! {self.strings('deleted_entries')}: {c}</b>",reply_markup=None)

    async def _cancel_cb(self,call):await self._history_cb(call,1)

    async def _render_comments_page(self,call,msg_id:int,scan_type:str,item_id:str,cursor:Optional[str],offset:int,history:tuple,resp:Optional[Dict]):
        d=self._db.get(__name__,f"result_{msg_id}")
        own_id=(d or {}).get('own_comment_id')
        comments=(resp or {}).get('data') or []
        comments=sorted(
            comments,
            key=lambda c:(c.get('attributes',{}).get('votes',{}).get('positive',0)
                          -c.get('attributes',{}).get('votes',{}).get('negative',0)),
            reverse=True,
        )
        pos=neg=0
        for c in comments:
            votes=c.get('attributes',{}).get('votes',{})
            pos+=votes.get('positive',0)
            neg+=votes.get('negative',0)
        shown_to=offset+len(comments)
        lines=[f"<b>{self._emoji('check')} {self.strings('comments_title')}</b>","━━━━━━━━━━━━━━━━━━━"]
        total_count=(resp or {}).get('meta',{}).get('count')
        if total_count is not None:
            lines.append(f"<i>{self.strings('comments_total').format(total_count)}</i>")
        for i,c in enumerate(comments,offset+1):
            attrs=c.get('attributes',{})
            text=html.escape((attrs.get('text') or '').strip())
            if len(text)>300:text=text[:300]+'…'
            author=html.escape(c.get('relationships',{}).get('author',{}).get('data',{}).get('id') or self.strings('unknown'))
            ts=attrs.get('date')
            dt=self._relative_time(int(time.time()-ts)) if ts else ''
            meta=f"{author} · <code>{dt}</code>" if dt else author
            c_votes=attrs.get('votes',{})
            c_pos=c_votes.get('positive',0)
            c_neg=c_votes.get('negative',0)
            vote_str=self.strings('comment_votes').format(c_pos,c_neg)
            mark=f" <i>({self.strings('you')})</i>" if own_id and c.get('id')==own_id else ""
            lines.append(f"<blockquote expandable><b>{i}.{mark} {meta}</b>\n{text}\n{vote_str}</blockquote>")
        votes_line=self.strings('comment_votes').format(pos,neg)
        lines.append(f"\n<b>{votes_line}</b>")
        txt='\n'.join(lines)
        next_cursor=(resp or {}).get('meta',{}).get('cursor')
        nav=[]
        if history:
            prev_cursor=history[-1]
            new_history=history[:-1]
            nav.append({"text":f"{self._emoji('left_arrow',False)} {self.strings('prev_page')}","callback":self._comments_cb,"args":(msg_id,prev_cursor,max(0,offset-COMMENTS_PER_PAGE),new_history)})
        if next_cursor:
            nav.append({"text":f"{self.strings('next_page')} {self._emoji('right_arrow',False)}","callback":self._comments_cb,"args":(msg_id,next_cursor,shown_to,history+(cursor,))})
        btns=[]
        if nav:btns.append(nav)
        extra=[]
        if offset>0:
            extra.append({"text":f"{self._emoji('back_arrow',False)} {self.strings('to_start')}","callback":self._comments_cb,"args":(msg_id,None,0,())})
        if next_cursor:
            extra.append({"text":f"{self.strings('to_end')} {self._emoji('right_arrow',False)}","callback":self._comments_end_cb,"args":(msg_id,next_cursor,shown_to,history+(cursor,))})
        extra.append({"text":f"{self._emoji('back_arrow',False)} {self.strings('back_to_results')}","callback":self._return_cb,"args":(msg_id,)})
        btns.append(extra)
        await call.edit(text=txt,reply_markup=btns)

    async def _delete_comment_cb(self,call,msg_id:int,comment_id:str):
        try:
            await self.delete_comment(comment_id)
        except Exception as e:
            return await call.answer(await self._handle_error(e,"delete_comment",plain=True),show_alert=True)
        d=self._db.get(__name__,f"result_{msg_id}")
        if d and d.get('own_comment_id')==comment_id:
            rd=dict(d);rd.pop('own_comment_id',None)
            self._db.set(__name__,f"result_{msg_id}",rd)
            scan_type=d.get('scan_type','')
            item_id=d.get('vt_url','').rstrip('/').split('/')[-1]
            self._comments_cache.pop((scan_type,item_id,None),None)
        await call.answer(f"{self._emoji('trash',False)} {self.strings('comment_deleted')}")
        await self._comments_cb(call,msg_id)

    async def _delete_own_review_cb(self,call,msg_id:int,comment_id:str):
        try:
            await self.delete_comment(comment_id)
        except Exception as e:
            return await call.answer(await self._handle_error(e,"delete_comment",plain=True),show_alert=True)
        d=self._db.get(__name__,f"result_{msg_id}")
        if d and d.get('own_comment_id')==comment_id:
            rd=dict(d);rd.pop('own_comment_id',None)
            self._db.set(__name__,f"result_{msg_id}",rd)
            scan_type=d.get('scan_type','')
            item_id=d.get('vt_url','').rstrip('/').split('/')[-1]
            self._comments_cache.pop((scan_type,item_id,None),None)
        txt=f"{self._emoji('trash')} <b>{self.strings('comment_deleted')}</b>"
        await call.edit(text=txt,reply_markup=None)

    async def _comments_cb(self,call,msg_id:int,cursor:Optional[str]=None,offset:int=0,history:tuple=()):
        if msg_id in self._comments_inflight:
            return await call.answer(self.strings('please_wait'))
        self._comments_inflight.add(msg_id)
        try:
            d=self._db.get(__name__,f"result_{msg_id}")
            if not d:
                return await call.answer(self.strings('error').format('Result expired'),show_alert=True)
            vt_url=d.get('vt_url','')
            scan_type=d.get('scan_type','')
            item_id=vt_url.rstrip('/').split('/')[-1]
            try:
                resp,was_fetched=await self.get_comments_cached(scan_type,item_id,cursor)
            except Exception as e:
                return await call.answer(await self._handle_error(e,"comments",plain=True),show_alert=True)
            comments=(resp or {}).get('data') or []
            if not comments and offset==0:
                return await call.answer(self.strings('no_comments'),show_alert=True)
            await self._render_comments_page(call,msg_id,scan_type,item_id,cursor,offset,history,resp)
            if was_fetched:
                await call.answer(self.strings('spent_requests').format(-1))
        finally:
            self._comments_inflight.discard(msg_id)

    async def _comments_end_cb(self,call,msg_id:int,cursor:Optional[str]=None,offset:int=0,history:tuple=()):
        if msg_id in self._comments_inflight:
            return await call.answer(self.strings('please_wait'))
        self._comments_inflight.add(msg_id)
        try:
            d=self._db.get(__name__,f"result_{msg_id}")
            if not d:
                return await call.answer(self.strings('error').format('Result expired'),show_alert=True)
            vt_url=d.get('vt_url','')
            scan_type=d.get('scan_type','')
            item_id=vt_url.rstrip('/').split('/')[-1]
            cur_cursor,cur_offset,cur_history=cursor,offset,history
            resp=None
            hit_limit=False
            spent=0
            prev_resp=prev_cursor=prev_offset=prev_history=None
            for i in range(MAX_JUMP_PAGES):
                try:
                    resp,was_fetched=await self.get_comments_cached(scan_type,item_id,cur_cursor)
                    if was_fetched:spent+=1
                except Exception as e:
                    if i==0:
                        return await call.answer(self.strings('quota_short'),show_alert=True)
                    hit_limit=True
                    resp,cur_cursor,cur_offset,cur_history=prev_resp,prev_cursor,prev_offset,prev_history
                    break
                comments=(resp or {}).get('data') or []
                if not comments:
                    if i==0:
                        return await call.answer(self.strings('no_comments'),show_alert=True)
                    break
                next_cursor=(resp or {}).get('meta',{}).get('cursor')
                if not next_cursor:
                    break
                if i==MAX_JUMP_PAGES-1:
                    hit_limit=True
                    break
                prev_resp,prev_cursor,prev_offset,prev_history=resp,cur_cursor,cur_offset,cur_history
                cur_history=cur_history+(cur_cursor,)
                cur_offset+=len(comments)
                cur_cursor=next_cursor
            await self._render_comments_page(call,msg_id,scan_type,item_id,cur_cursor,cur_offset,cur_history,resp)
            if hit_limit:
                await call.answer(self.strings('jump_limit_hit').format(-spent))
            elif spent>0:
                await call.answer(self.strings('spent_requests').format(-spent))
        finally:
            self._comments_inflight.discard(msg_id)

    async def _return_cb(self,call,msg_id:int):
        if msg_id in self._result_cache:
            t,vu,ts=self._result_cache[msg_id]
            if time.time()-ts<self._cache_ttl:
                d=self._db.get(__name__,f"result_{msg_id}")
                st=d.get('scan_type','') if d else ''
                return await call.edit(text=t,reply_markup=self._result_buttons(vu,msg_id,st))
        d=self._db.get(__name__,f"result_{msg_id}")
        if not d:return await call.answer(self.strings('error').format('Result expired'),show_alert=True) or await call.delete()
        self._result_cache[msg_id]=(d['text'],d['vt_url'],time.time())
        await call.edit(text=d['text'],reply_markup=self._result_buttons(d['vt_url'],msg_id,d.get('scan_type','')))

    async def _write_review_input(self,call,query:str,msg_id:int):
        text=(query or '').strip()
        d=self._db.get(__name__,f"result_{msg_id}")
        if not d:
            try:await call.answer(self.strings('error').format('Result expired'),show_alert=True)
            except Exception:pass
            return
        chat_id=d.get('chat_id')
        if not text:
            if chat_id and self._client:
                try:await self._client.send_message(chat_id,f"<b>{self.strings('review_empty')}</b>",parse_mode='html')
                except Exception:pass
            return
        vt_url=d.get('vt_url','')
        scan_type=d.get('scan_type','')
        item_id=vt_url.rstrip('/').split('/')[-1]
        name=f"<code>{html.escape(d.get('name') or item_id)}</code>"
        try:
            presp=await self.post_comment(scan_type,item_id,text)
            comment_id=(presp or {}).get('data',{}).get('id')
            if comment_id:
                rd=dict(d);rd['own_comment_id']=comment_id
                self._db.set(__name__,f"result_{msg_id}",rd)
            msg=f"{self._emoji('success')} <b>{self.strings('review_posted').format(name)}</b>"
            self._comments_cache.pop((scan_type,item_id,None),None)
            try:
                resp,_=await self.get_comments_cached(scan_type,item_id)
                count=(resp or {}).get('meta',{}).get('count')
            except Exception:
                count=None
            comment_preview=html.escape(text.strip())
            if len(comment_preview)>300:comment_preview=comment_preview[:300]+'…'
            if count is not None:
                msg+=f"\n{self._emoji('comment')} <b>{self.strings('comments')}:</b> <code>{count}</code> - <i>{comment_preview}</i>"
            else:
                msg+=f"\n{self._emoji('comment')} <b>{self.strings('comments')}...</b> - <i>{comment_preview}</i>"
        except Exception as e:
            reason=await self._handle_error(e,"review")
            reason=re.sub(r'</?(?:b|code)>','',reason).split('.')[0].strip()
            msg=f"{self._emoji('error')} <b>{self.strings('review_failed').format(name)}</b> — {reason}"
            comment_id=None
        if chat_id and self._client:
            if comment_id:
                try:
                    await self.inline.form(text=msg,message=chat_id,reply_markup=[[{"text":f"{self._emoji('trash',False)} {self.strings('delete_short')}","callback":self._delete_own_review_cb,"args":(msg_id,comment_id)}]],ttl=300)
                except Exception:
                    try:await self._client.send_message(chat_id,msg,parse_mode='html')
                    except Exception:pass
            else:
                try:await self._client.send_message(chat_id,msg,parse_mode='html')
                except Exception:pass

    @loader.command(ru_doc="[файл/ссылка/айпи/хеш] - просканировать",en_doc="[file/url/IP/hash] - scan")
    async def vt(self,message):
        if not self._refresh_api_keys():return await utils.answer(message,f"{self._emoji('forbidden')} <b>{self.strings('no_key')}</b>")
        r=await message.get_reply_message()
        if r and r.document:
            sz=r.document.size
            if sz>MAX_FILE_SIZE:
                msg_id=r.id
                chat_id=r.chat_id
                sz_str=self._format_size(sz)
                fname=r.file.name or self.strings('file_default')
                hist_match=[e for e in self.history if e.scan_type=='file' and (e.name or '').lower()==fname.lower()]
                if hist_match:
                    best=hist_match[-1]
                    s=time.time()
                    m=await utils.answer(message,f"<b>{self._emoji('check')} {self.strings('checking_cache')}</b>")
                    try:
                        if ex:=await self.get_file_report(best.item_id):
                            return await self._show_results(m,best.item_id,ex,'file',orig_msg=message,name=fname,scan_time=int(time.time()-s),file_size=sz,is_hash=True)
                    except Exception:
                        pass
                txt=(
                    f"<b>{self._emoji('forbidden')} {self.strings('file_too_large')}</b>\n"
                    f"<code>━━━━━━━━━━━━━━━━━━━</code>\n\n"
                    f"📄 <b>{fname}</b>\n"
                    f"📦 {self.strings('size_label')}: <code>{sz_str}</code> ({self.strings('size_limit_hint')})\n\n"
                    f"{self.strings('try_hash_search')}"
                )
                async def _large_file_search_cb(call):
                    await call.edit(text=f"<b>{self._emoji('downloading')} {self.strings('downloading_for_hash')}</b>")
                    s=time.time()
                    try:
                        import io
                        msg=await self._client.get_messages(chat_id,ids=msg_id)
                        buf=io.BytesIO()
                        await msg.download_media(buf)
                        buf.seek(0)
                        fh=hashlib.sha256(buf.read()).hexdigest()
                        del buf
                        await call.edit(text=f"<b>{self._emoji('check')} {self.strings('checking_cache')}</b>")
                        try:
                            if ex:=await self.get_file_report(fh):
                                return await self._show_results(call,fh,ex,'file',name=fname,scan_time=int(time.time()-s),file_size=sz,is_hash=True)
                        except Exception as e:
                            et=await self._handle_error(e,"check_cache")
                            return await call.edit(text=et)
                        await call.edit(text=f"<b>{self._emoji('forbidden')} {self.strings('size_limit')}\n\n🔍 {self.strings('not_in_vt_db')}</b>")
                    except Exception as e:
                        et=await self._handle_error(e,"large_file_hash")
                        return await call.edit(text=et)
                return await self.inline.form(
                    text=txt,
                    message=message,
                    reply_markup=[[{"text":self.strings('search_in_vt'),"callback":_large_file_search_cb}]],
                    ttl=120
                )
            m=await utils.answer(message,f"<b>{self._emoji('downloading')} {self.strings('downloading')}</b>")
            s=time.time()
            try:
                fb=await r.download_media(bytes)
                sz=len(fb)
                if sz>MAX_FILE_SIZE:return await m.edit(f"<b>{self._emoji('forbidden')} {self.strings('size_limit')}</b>")
                fh=hashlib.sha256(fb).hexdigest()
                await m.edit(f"<b>{self._emoji('check')} {self.strings('checking_cache')}</b>")
                try:
                    if ex:=await self.get_file_report(fh):return await self._show_results(m,fh,ex,'file',orig_msg=message,name=r.file.name,scan_time=int(time.time()-s),file_size=sz,is_hash=False)
                except Exception as e:
                    et=await self._handle_error(e,"check_cache")
                    return await m.edit(et)
                await m.edit(f"<b>{self._emoji('upload')} {self.strings('uploading')}</b>")
                try:aid=await self.upload_file(r.file.name or 'file.bin',fb)
                except Exception as e:
                    et=await self._handle_error(e,"upload")
                    return await m.edit(et)
                if not aid:return await m.edit(f"<b>{self._emoji('error')} {self.strings('upload_error')}</b>")
                await m.edit(f"<b>{self._emoji('waiting')} {self.strings('waiting')}</b>")
                try:pr=await self._poll_analysis(aid)
                except Exception as e:
                    et=await self._handle_error(e,"poll")
                    return await m.edit(et)
                if not pr:return await m.edit(f"<b>{self._emoji('timeout')} {self.strings('timeout')}</b>")
                try:fn=await self.get_file_report(fh)
                except Exception as e:
                    et=await self._handle_error(e,"final_report")
                    return await m.edit(et)
                await self._show_results(m,fh,fn or pr,'file',orig_msg=message,name=r.file.name,scan_time=int(time.time()-s),file_size=sz,is_hash=False)
            except Exception as e:
                et=await self._handle_error(e,"file_processing")
                return await m.edit(et)
            return
        t=None
        a=utils.get_args_raw(message)
        if a:t=a.strip()
        if not t and r:
            rt=getattr(r,'raw_text',None) or r.text or ''
            f=re.findall(r'https?://[^\s"\'<>]+',rt)
            t=f[0] if f else (rt.strip().split()[0] if rt.strip() else None)
        if not t:return await utils.answer(message,f"{self._emoji('forbidden')} <b>{self.strings('no_url')}</b>")
        t=t.split('"')[0].split('>')[0].split('<')[0]
        fh=t.lower()
        ht='SHA256' if re.match(r'^[a-f0-9]{64}$',fh) else 'SHA1' if re.match(r'^[a-f0-9]{40}$',fh) else 'MD5' if re.match(r'^[a-f0-9]{32}$',fh) else None
        if ht:
            m=await utils.answer(message,f"<b>{self._emoji('hash')} {self.strings('checking_hash')}</b>")
            s=time.time()
            await m.edit(f"<b>{self._emoji('check')} {self.strings('searching_report').format(ht)}</b>")
            try:r=await self.get_file_report(fh)
            except Exception as e:
                et=await self._handle_error(e,"hash_report")
                return await m.edit(et)
            if r:
                sz=r.get('data',{}).get('attributes',{}).get('size',0)
                fn=None
                try:fn=r.get('data',{}).get('attributes',{}).get('meaningful_name')
                except Exception:logger.debug('Could not get meaningful_name')
                dn=fh[:16]+"..."
                hn=fn or f"{self.strings('hash')}: {fh[:16]}..."
                await self._show_results(m,fh,r,'file',orig_msg=message,name=dn,history_name=hn,scan_time=int(time.time()-s),file_size=sz,is_hash=True)
            else:await m.edit(f"<b>{self._emoji('not_found')} {self.strings('not_found')}</b>")
            return
        if self._is_valid_ip(t):
            m=await utils.answer(message,f"<b>{self._emoji('globe')} {self.strings('checking')} IP {t}...</b>")
            s=time.time()
            try:rp=await self.get_ip_report(t)
            except Exception as e:
                et=await self._handle_error(e,"ip_report")
                return await m.edit(et)
            if rp:await self._show_results(m,t,rp,'ip',orig_msg=message,url=t,scan_time=int(time.time()-s))
            else:await m.edit(f"<b>{self._emoji('not_found')} {self.strings('not_found')}</b>")
            return
        if self._is_domain(t):
            try:t_ascii=t.encode('idna').decode('ascii')
            except Exception:t_ascii=t
            m=await utils.answer(message,f"<b>{self._emoji('globe')} {self.strings('checking_domain')} {t}...</b>")
            s=time.time()
            try:rp=await self.get_domain_report(t_ascii)
            except Exception as e:
                et=await self._handle_error(e,"domain_report")
                return await m.edit(et)
            if rp:await self._show_results(m,t_ascii,rp,'domain',orig_msg=message,url=t,scan_time=int(time.time()-s))
            else:await m.edit(f"<b>{self._emoji('not_found')} {self.strings('not_found')}</b>")
            return
        u=self._validate_url(t)
        if not u:return await utils.answer(message,f"{self._emoji('error')} <b>{self.strings('invalid_url')}</b>")
        m=await utils.answer(message,f"<b>{self._emoji('url')} {self.strings('scanning_url')}</b>")
        s=time.time()
        uid=base64.urlsafe_b64encode(u.encode()).decode().strip('=')
        await m.edit(f"<b>{self._emoji('check')} {self.strings('checking_cache')}</b>")
        try:
            if ex:=await self.get_url_report(uid):return await self._show_results(m,uid,ex,'url',orig_msg=message,url=u,scan_time=int(time.time()-s))
        except Exception as e:
            et=await self._handle_error(e,"url_check")
            return await m.edit(et)
        await m.edit(f"<b>{self._emoji('waiting')} {self.strings('waiting')}</b>")
        try:sc=await self.scan_url(u)
        except Exception as e:
            et=await self._handle_error(e,"url_scan")
            return await m.edit(et)
        if not sc or not (aid:=sc.get('data',{}).get('id')):return await m.edit(f"<b>{self._emoji('error')} {self.strings('scan_error')}</b>")
        try:pr=await self._poll_analysis(aid)
        except Exception as e:
            et=await self._handle_error(e,"url_poll")
            return await m.edit(et)
        if not pr:return await m.edit(f"<b>{self._emoji('timeout')} {self.strings('timeout')}</b>")
        try:fn=await self.get_url_report(uid)
        except Exception as e:
            et=await self._handle_error(e,"url_final")
            return await m.edit(et)
        await self._show_results(m,uid,fn or pr,'url',orig_msg=message,url=u,scan_time=int(time.time()-s))

    @loader.command(ru_doc="[страница/запрос] - показать историю или найти по названию",en_doc="[page/query] - show history or search by name")
    async def vthistory(self,message):
        args=utils.get_args_raw(message)
        page=1
        query=None
        if args:
            try:
                page=int(args)
            except ValueError:
                query=args.strip()
        await self._history_cb(message, page=page, query=query)

    @loader.command(ru_doc=" - очистить историю",en_doc=" - clear history")
    async def vtclear(self,message):
        if not self.history:return await utils.answer(message,f"{self._emoji('history_empty')} <b>{self.strings('history_empty')}</b>")
        c=len(self.history)
        self.history.clear()
        self._db.set(__name__,'history',[])
        await utils.answer(message,f"{self._emoji('trash')} <b>{self.strings('history_cleared')}</b>. {self._emoji('success')} <b>{self.strings('deleted_entries')}: {c}</b>")

    @loader.command(ru_doc=" - статус ключей и квота",en_doc=" - key status and quota")
    async def vtkey(self,message):
        self._refresh_api_keys()
        if not self.api_keys:
            return await utils.answer(message,f"{self._emoji('forbidden')} <b>{self.strings('quota_no_keys')}</b>")
        m=await utils.answer(message,f"{self._emoji('progress')} <b>{self.strings('loading')}</b>")
        total=len(self.api_keys)
        active=sum(1 for k in self.api_keys if self.key_status.get(k,True))
        today=datetime.now(timezone.utc).date()
        local_count=self._request_count if self._request_count_day==today else 0
        used_sum=0
        allowed_sum=0
        got_data=False
        for key in self.api_keys:
            data=await self.get_overall_quotas(key)
            if not data:continue
            d=data.get('data',{}).get('api_requests_daily',{})
            entry=d.get('user') or d
            allowed=entry.get('allowed')
            used=entry.get('used')
            if allowed is None or used is None:continue
            used_sum+=used
            allowed_sum+=allowed
            got_data=True
        text=(
            f"<b>{self._emoji('shield')} {self.strings('quota_title')}</b>\n"
            f"━━━━━━━━━━━━━━━━━━━\n"
            f"{self.strings('quota_active_keys')}: <code>{active}/{total}</code>\n"
        )
        if got_data:
            key_type=self.strings('quota_free') if allowed_sum<=500*total else self.strings('quota_paid')
            text+=f"{self.strings('quota_key_type')}: <code>{key_type}</code>\n"
        text+=f"{self.strings('quota_requests_today')}: <code>{local_count}</code>\n"
        if got_data:
            text+=f"{self.strings('quota_used')}: <code>{used_sum}/{allowed_sum}</code>"
        else:
            text+=f"<i>{self.strings('quota_unavailable')}</i>"
        await m.edit(text)

    @loader.command(ru_doc=" - обновить модуль до последней версии",en_doc=" - update module to latest version")
    async def vtupdate(self,message):
        url="https://raw.githubusercontent.com/lcetaa/VirusTotal-hikka-bot/refs/heads/main/VirusTotal.py"
        m=await utils.answer(message,f"{self._emoji('refresh')} <b>{self.strings('checking_update')}</b>")
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(url,timeout=aiohttp.ClientTimeout(total=15)) as r:
                    if r.status!=200:
                        return await m.edit(f"{self._emoji('error')} <b>{self.strings('update_load_error').format(r.status)}</b>")
                    code=await r.text()
            import re as _re
            match=_re.search(r"__version__\s*=\s*\((\d+),\s*(\d+),\s*(\d+)\)",code)
            if match:
                new_ver=tuple(int(x) for x in match.groups())
                cur_ver=__version__
                if new_ver<=cur_ver:
                    return await m.edit(
                        f"{self._emoji('success')} <b>{self.strings('already_latest')}</b>\n"
                        f"<code>v{cur_ver[0]}.{cur_ver[1]}.{cur_ver[2]}</code>"
                    )
                ver_str=f"v{new_ver[0]}.{new_ver[1]}.{new_ver[2]}"
            else:
                ver_str=self.strings('version_unknown')
            await m.edit(f"{self._emoji('refresh')} <b>{self.strings('installing_update').format(ver_str)}</b>")
            ldr = self.lookup("Loader")
            if not ldr or not hasattr(ldr, "download_and_install"):
                return await m.edit(f"{self._emoji('error')} <b>{self.strings('update_error').format('Loader not found')}</b>")
            await ldr.download_and_install(url)
            if getattr(ldr, "fully_loaded", False):
                ldr.update_modules_in_db()
            await m.edit(
                f"{self._emoji('success')} <b>{self.strings('update_success').format(ver_str)}</b>\n"
                f"{self.strings('update_fallback').format(url)}"
            )
        except asyncio.TimeoutError:
            await m.edit(f"{self._emoji('timeout')} <b>{self.strings('update_timeout')}</b>")
        except Exception as e:
            await m.edit(f"{self._emoji('error')} <b>{self.strings('update_error').format(e)}</b>")

    
