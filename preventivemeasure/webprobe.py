"""Huella tecnológica de una web/aplicación web a partir de cabeceras, HTML y recursos.

Sondeo pasivo: un GET a la URL indicada y a sus scripts/estilos enlazados del mismo host.
"""
import re
import time
import urllib.parse
import urllib.request

from .manifests import comp, cpe_comp
from .sources import open_url

UA = "PreventiveMeasure/1.0 (+self-monitoring)"
MAX_BYTES = 3_000_000

# cabecera/patrón -> (vendor, producto)
HEADER_PRODUCTS = {
    "nginx": ("f5", "nginx"), "apache": ("apache", "http_server"), "microsoft-iis": ("microsoft", "internet_information_services"),
    "php": ("php", "php"), "openresty": ("openresty", "openresty"), "litespeed": ("litespeedtech", "litespeed_web_server"),
    "caddy": ("caddyserver", "caddy"), "envoy": ("envoyproxy", "envoy"), "jetty": ("eclipse", "jetty"),
    "tomcat": ("apache", "tomcat"), "express": ("expressjs", "express"), "next.js": ("vercel", "next.js"),
    "asp.net": ("microsoft", "asp.net"), "openssl": ("openssl", "openssl"), "kestrel": ("microsoft", "asp.net_core"),
    "gunicorn": ("gunicorn", "gunicorn"), "werkzeug": ("palletsprojects", "werkzeug"), "uvicorn": ("encode", "uvicorn"),
    "varnish": ("varnish-software", "varnish_cache"), "traefik": ("traefik", "traefik"), "mod_ssl": ("apache", "mod_ssl"),
    "phusion_passenger": ("phusion", "passenger"), "weblogic": ("oracle", "weblogic_server"), "gws": ("google", "web_server"),
}

GENERATORS = {
    "wordpress": ("wordpress", "wordpress"), "joomla": ("joomla", "joomla"), "drupal": ("drupal", "drupal"),
    "typo3": ("typo3", "typo3"), "prestashop": ("prestashop", "prestashop"), "magento": ("magento", "magento"),
    "ghost": ("ghost", "ghost"), "hugo": ("gohugo", "hugo"), "shopify": ("shopify", "shopify"),
    "wix": ("wix", "wix"), "moodle": ("moodle", "moodle"), "mediawiki": ("mediawiki", "mediawiki"),
    "discourse": ("discourse", "discourse"), "gatsby": ("gatsbyjs", "gatsby"),
}

# librería JS en ruta/nombre de fichero -> paquete npm
JS_LIBS = {
    "jquery": "jquery", "jquery-ui": "jquery-ui", "jquery.ui": "jquery-ui", "bootstrap": "bootstrap",
    "angular": "angular", "vue": "vue", "react": "react", "react-dom": "react-dom", "lodash": "lodash",
    "moment": "moment", "handlebars": "handlebars", "underscore": "underscore", "axios": "axios",
    "dompurify": "dompurify", "purify": "dompurify", "swiper": "swiper", "select2": "select2", "tinymce": "tinymce",
    "ckeditor": "ckeditor4", "chart": "chart.js", "d3": "d3", "knockout": "knockout", "backbone": "backbone",
    "prototype": "prototype", "highcharts": "highcharts", "video": "video.js", "plyr": "plyr", "datatables": "datatables",
    "jquery.datatables": "datatables.net", "fancybox": "@fancyapps/fancybox", "slick": "slick-carousel",
    "socket.io": "socket.io-client", "sweetalert2": "sweetalert2", "ember": "ember-source", "mustache": "mustache",
}


def fetch(url: str, timeout: int = 20) -> tuple[dict, str, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    # Webs de intranet permitidas; metadatos cloud y esquemas raros bloqueados en cada redirección
    with open_url(req, timeout, allow_private=True) as r:
        deadline, buf = time.monotonic() + timeout * 3, bytearray()
        while len(buf) < MAX_BYTES and time.monotonic() < deadline and (chunk := r.read(65536)):
            buf += chunk  # truncar basta para la huella: no hace falta la página entera
        body = bytes(buf[:MAX_BYTES]).decode(r.headers.get_content_charset() or "utf-8", "replace")
        return {k.lower(): v for k, v in r.headers.items()}, body, r.geturl()


def _header_products(headers: dict, src: str) -> list[dict]:
    out = []
    for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime", "via"):
        val = headers.get(h, "")
        for m in re.finditer(r"([A-Za-z][\w.\-]*)(?:/|\s+v?)(\d+(?:\.\d+)+[a-z]?)", val):
            key = m.group(1).lower()
            if key in HEADER_PRODUCTS:
                v, p = HEADER_PRODUCTS[key]
                out.append(cpe_comp(p, m.group(2), f"{src} [{h}]", v, m.group(1)))
        if h == "x-aspnet-version" and val:
            out.append(cpe_comp("asp.net", val.strip(), f"{src} [{h}]", "microsoft", "ASP.NET"))
        for key in HEADER_PRODUCTS:  # producto sin versión (inventario, se avisa por noticias)
            if re.search(rf"\b{re.escape(key)}\b", val.lower()) and not any(c["product"] == HEADER_PRODUCTS[key][1] for c in out):
                out.append(cpe_comp(HEADER_PRODUCTS[key][1], "", f"{src} [{h}]", HEADER_PRODUCTS[key][0], key))
    cookies = headers.get("set-cookie", "")
    for cookie, (vendor, product) in {"phpsessid": ("php", "php"), "laravel_session": ("laravel", "laravel"),
                                      "jsessionid": ("eclipse", "jetty"), "asp.net_sessionid": ("microsoft", "asp.net"),
                                      "ci_session": ("codeigniter", "codeigniter"), "wp-settings": ("wordpress", "wordpress")}.items():
        if cookie in cookies.lower() and not any(c["product"] == product for c in out):
            out.append(cpe_comp(product, "", f"{src} [cookie]", vendor, product))
    return out


def _html_products(html: str, src: str) -> list[dict]:
    out = []
    for m in re.finditer(r'<meta[^>]{0,512}name=["\']generator["\'][^>]{0,512}content=["\']([^"\']{1,256})', html, re.I):
        content = m.group(1)
        vm = re.search(r"(\d+(?:\.\d+)+)", content)
        for key, (vendor, product) in GENERATORS.items():
            if key in content.lower():
                out.append(cpe_comp(product, vm.group(1) if vm else "", f"{src} [meta generator]", vendor, content))
    # WordPress: plugins y temas por ruta + ?ver=
    for m in re.finditer(r"/wp-content/(plugins|themes)/([\w\-]+)/[^\"'\s>]*?\?ver=([\d.]+)", html):
        out.append(cpe_comp(m.group(2), m.group(3), f"{src} [wp-{m.group(1)}]", None, f"wp:{m.group(2)}"))
    if "/wp-content/" in html and not any(c["product"] == "wordpress" for c in out):
        if vm := re.search(r"/wp-includes/[^\"']+\?ver=([\d.]+)", html):
            out.append(cpe_comp("wordpress", vm.group(1), f"{src} [wp-includes]", "wordpress", "WordPress"))
    return out


def _js_products(urls: list[str], src: str) -> list[dict]:
    out = []
    for u in urls:
        path = urllib.parse.urlparse(u).path.lower()
        # cdn: /npm/jquery@3.5.1/ , /ajax/libs/jquery/3.5.1/ , jquery-3.5.1.min.js , jquery.min.js?ver=3.5.1
        for pat in (r"/(?:npm/)?((?:@[\w.\-]+/)?[\w.\-]+)@(\d+\.\d+(?:\.\d+)?)",
                    r"/ajax/libs/([\w.\-]+)/(\d+\.\d+(?:\.\d+)?)/",
                    r"/([a-z][\w.]*?)[.\-]v?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)$"):
            if m := re.search(pat, path):
                name = m.group(1).removesuffix(".min").removesuffix(".js")
                if name in JS_LIBS:
                    out.append(comp("npm", JS_LIBS[name], m.group(2), f"{src} [{u[:120]}]"))
                break
        else:
            m = re.search(r"/([a-z][\w.\-]*?)(?:\.min)?\.js\?(?:ver|v)=(\d+\.\d+(?:\.\d+)?)", u.lower())
            if m and m.group(1) in JS_LIBS:
                out.append(comp("npm", JS_LIBS[m.group(1)], m.group(2), f"{src} [{u[:120]}]"))
    return out


def _inline_versions(text: str, src: str) -> list[dict]:
    """Banners de licencia dentro de los propios ficheros JS ('jQuery v3.5.1')."""
    out = []
    for name, pkg in (("jquery", "jquery"), ("bootstrap", "bootstrap"), ("lodash", "lodash"), ("vue.js", "vue"),
                      ("angularjs", "angular"), ("moment.js", "moment"), ("react", "react"), ("handlebars", "handlebars")):
        if m := re.search(rf"\b{re.escape(name)}\s+v?(\d+\.\d+\.\d+)", text[:3000], re.I):
            out.append(comp("npm", pkg, m.group(1), src))
    return out


def probe(url: str) -> tuple[list[dict], list[str]]:
    headers, html, final = fetch(url)
    out = _header_products(headers, url) + _html_products(html, url)
    assets = [urllib.parse.urljoin(final, m) for m in re.findall(r'<script[^>]{0,512}src=["\']([^"\']{1,2048})', html, re.I)]
    assets += [urllib.parse.urljoin(final, m)
               for m in re.findall(r'<link[^>]{0,512}href=["\']([^"\']{1,2048}?\.css[^"\']{0,256})', html, re.I)]
    out += _js_products(assets, url)
    errors = []
    host = urllib.parse.urlparse(final).netloc
    found = {c["name"] for c in out if c["ecosystem"] == "npm"}
    # Scripts propios sin versión en la URL: leer la cabecera del fichero (máx. 15)
    own = [a for a in assets if urllib.parse.urlparse(a).netloc == host and urllib.parse.urlparse(a).path.endswith(".js")]
    for a in own[:15]:
        try:
            _, body, _ = fetch(a, timeout=10)
        except Exception as e:
            errors.append(f"{a}: {e}")
            continue
        out += [c for c in _inline_versions(body, f"{url} [{a[:120]}]") if c["name"] not in found]
    seen = {}
    for c in out:
        seen.setdefault((c["ecosystem"], c["product"] or c["name"], c["version"]), c)
    return list(seen.values()), errors
